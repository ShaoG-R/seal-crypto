use clap::Parser;
use colored::*;
use futures::{stream, StreamExt};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of parallel test jobs, defaults to number of logical CPUs
    #[arg(short, long)]
    jobs: Option<usize>,

    /// Number of parallel build jobs, defaults to (logical CPUs / 2) + 1
    #[arg(short = 'b', long)]
    build_jobs: Option<usize>,

    /// Path to the test matrix config file
    #[arg(short, long, default_value = "TestMatrix.toml")]
    config: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct TestCase {
    name: String,
    features: String,
    no_default_features: bool,
    #[serde(default)]
    allow_failure: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TestMatrix {
    cases: Vec<TestCase>,
}

#[derive(Debug, Clone)]
enum FailureReason {
    Build,
    Test,
}

#[derive(Debug, Clone)]
struct TestResult {
    case: TestCase,
    output: String,
    success: bool,
    failure_reason: Option<FailureReason>,
}

/// A context for a build, managing the temporary directory.
struct BuildContext {
    /// The temporary directory that will be auto-deleted when this struct is dropped.
    _temp_root: TempDir,
    /// Path to the target directory for this build.
    target_path: PathBuf,
}

/// Holds the result of a successful build.
struct BuiltTest {
    case: TestCase,
    executable: PathBuf,
    build_ctx: BuildContext,
}

/// Represents a diagnostic message from the compiler.
#[derive(Debug, Clone, Deserialize)]
struct CargoDiagnostic {
    level: String,
    message: String,
    rendered: Option<String>,
}

/// Represents a message from `cargo build --message-format=json`.
#[derive(Deserialize)]
struct CargoMessage {
    reason: String,
    target: Option<CargoTarget>,
    executable: Option<PathBuf>,
    message: Option<CargoDiagnostic>,
}

/// Represents the "target" field in a `CargoMessage`.
#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    test: bool,
}

/// Extracts and formats compiler errors from `cargo` JSON output.
fn format_build_error_output(raw_output: &str) -> String {
    let error_messages: Vec<String> = raw_output
        .lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .filter_map(|msg| {
            if msg.reason == "compiler-message" {
                if let Some(diag) = msg.message {
                    if diag.level == "error" {
                        // Prefer the colorful rendered output if available
                        return diag.rendered.or(Some(diag.message));
                    }
                }
            }
            None
        })
        .collect();

    if error_messages.is_empty() {
        // If we can't find a specific error, return a snippet of the raw output.
        let snippet = raw_output.lines().take(50).collect::<Vec<_>>().join("\n");
        format!(
            "{}\n\n{}",
            "Could not parse specific compiler errors. Raw output snippet:".yellow(),
            snippet
        )
    } else {
        error_messages.join("\n")
    }
}

/// Recursively copies a directory.
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.as_ref().join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(entry.path(), &dst_path)?;
        } else {
            // The `copy` function will overwrite the destination file if it exists.
            fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

/// Prints details for an unexpected test failure and exits the process.
fn handle_unexpected_failure(result: &TestResult) {
    println!("{}", "=================================================================".cyan());
    println!("{}", format!("  Failure details for: {}", result.case.name).cyan());
    println!("{}", "-----------------------------------------------------------------".cyan());

    let output_to_print = match &result.failure_reason {
        Some(FailureReason::Build) => format_build_error_output(&result.output),
        _ => result.output.clone(), // For Test failures or unknown, print raw output
    };
    println!("{}", output_to_print);

    let failure_type = match result.failure_reason {
        Some(FailureReason::Build) => "build",
        Some(FailureReason::Test) => "test",
        None => "task",
    };
    println!("{}", format!("Unexpected {} failure for configuration: {}", failure_type, result.case.name).red());
    println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());
    println!("{}", "TEST MATRIX FAILED".red());
    println!("{}", format!("  - {} ({})", result.case.name, failure_type).red());
    std::process::exit(1);
}

/// Prints the final summary of all test results.
/// Returns true if there were any unexpected failures.
fn print_summary(final_results: &[TestResult]) -> bool {
    println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());

    let mut has_unexpected_failures = false;
    for result in final_results.iter() {
        println!("{}", "=================================================================".cyan());
        println!("{}", format!("  Test results for: {}", result.case.name).cyan());
        println!("{}", "-----------------------------------------------------------------".cyan());
        
        let output_to_print = if !result.success {
            match &result.failure_reason {
                Some(FailureReason::Build) => format_build_error_output(&result.output),
                _ => result.output.clone(),
            }
        } else {
            result.output.clone()
        };
        println!("{}", output_to_print);

        if result.success {
            println!("{}", format!("Test successful for configuration: {}", result.case.name).green());
        } else {
            let current_os = std::env::consts::OS;
            let failure_allowed = result.case.allow_failure.iter().any(|os| os == current_os);

            if failure_allowed {
                println!("{}", format!("Test failed for configuration: {}", result.case.name).red());
                println!("{}", format!("NOTE: This failure was expected on '{}' and will be ignored.", current_os).yellow());
            } else {
                // This branch should not be reached due to early exit, but is kept for safety.
                has_unexpected_failures = true;
                println!("{}", format!("Test failed for configuration: {}", result.case.name).red());
            }
        }
        println!();
    }
    has_unexpected_failures
}

/// Spawns a command and captures its stdout and stderr streams.
/// If a stop_signal is provided and set, it will attempt to kill the child process.
async fn spawn_and_capture(
    mut cmd: tokio::process::Command,
    stop_token: Option<CancellationToken>,
) -> (std::io::Result<std::process::ExitStatus>, String) {
    // Capture stdout and stderr
    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            // If spawning fails, we return the error and an empty string for the output.
            return (Err(e), String::new());
        }
    };

    let stdout = child
        .stdout
        .take()
        .expect("Failed to capture stdout of child process");
    let stderr = child
        .stderr
        .take()
        .expect("Failed to capture stderr of child process");

    let output = Arc::new(tokio::sync::Mutex::new(String::new()));

    let stdout_output = Arc::clone(&output);
    let stdout_handle = tokio::spawn(async move {
        let reader = tokio::io::BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut output = stdout_output.lock().await;
            output.push_str(&line);
            output.push('\n');
        }
    });

    let stderr_output = Arc::clone(&output);
    let stderr_handle = tokio::spawn(async move {
        let reader = tokio::io::BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut output = stderr_output.lock().await;
            output.push_str(&line);
            output.push('\n');
        }
    });

    let status = if let Some(token) = stop_token {
        tokio::select! {
            _ = token.cancelled() => {
                if let Err(e) = child.start_kill() {
                    eprintln!("Failed to kill child process: {}", e);
                }
                child.wait().await
            },
            status = child.wait() => {
                status
            }
        }
    } else {
        child.wait().await
    };

    stdout_handle.await.unwrap();
    stderr_handle.await.unwrap();

    (status, output.lock().await.clone())
}

/// Generate a temporary build directory for a given build configuration
fn create_build_dir(features: &str, no_default_features: bool) -> BuildContext {
    // Create a base temp directory with a meaningful prefix
    let build_type = if no_default_features { "no-std" } else { "std" };
    
    // Create descriptive prefix for the temp directory
    let mut prefix = format!("seal-crypto-{}", build_type);
    if !features.is_empty() {
        // Add a short hash of features to keep the name reasonably sized
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        features.hash(&mut hasher);
        let feature_hash = hasher.finish() % 10000; // Get last 4 digits
        prefix = format!("{}-{:04}", prefix, feature_hash);
    }
    
    let temp_dir = TempDir::with_prefix(&prefix).expect("Failed to create temporary directory");
    let target_path = temp_dir.path().to_path_buf();
    
    BuildContext {
        _temp_root: temp_dir,
        target_path,
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let num_cpus = num_cpus::get();
    let test_jobs = args.jobs.unwrap_or(num_cpus);
    let build_jobs = args.build_jobs.unwrap_or(num_cpus / 2 + 1);
    
    println!("{}", "Temporary directories will be auto-cleaned for successful tests.".green());
    println!("{}", "Artifacts for failed tests will be preserved in './target-errors'.".yellow());

    // Determine the project root (parent of the test-runner's manifest dir)
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir
        .parent()
        .expect("Failed to get parent directory of CARGO_MANIFEST_DIR")
        .to_path_buf();

    // --- Pre-fetch all dependencies ---
    println!("\n{}", "Fetching all dependencies to avoid lock contention...".cyan());
    let mut fetch_cmd = std::process::Command::new("cargo");
    fetch_cmd.current_dir(&project_root);
    fetch_cmd.arg("fetch");

    let fetch_status = fetch_cmd
        .status()
        .expect("Failed to execute cargo fetch command");

    if !fetch_status.success() {
        panic!("'cargo fetch' failed. Please check your network and Cargo.toml file.");
    }
    println!("{}", "Dependency fetching successful.".green());

    // The config file path is relative to the manifest directory, unless it's absolute
    let config_path = manifest_dir.join(&args.config);

    println!("Project root detected at: {}", project_root.display());
    println!("Loading test matrix from: {}", config_path.display());
    let config_content = fs::read_to_string(&config_path)
        .unwrap_or_else(|_| panic!("Failed to read config file: {}", config_path.display()));

    let test_matrix: TestMatrix =
        toml::from_str(&config_content).expect("Failed to parse TOML config file");

    let current_os = std::env::consts::OS;
    println!("Current OS detected: {}", current_os.yellow());

    let (flaky_cases, safe_cases): (Vec<_>, Vec<_>) = test_matrix
        .cases
        .into_iter()
        .partition(|c| c.allow_failure.iter().any(|os| os == current_os));

    let mut results = Vec::new();

    // --- Build safe cases in parallel ---
    println!(
        "\n{}",
        format!(
            "Building {} safe configurations with up to {} parallel jobs...",
            safe_cases.len(),
            build_jobs
        )
        .cyan()
    );

    let build_stop_token = CancellationToken::new();
    let mut safe_build_stream = stream::iter(safe_cases)
        .map(|case| {
            let project_root = project_root.clone();
            let stop_token = build_stop_token.clone();
            tokio::spawn(async move {
                build_test_case(case, project_root, Some(stop_token)).await
            })
        })
        .buffer_unordered(build_jobs);

    let mut built_safe_cases = Vec::new();
    while let Some(res) = safe_build_stream.next().await {
        match res.unwrap() {
            Ok(built_test) => {
                built_safe_cases.push(built_test);
            }
            Err(failure_result) => {
                // First unexpected build failure is fatal.
                build_stop_token.cancel();
                handle_unexpected_failure(&failure_result); // Exits process.
            }
        }
    }
    println!("{}", "All safe cases built successfully.".green());
    
    // --- Build flaky cases in parallel ---
    let mut built_flaky_cases = Vec::new();
    if !flaky_cases.is_empty() {
        println!(
            "\n{}",
            format!(
                "Building {} platform-specific (flaky) cases with up to {} parallel jobs...",
                flaky_cases.len(),
                build_jobs
            )
            .yellow()
        );
        let flaky_build_stop_token = CancellationToken::new();
        let mut flaky_build_stream = stream::iter(flaky_cases)
            .map(|case| {
                let project_root = project_root.clone();
                // Pass a stop token to allow cancellation on first unexpected failure.
                let stop_token = flaky_build_stop_token.clone();
                tokio::spawn(async move {
                    build_test_case(case, project_root, Some(stop_token)).await
                })
            })
            .buffer_unordered(build_jobs);

        while let Some(res) = flaky_build_stream.next().await {
            match res.unwrap() {
                Ok(built_test) => built_flaky_cases.push(built_test),
                Err(failure_result) => {
                    let is_allowed =
                        failure_result.case.allow_failure.iter().any(|os| os == current_os);
                    if !is_allowed {
                        // On unexpected failure, cancel other builds and exit.
                        flaky_build_stop_token.cancel();
                        handle_unexpected_failure(&failure_result);
                    }
                    // If failure is allowed, just record it and continue.
                    results.push(failure_result);
                }
            }
        }
        println!("{}", "Finished building platform-specific cases.".green());
    }

    // --- Run safe cases in parallel ---
    println!(
        "\n{}",
        format!(
            "Running {} safe-to-build configurations with up to {} parallel jobs...",
            built_safe_cases.len(),
            test_jobs
        )
        .cyan()
    );

    let stop_token = CancellationToken::new();
    let mut safe_tests_stream = stream::iter(built_safe_cases)
        .map(|built_test| {
            let stop_token = stop_token.clone();
            tokio::spawn(
                async move { run_built_test(built_test, Some(stop_token)).await },
            )
        })
        .buffer_unordered(test_jobs);

    let mut unexpected_failure_observed = false;
    while let Some(res) = safe_tests_stream.next().await {
        let result = res.unwrap(); // Unwrap the JoinHandle result
        match result {
            Ok(test_result) => {
                results.push(test_result);
            }
            Err(test_result) => {
                if !unexpected_failure_observed {
                    // This is the first unexpected failure.
                    unexpected_failure_observed = true;
                    stop_token.cancel(); // Signal all other tests to stop.
                    handle_unexpected_failure(&test_result); // This will exit the process.
                }
                results.push(test_result);
            }
        }
    }


    // --- Run flaky cases sequentially ---
    if !built_flaky_cases.is_empty() {
        println!(
            "\n{}",
            format!(
                "Running {} platform-specific (may fail) configurations sequentially...",
                built_flaky_cases.len()
            )
            .yellow()
        );
        for built_test in built_flaky_cases {
            let result = run_built_test(built_test, None).await;
            match result {
                Ok(res) => {
                    results.push(res);
                }
                Err(res) => {
                    let failure_allowed = res.case.allow_failure.iter().any(|os| os == current_os);

                    if !failure_allowed {
                        handle_unexpected_failure(&res);
                    }
                    results.push(res);
                }
            }
        }
    }

    let has_unexpected_failures = print_summary(&results);

    // Final status message about directories.
    println!("{}", "\nTemporary build directories for successful tests have been cleaned up automatically.".green());
    if results.iter().any(|r| !r.success) {
        println!("{}", "Build artifacts for any failed tests have been preserved in './target-errors'.".yellow());
    }

    if has_unexpected_failures {
        println!("{}", "TEST MATRIX FAILED".red());
        std::process::exit(1);
    } else {
        println!("{}", "TEST MATRIX PASSED SUCCESSFULLY".green());
        std::process::exit(0);
    }
}

async fn build_test_case(
    case: TestCase,
    project_root: PathBuf,
    stop_token: Option<CancellationToken>,
) -> Result<BuiltTest, TestResult> {
    println!("{}", format!("Building test: {}", case.name).blue());

    let build_ctx = create_build_dir(&case.features, case.no_default_features);
    
    let mut cmd = tokio::process::Command::new("cargo");
    cmd.kill_on_drop(true);
    cmd.current_dir(&project_root);
    cmd.arg("test")
        .arg("--lib")
        .arg("--no-run") // Build but don't run
        .arg("--message-format=json-diagnostic-rendered-ansi")
        .arg("--locked")
        .arg("--offline")
        .arg("--target-dir")
        .arg(&build_ctx.target_path);

    if case.no_default_features {
        cmd.arg("--no-default-features");
    }

    if !case.features.is_empty() {
        cmd.arg("--features").arg(&case.features);
    }

    let (status_res, output) = spawn_and_capture(cmd, stop_token).await;
    let status = status_res.expect("Error waiting for process to complete");

    if !status.success() {
        let sanitized_name = case.name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect::<String>();
        let error_dir_path = project_root.join("target-errors").join(sanitized_name);
        
        println!(
            "{}",
            format!(
                "Build for '{}' failed. Preserving build artifacts in: {}",
                case.name,
                error_dir_path.display()
            )
            .yellow()
        );

        if error_dir_path.exists() {
             fs::remove_dir_all(&error_dir_path).expect("Failed to clean up old error artifacts directory");
        }
        
        copy_dir_all(&build_ctx.target_path, &error_dir_path)
            .unwrap_or_else(|e| eprintln!("Failed to copy error artifacts for '{}': {}", case.name, e));
        
        return Err(TestResult {
            case,
            output,
            success: false,
            failure_reason: Some(FailureReason::Build),
        });
    }

    // Find the executable from the cargo JSON output
    let executable = output
        .lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .find_map(|msg| {
            if msg.reason == "compiler-artifact" {
                if let (Some(target), Some(executable_path)) = (msg.target, msg.executable) {
                    // Check if it's a test artifact for the main crate.
                    // When running `cargo test`, the main library is compiled as a test.
                    // We check for `target.test == true` and that the name matches our crate.
                    // Crate names with hyphens are converted to underscores.
                    if target.name == "seal_crypto" && target.test {
                        return Some(executable_path);
                    }
                }
            }
            None
        })
        .expect("Could not find test executable in cargo output");
    
    println!("{}", format!("Successfully built test: {}", case.name).green());

    Ok(BuiltTest {
        case,
        executable,
        build_ctx,
    })
}


async fn run_built_test(
    built_test: BuiltTest,
    stop_token: Option<CancellationToken>,
) -> Result<TestResult, TestResult> {
    let case = built_test.case;
    let executable = built_test.executable;
    let build_ctx = built_test.build_ctx; // This now holds the ownership of the temp dir
    let project_root = PathBuf::from("."); // Not ideal, but should work.

    let start_time = std::time::Instant::now();
    println!("{}", format!("Queueing test: {}", case.name).blue());

    let mut cmd = tokio::process::Command::new(executable);
    cmd.kill_on_drop(true);

    let (status_res, output) = spawn_and_capture(cmd, stop_token).await;
    let status = status_res.expect("Error waiting for process to complete");
    
    let duration = start_time.elapsed();
    
    println!("{}", format!("Finished test: {} in {:.2?}", case.name, duration).blue());
    
    let result = TestResult {
        case: case.clone(),
        output,
        success: status.success(),
        failure_reason: if status.success() { None } else { Some(FailureReason::Test) },
    };

    if !result.success {
        let sanitized_name = case.name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect::<String>();
        let error_dir_path = project_root.join("target-errors").join(sanitized_name);
        
        println!(
            "{}",
            format!(
                "Test '{}' failed. Preserving build artifacts in: {}",
                case.name,
                error_dir_path.display()
            )
            .yellow()
        );

        if error_dir_path.exists() {
             fs::remove_dir_all(&error_dir_path).expect("Failed to clean up old error artifacts directory");
        }
        
        // The build artifacts are already in the temp dir managed by build_ctx.
        // We just need to copy them.
        copy_dir_all(&build_ctx.target_path, &error_dir_path)
            .unwrap_or_else(|e| eprintln!("Failed to copy error artifacts for '{}': {}", case.name, e));
        
        Err(result)
    } else {
        // build_ctx is dropped here, cleaning up the temp dir
        Ok(result)
    }
}
