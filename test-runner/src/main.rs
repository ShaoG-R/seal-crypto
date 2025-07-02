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
    /// Number of parallel jobs, defaults to number of logical CPUs
    #[arg(short, long)]
    jobs: Option<usize>,

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

struct TestResult {
    case: TestCase,
    output: String,
    success: bool,
}

/// A context for a build, managing the temporary directory.
struct BuildContext {
    /// The temporary directory that will be auto-deleted when this struct is dropped.
    _temp_root: TempDir,
    /// Path to the target directory for this build.
    target_path: PathBuf,
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
    println!("{}", format!("  Test results for: {}", result.case.name).cyan());
    println!("{}", "-----------------------------------------------------------------".cyan());
    println!("{}", result.output);
    println!("{}", format!("Unexpected test failure for configuration: {}", result.case.name).red());
    println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());
    println!("{}", "TEST MATRIX FAILED".red());
    println!("{}", "Failed configurations:".red());
    println!("{}", format!("  - {}", result.case.name).red());
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
        println!("{}", result.output);

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
    let num_jobs = args.jobs.unwrap_or(num_cpus);
    
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

    println!(
        "\n{}",
        format!(
            "Running {} safe-to-build configurations with up to {} parallel jobs...",
            safe_cases.len(),
            num_jobs
        )
        .cyan()
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_jobs)
        .build_global()
        .unwrap();

    let mut results = Vec::new();
    let stop_token = CancellationToken::new();
    let mut safe_cases_stream = stream::iter(safe_cases)
        .map(|case| {
            let project_root = project_root.clone();
            let stop_token = stop_token.clone();
            tokio::spawn(async move {
                run_test_case(case, project_root, Some(stop_token)).await
            })
        })
        .buffer_unordered(num_jobs);

    let mut unexpected_failure_observed = false;
    while let Some(res) = safe_cases_stream.next().await {
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
                // We still collect the result of other tests that might have finished
                // before the cancellation signal was fully processed.
                results.push(test_result);
            }
        }
    }

    // --- Run flaky cases sequentially ---
    if !flaky_cases.is_empty() {
        println!(
            "\n{}",
            format!(
                "Running {} platform-specific (may fail) configurations sequentially...",
                flaky_cases.len()
            )
            .yellow()
        );
        for case in flaky_cases {
            let result = run_test_case(case, project_root.clone(), None).await;
            match result {
                Ok(res) => {
                    results.push(res);
                }
                Err(res) => {
                    let current_os = std::env::consts::OS;
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

async fn run_test_case(
    case: TestCase,
    project_root: PathBuf,
    stop_token: Option<CancellationToken>,
) -> Result<TestResult, TestResult> {
    let start_time = std::time::Instant::now();
    println!("{}", format!("Queueing test: {}", case.name).blue());

    // Get unique target directory for this test case.
    // The build_ctx will be dropped when this function returns, cleaning up the temp dir.
    let build_ctx = create_build_dir(&case.features, case.no_default_features);
    println!("Using temporary target directory: {}", build_ctx.target_path.display());

    let mut cmd = tokio::process::Command::new("cargo");
    cmd.kill_on_drop(true);
    cmd.current_dir(&project_root);
    cmd.arg("test")
        .arg("--lib")
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
    
    let duration = start_time.elapsed();
    
    println!("{}", format!("Finished test: {} in {:.2?}", case.name, duration).blue());
    
    // The build context is NOT stored, it will be dropped when this function returns,
    // which cleans up the temporary directory.

    let result = TestResult {
        case: case.clone(),
        output,
        success: status.success(),
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
        
        copy_dir_all(&build_ctx.target_path, &error_dir_path)
            .unwrap_or_else(|e| eprintln!("Failed to copy error artifacts for '{}': {}", case.name, e));
        
        Err(result)
    } else {
        Ok(result)
    }
}
