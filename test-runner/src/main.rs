use clap::Parser;
use colored::*;
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

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
fn spawn_and_capture(mut cmd: Command) -> (std::process::ExitStatus, String) {
    // Capture stdout and stderr
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn cargo command");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let output = Arc::new(Mutex::new(String::new()));

    let stdout_output = Arc::clone(&output);
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line.unwrap();
            let mut output = stdout_output.lock().unwrap();
            output.push_str(&line);
            output.push('\n');
        }
    });

    let stderr_output = Arc::clone(&output);
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap();
            let mut output = stderr_output.lock().unwrap();
            output.push_str(&line);
            output.push('\n');
        }
    });

    stdout_handle.join().unwrap();
    stderr_handle.join().unwrap();
    
    let status = child.wait().expect("Failed to wait on cargo command");

    (status, output.lock().unwrap().clone())
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

fn main() {
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

    let results = Arc::new(Mutex::new(Vec::new()));

    let safe_run_result = safe_cases
        .par_iter()
        .try_for_each(|case| -> Result<(), TestResult> {
            match run_test_case(case.clone(), project_root.clone()) {
                Ok(result) => {
                    results.lock().unwrap().push(result);
                    Ok(())
                }
                Err(result) => {
                    // For safe cases, any failure is unexpected.
                    Err(result)
                }
            }
        });

    if let Err(failed_result) = safe_run_result {
        handle_unexpected_failure(&failed_result);
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
            let result = run_test_case(case, project_root.clone());
            let mut results_lock = results.lock().unwrap();
            match result {
                Ok(res) => {
                    results_lock.push(res);
                }
                Err(res) => {
                    let current_os = std::env::consts::OS;
                    let failure_allowed = res.case.allow_failure.iter().any(|os| os == current_os);

                    if !failure_allowed {
                        handle_unexpected_failure(&res);
                    }
                    results_lock.push(res);
                }
            }
        }
    }

    let final_results = results.lock().unwrap();
    let has_unexpected_failures = print_summary(&final_results);

    // Final status message about directories.
    println!("{}", "\nTemporary build directories for successful tests have been cleaned up automatically.".green());
    if final_results.iter().any(|r| !r.success) {
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

fn run_test_case(
    case: TestCase,
    project_root: PathBuf,
) -> Result<TestResult, TestResult> {
    let start_time = std::time::Instant::now();
    println!("{}", format!("Queueing test: {}", case.name).blue());

    // Get unique target directory for this test case.
    // The build_ctx will be dropped when this function returns, cleaning up the temp dir.
    let build_ctx = create_build_dir(&case.features, case.no_default_features);
    println!("Using temporary target directory: {}", build_ctx.target_path.display());

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&project_root);
    cmd.arg("test").arg("--lib");
    cmd.arg("--target-dir").arg(&build_ctx.target_path);

    if case.no_default_features {
        cmd.arg("--no-default-features");
    }

    if !case.features.is_empty() {
        cmd.arg("--features").arg(&case.features);
    }

    let (status, output) = spawn_and_capture(cmd);
    
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
