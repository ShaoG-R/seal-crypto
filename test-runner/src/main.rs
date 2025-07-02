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

    /// Keep the target directories after testing (for debugging)
    #[arg(long)]
    keep_target_dirs: bool,
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

/// Temporary build directory context that manages cleanup
struct BuildContext {
    /// The temporary directory that will be auto-deleted when this struct is dropped
    _temp_root: Option<TempDir>,
    /// Path to the target directory inside the temp directory
    target_path: PathBuf,
}

/// Generate a temporary build directory for a given build configuration
fn create_build_dir(features: &str, no_default_features: bool, keep_dirs: bool) -> BuildContext {
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
    
    if keep_dirs {
        // If we want to keep directories, create them in a visible location
        let target_path = PathBuf::from(format!("./target-matrix/{}", prefix));
        fs::create_dir_all(&target_path).expect("Failed to create persistent target directory");

        BuildContext {
            _temp_root: None,
            target_path,
        }
    } else {
        // Otherwise create a true temporary directory that will be automatically cleaned up
        let temp_dir = TempDir::with_prefix(&prefix).expect("Failed to create temporary directory");
        let target_path = temp_dir.path().to_path_buf();
        
        BuildContext {
            _temp_root: Some(temp_dir),
            target_path,
        }
    }
}

fn run_pre_build(project_root: &Path, features: &str, no_default_features: bool, keep_dirs: bool) -> BuildContext {
    let build_type = if no_default_features { "no-std" } else { "std" };
    println!("{}", format!("Starting pre-build for all '{}' configurations...", build_type).yellow());

    // Get unique target directory for this build configuration
    let build_ctx = create_build_dir(features, no_default_features, keep_dirs);
    
    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_root);
    cmd.arg("test").arg("--no-run");
    cmd.arg("--target-dir").arg(&build_ctx.target_path);

    if no_default_features {
        cmd.arg("--no-default-features");
    }

    if !features.is_empty() {
        cmd.arg("--features").arg(features);
    }

    println!("Executing: {:?}", cmd);
    println!("Using target directory: {}", build_ctx.target_path.display());

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pre-build cargo command");

    let stdout = child.stdout.take().expect("Failed to capture stdout of pre-build");
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            println!("{}", line.unwrap());
        }
    });

    let stderr = child.stderr.take().expect("Failed to capture stderr of pre-build");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            eprintln!("{}", line.unwrap());
        }
    });

    stdout_handle.join().unwrap();
    stderr_handle.join().unwrap();

    let status = child.wait().expect("Failed to wait on pre-build cargo command");

    if !status.success() {
        panic!("Pre-build failed for '{}' configurations!", build_type);
    }

    println!("{}", format!("Pre-build for '{}' configurations successful.", build_type).green());
    
    build_ctx
}

fn main() {
    let args = Args::parse();
    let num_cpus = num_cpus::get();
    let num_jobs = args.jobs.unwrap_or(num_cpus);
    let keep_target_dirs = args.keep_target_dirs;
    
    if keep_target_dirs {
        println!("{}", "Target directories will be kept after testing (--keep-target-dirs flag is set).".yellow());
    } else {
        println!("{}", "Target directories will be automatically cleaned up after testing.".green());
    }

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

    // Partition cases into safe and flaky (allowed to fail on this OS)
    let (flaky_cases, safe_cases): (Vec<_>, Vec<_>) = test_matrix
        .cases
        .into_iter()
        .partition(|c| c.allow_failure.iter().any(|os| os == current_os));

    // --- Pre-build for safe cases ---
    let (no_std_safe_cases, std_safe_cases): (Vec<_>, Vec<_>) = safe_cases
        .into_iter()
        .partition(|c| c.no_default_features);

    // Get all unique features for each build type from safe cases
    let all_std_features = std_safe_cases
        .iter()
        .flat_map(|c| c.features.split(','))
        .filter(|f| !f.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");

    let all_no_std_features = no_std_safe_cases
        .iter()
        .flat_map(|c| c.features.split(','))
        .filter(|f| !f.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");

    // Store build contexts to keep them alive during testing
    let mut build_contexts = Vec::new();

    // Run pre-builds only for safe cases
    if !std_safe_cases.is_empty() {
        let ctx = run_pre_build(&project_root, &all_std_features, false, keep_target_dirs);
        build_contexts.push(ctx);
    }
    if !no_std_safe_cases.is_empty() {
        let ctx = run_pre_build(&project_root, &all_no_std_features, true, keep_target_dirs);
        build_contexts.push(ctx);
    }

    // Re-combine safe cases for parallel execution
    let safe_cases_to_run = std_safe_cases
        .into_iter()
        .chain(no_std_safe_cases.into_iter())
        .collect::<Vec<_>>();

    println!(
        "\n{}",
        format!(
            "Running {} safe-to-build configurations with up to {} parallel jobs...",
            safe_cases_to_run.len(),
            num_jobs
        )
        .cyan()
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_jobs)
        .build_global()
        .unwrap();

    let results = Arc::new(Mutex::new(Vec::new()));

    // Store test contexts to keep them alive until all tests complete
    let test_contexts = Arc::new(Mutex::new(Vec::new()));

    let safe_run_result = safe_cases_to_run
        .par_iter()
        .try_for_each(|case| -> Result<(), TestResult> {
            match run_test_case(case.clone(), project_root.clone(), keep_target_dirs, test_contexts.clone()) {
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
        println!("{}", "=================================================================".cyan());
        println!("{}", format!("  Test results for: {}", failed_result.case.name).cyan());
        println!("{}", "-----------------------------------------------------------------".cyan());
        println!("{}", failed_result.output);
        println!("{}", format!("Unexpected test failure for configuration: {}", failed_result.case.name).red());
        println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());
        println!("{}", "TEST MATRIX FAILED".red());
        println!("{}", "Failed configurations:".red());
        println!("{}", format!("  - {}", failed_result.case.name).red());
        std::process::exit(1);
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
            let result = run_test_case(case, project_root.clone(), keep_target_dirs, test_contexts.clone());
            let mut results_lock = results.lock().unwrap();
            match result {
                Ok(res) => {
                    results_lock.push(res);
                }
                Err(res) => {
                    let current_os = std::env::consts::OS;
                    let failure_allowed = res.case.allow_failure.iter().any(|os| os == current_os);

                    if !failure_allowed {
                        println!("{}", "=================================================================".cyan());
                        println!("{}", format!("  Test results for: {}", res.case.name).cyan());
                        println!("{}", "-----------------------------------------------------------------".cyan());
                        println!("{}", res.output);
                        println!("{}", format!("Unexpected test failure for configuration: {}", res.case.name).red());
                        println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());
                        println!("{}", "TEST MATRIX FAILED".red());
                        println!("{}", "Failed configurations:".red());
                        println!("{}", format!("  - {}", res.case.name).red());
                        std::process::exit(1);
                    }
                    results_lock.push(res);
                }
            }
        }
    }

    let final_results = results.lock().unwrap();
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

    // Report number of target directories that will be cleaned
    if !keep_target_dirs {
        let contexts_count = test_contexts.lock().unwrap().len() + build_contexts.len();
        println!("{}", format!("Cleaning up {} target directories...", contexts_count).green());
        // Contexts will be dropped here, cleaning up all temporary directories
    } else {
        // Extract and log paths that will be kept
        let build_paths: Vec<_> = build_contexts.iter().map(|ctx| ctx.target_path.display().to_string()).collect();
        let test_paths: Vec<_> = test_contexts.lock().unwrap().iter().map(|ctx| ctx.target_path.display().to_string()).collect();
        
        println!("{}", "The following target directories have been kept for inspection:".yellow());
        for path in build_paths.iter().chain(test_paths.iter()) {
            println!("  - {}", path);
        }
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
    keep_dirs: bool,
    contexts: Arc<Mutex<Vec<BuildContext>>>
) -> Result<TestResult, TestResult> {
    let start_time = std::time::Instant::now();
    println!("{}", format!("Queueing test: {}", case.name).blue());

    // Get unique target directory for this test case
    let build_ctx = create_build_dir(&case.features, case.no_default_features, keep_dirs);
    println!("Using target directory: {}", build_ctx.target_path.display());

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
    let duration = start_time.elapsed();
    
    println!("{}", format!("Finished test: {} in {:.2?}", case.name, duration).blue());
    
    // Store the build context to keep it alive until all tests complete
    contexts.lock().unwrap().push(build_ctx);

    let result = TestResult {
        case,
        output: output.lock().unwrap().clone(),
        success: status.success(),
    };

    if result.success {
        Ok(result)
    } else {
        Err(result)
    }
}
