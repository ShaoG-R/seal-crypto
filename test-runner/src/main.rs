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

fn run_pre_build(project_root: &Path, features: &str, no_default_features: bool) {
    let build_type = if no_default_features { "no-std" } else { "std" };
    println!("{}", format!("Starting pre-build for all '{}' configurations...", build_type).yellow());

    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_root);
    cmd.arg("test").arg("--no-run");

    if no_default_features {
        cmd.arg("--no-default-features");
    }

    if !features.is_empty() {
        cmd.arg("--features").arg(features);
    }

    println!("Executing: {:?}", cmd);

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
}

fn main() {
    let args = Args::parse();
    let num_cpus = num_cpus::get();
    let num_jobs = args.jobs.unwrap_or(num_cpus);

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

    // Run pre-builds only for safe cases
    if !std_safe_cases.is_empty() {
        run_pre_build(&project_root, &all_std_features, false);
    }
    if !no_std_safe_cases.is_empty() {
        run_pre_build(&project_root, &all_no_std_features, true);
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

    let safe_run_result = safe_cases_to_run
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

    if has_unexpected_failures {
        println!("{}", "TEST MATRIX FAILED".red());
        std::process::exit(1);
    } else {
        println!("{}", "TEST MATRIX PASSED SUCCESSFULLY".green());
        std::process::exit(0);
    }
}

fn run_test_case(case: TestCase, project_root: PathBuf) -> Result<TestResult, TestResult> {
    let start_time = std::time::Instant::now();
    println!("{}", format!("Queueing test: {}", case.name).blue());

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&project_root);
    cmd.arg("test").arg("--lib");

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
