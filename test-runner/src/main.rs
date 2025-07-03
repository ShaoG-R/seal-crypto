use clap::Parser;
use colored::*;
use futures::{stream, StreamExt};
use std::fs;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

mod runner;
use runner::config::{TestMatrix};
use runner::execution::run_test_case;
use runner::reporting::{handle_unexpected_failure, print_summary};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of parallel jobs, defaults to (logical CPUs / 2) + 1
    #[arg(short, long)]
    jobs: Option<usize>,

    /// Path to the test matrix config file
    #[arg(short, long, default_value = "TestMatrix.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let num_cpus = num_cpus::get();
    let jobs = args.jobs.unwrap_or(num_cpus / 2 + 1);
    
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

    // --- Run safe cases in parallel ---
    println!(
        "\n{}",
        format!(
            "Running {} safe configurations with up to {} parallel jobs...",
            safe_cases.len(),
            jobs
        )
        .cyan()
    );

    let stop_token = CancellationToken::new();
    let mut safe_tests_stream = stream::iter(safe_cases)
        .map(|case| {
            let project_root = project_root.clone();
            let stop_token = stop_token.clone();
            tokio::spawn(
                async move { run_test_case(case, project_root, Some(stop_token)).await },
            )
        })
        .buffer_unordered(jobs);

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
                // Even though we're exiting, push the result for completeness if needed.
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
