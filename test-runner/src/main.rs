use clap::Parser;
use colored::*;
use rayon::prelude::*;
use serde::Deserialize;
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
    allow_failure: bool,
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

    let test_cases = test_matrix.cases;

    println!(
        "{}",
        format!(
            "Running {} test configurations with up to {} parallel jobs...",
            test_cases.len(),
            num_jobs
        )
        .cyan()
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_jobs)
        .build_global()
        .unwrap();

    let results: Vec<TestResult> = test_cases
        .par_iter()
        .map(|case| run_test_case(case.clone(), project_root.clone()))
        .collect();

    let mut failed_cases = Vec::new();

    for result in results {
        println!("{}", "=================================================================".cyan());
        println!("{}", format!("  Test results for: {}", result.case.name).cyan());
        println!("{}", "-----------------------------------------------------------------".cyan());
        println!("{}", result.output);

        if result.success {
            println!("{}", format!("Test successful for configuration: {}", result.case.name).green());
        } else {
            println!("{}", format!("Test failed for configuration: {}", result.case.name).red());
            if result.case.allow_failure {
                println!("{}", "NOTE: This failure was expected and will be ignored.".yellow());
            } else {
                failed_cases.push(result.case.name);
            }
        }
        println!();
    }

    println!("\n{}", "==================== FINAL SUMMARY ====================".cyan());
    if failed_cases.is_empty() {
        println!("{}", "TEST MATRIX PASSED SUCCESSFULLY".green());
        std::process::exit(0);
    } else {
        println!("{}", "TEST MATRIX FAILED".red());
        println!("{}", "Failed configurations:".red());
        for name in &failed_cases {
            println!("{}", format!("  - {}", name).red());
        }
        std::process::exit(1);
    }
}

fn run_test_case(case: TestCase, project_root: PathBuf) -> TestResult {
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

    TestResult {
        case,
        output: output.lock().unwrap().clone(),
        success: status.success(),
    }
}
