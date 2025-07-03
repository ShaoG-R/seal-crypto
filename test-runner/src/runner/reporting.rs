use colored::*;
use crate::runner::models::{TestResult, FailureReason};
use crate::runner::command::format_build_error_output;

/// Prints details for an unexpected test failure and exits the process.
pub fn handle_unexpected_failure(result: &TestResult) {
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
pub fn print_summary(final_results: &[TestResult]) -> bool {
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