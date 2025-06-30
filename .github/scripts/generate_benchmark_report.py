import json
import os
from pathlib import Path

def parse_criterion_json(file_path):
    """Parses a file containing line-delimited JSON from 'cargo bench'."""
    benchmarks = {}
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("type") == "bench":
                    name = data["name"]
                    # Convert estimate from nanoseconds to a more readable unit if needed,
                    # but keep it in ns for raw comparison.
                    mean_ns = data["mean"]["estimate"]
                    benchmarks[name] = mean_ns
            except (json.JSONDecodeError, KeyError):
                continue
    return benchmarks

def compare_benchmarks(current, previous):
    """Compares current and previous benchmark data, returns a report dict."""
    report = {}
    for bench_name, new_ns in current.items():
        old_ns = previous.get(bench_name)
        change_percent = None
        if old_ns:
            change_percent = ((new_ns - old_ns) / old_ns) * 100
        
        report[bench_name] = {
            "new_ns": new_ns,
            "old_ns": old_ns,
            "change_percent": change_percent
        }
    
    # Add benchmarks that were in previous but not in current (removed)
    for bench_name, old_ns in previous.items():
        if bench_name not in current:
            report[bench_name] = {
                "new_ns": None,
                "old_ns": old_ns,
                "change_percent": -100.0 # Indicate removal
            }
            
    return report

def format_ns(nanoseconds):
    """Formats nanoseconds into a human-readable string."""
    if nanoseconds is None:
        return "N/A"
    if nanoseconds < 1_000:
        return f"{nanoseconds:.2f} ns"
    if nanoseconds < 1_000_000:
        return f"{nanoseconds / 1_000:.2f} µs"
    if nanoseconds < 1_000_000_000:
        return f"{nanoseconds / 1_000_000:.2f} ms"
    return f"{nanoseconds / 1_000_000_000:.2f} s"

def format_change(change_percent):
    """Formats the percentage change with color indicators."""
    if change_percent is None:
        return "*(new)*"
    if change_percent == -100.0 and change_percent is not None:
         return "*(removed)*"

    sign = "+" if change_percent > 0 else ""
    color_emoji = ""
    if change_percent > 5:
        color_emoji = "🔴"  # Regression
    elif change_percent < -5:
        color_emoji = "🟢"  # Improvement

    return f"**{sign}{change_percent:.2f}%** {color_emoji}"

def main():
    artifacts_dir = Path("artifacts")
    benchmark_report_dir = Path("benchmark_report")
    
    # Load previous results
    previous_results = {}
    # The action will manage bringing the history, so we read from the current dir
    previous_summary_file = benchmark_report_dir / "latest_summary.json"
    if previous_summary_file.exists():
        with open(previous_summary_file, 'r') as f:
            try:
                previous_results = json.load(f)
            except json.JSONDecodeError:
                print("Warning: Could not decode previous summary. Starting fresh.")
                previous_results = {}

    # Process current results from artifacts
    current_results = {}
    markdown_reports = ["# Benchmark Report"]
    
    platforms = sorted([p.name for p in artifacts_dir.iterdir() if p.is_dir()])

    for platform in platforms:
        platform_dir = artifacts_dir / platform
        json_file = next(platform_dir.glob('*.json'), None)
        if not json_file:
            continue
        
        current_benches = parse_criterion_json(json_file)
        platform_key = platform.replace('-latest', '') # e.g., 'ubuntu-latest' -> 'ubuntu'
        current_results[platform_key] = current_benches
        
        previous_platform_benches = previous_results.get(platform_key, {})
        comparison = compare_benchmarks(current_benches, previous_platform_benches)
        
        markdown_reports.append(f"\n## Results for `{platform}`\n")
        markdown_reports.append("| Benchmark | Previous Time | Current Time | Change |")
        markdown_reports.append("|:---|---:|---:|:---|")
        
        for name, data in sorted(comparison.items()):
            row = [
                f"`{name}`",
                format_ns(data['old_ns']),
                format_ns(data['new_ns']),
                format_change(data['change_percent'])
            ]
            markdown_reports.append("| " + " | ".join(row) + " |")

    # Save current results for the next run
    output_dir = benchmark_report_dir
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "latest_summary.json", 'w') as f:
        json.dump(current_results, f, indent=2)
        
    # Write the final markdown report
    with open(output_dir / "index.md", 'w') as f:
        f.write("\n".join(markdown_reports))
        
    print(f"Benchmark report generated successfully at {output_dir}/index.md")

if __name__ == "__main__":
    main() 