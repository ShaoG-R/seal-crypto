# PowerShell script to run a cargo test matrix, similar to the GitHub Actions workflow.
#
# Usage:
#   .\test-matrix.ps1
#

# --- Configuration ---
$Features = @(
    "",            # Represents the default case (no features)
    "rsa",
    "kyber",
    "aes-gcm",
    "full"         # Represents all features
)

# --- Script Body ---
$ErrorOccurred = $false

# Define some colors for output
$Color_Header = "Cyan"
$Color_Success = "Green"
$Color_Failure = "Red"
$Color_Command = "Yellow"

function Run-CargoTest {
    param (
        [string]$FeatureString
    )

    $featureDisplayName = if ([string]::IsNullOrEmpty($FeatureString)) { "default (no features)" } else { $FeatureString }
    Write-Host "=================================================================" -ForegroundColor $Color_Header
    Write-Host "  Testing with features: $featureDisplayName" -ForegroundColor $Color_Header
    Write-Host "================================================================="

    if ([string]::IsNullOrEmpty($FeatureString)) {
        $command = "cargo test --lib --no-default-features"
    } else {
        $command = "cargo test --no-default-features --features `"$FeatureString`""
    }

    Write-Host "Executing: " -NoNewline; Write-Host $command -ForegroundColor $Color_Command
    
    # Execute the command
    Invoke-Expression $command
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Test failed for features: $featureDisplayName" -ForegroundColor $Color_Failure
        $script:ErrorOccurred = $true
    } else {
        Write-Host "Test successful for features: $featureDisplayName" -ForegroundColor $Color_Success
    }
    Write-Host ""
}

# --- Main Execution ---
foreach ($feature in $Features) {
    if ($script:ErrorOccurred) {
        Write-Host "An error occurred in a previous step. Aborting remaining tests." -ForegroundColor $Color_Failure
        break
    }
    Run-CargoTest -FeatureString $feature
}

# --- Final Summary ---
if ($script:ErrorOccurred) {
    Write-Host "TEST MATRIX FAILED" -ForegroundColor $Color_Failure
    # Exit with a non-zero code to indicate failure in CI environments
    exit 1
} else {
    Write-Host "TEST MATRIX PASSED SUCCESSFULLY" -ForegroundColor $Color_Success
    exit 0
} 