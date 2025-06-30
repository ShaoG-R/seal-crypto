# PowerShell script to run a cargo test matrix, similar to the GitHub Actions workflow.
#
# Usage:
#   .\test-matrix.ps1
#

# --- Configuration ---
$TestCases = @(
    @{ Name = "std-default";         Args = "" },
    @{ Name = "std-classic";         Args = "--features 'classic,ecdh'" },
    @{ Name = "std-pqc";             Args = "--features pqc" },
    @{ Name = "std-kdf";             Args = "--features kdf" },
    @{ Name = "std-full";            Args = "--features full" },
    @{ Name = "std-classic-asm";     Args = "--features 'classic,ecdh,asm'"; AllowFailure = $true },
    @{ Name = "std-pqc-avx2";        Args = "--features 'pqc,avx2'" },
    @{ Name = "std-full-optimized";  Args = "--features 'full,asm,avx2'"; AllowFailure = $true },
    @{ Name = "no_std-base";         Args = "--no-default-features" },
    @{ Name = "no_std-classic";      Args = "--no-default-features --features 'classic,ecdh'" },
    @{ Name = "no_std-pqc";          Args = "--no-default-features --features pqc" },
    @{ Name = "no_std-kdf";          Args = "--no-default-features --features kdf" },
    @{ Name = "no_std-full";         Args = "--no-default-features --features full" },
    @{ Name = "no_std-classic-asm";  Args = "--no-default-features --features 'classic,ecdh,asm'"; AllowFailure = $true },
    @{ Name = "no_std-pqc-avx2";     Args = "--no-default-features --features 'pqc,avx2'" },
    @{ Name = "no_std-full-optimized"; Args = "--no-default-features --features 'full,asm,avx2'"; AllowFailure = $true }
)

# --- Color Configuration ---
$Color_Header = "Cyan"
$Color_Command = "Yellow"
$Color_Success = "Green"
$Color_Failure = "Red"
$Color_Warning = "Yellow"

# --- State ---
$script:ErrorOccurred = $false

function Run-CargoTest {
    param (
        [hashtable]$TestCase
    )

    $featureDisplayName = $TestCase.Name
    Write-Host "=================================================================" -ForegroundColor $Color_Header
    Write-Host "  Testing configuration: $featureDisplayName" -ForegroundColor $Color_Header
    Write-Host "================================================================="

    $command = "cargo test --lib $($TestCase.Args)"

    Write-Host "Executing: " -NoNewline; Write-Host $command -ForegroundColor $Color_Command
    
    # Execute the command
    Invoke-Expression $command
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Test failed for configuration: $featureDisplayName" -ForegroundColor $Color_Failure
        if ($null -ne $TestCase.AllowFailure -and $TestCase.AllowFailure) {
            Write-Host "NOTE: This failure was expected and will be ignored." -ForegroundColor $Color_Warning
        }
        else {
            $script:ErrorOccurred = $true
        }
    } else {
        Write-Host "Test successful for configuration: $featureDisplayName" -ForegroundColor $Color_Success
    }
    Write-Host ""
}

# --- Main Execution ---
foreach ($case in $TestCases) {
    if ($script:ErrorOccurred) {
        Write-Host "An error occurred in a previous step. Aborting remaining tests." -ForegroundColor $Color_Failure
        break
    }
    Run-CargoTest -TestCase $case
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