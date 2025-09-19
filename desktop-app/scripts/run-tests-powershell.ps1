# 🚀 APOLLO PowerShell Test Runner
# Windows-optimized comprehensive testing script

Write-Host "🚀 APOLLO COMPREHENSIVE TEST SUITE - POWERSHELL EDITION" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Yellow
Write-Host "🎯 Mission: Validate 100% functionality for beta launch" -ForegroundColor Cyan
Write-Host "🛡️ Scope: Every component, button, API, and edge case" -ForegroundColor Cyan
Write-Host "⚡ Goal: Military-grade reliability certification" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Yellow

$startTime = Get-Date

try {
    # Ensure we're in the right directory
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectDir = Split-Path -Parent $scriptDir
    Set-Location $projectDir
    
    Write-Host "`n📋 Pre-flight Checklist:" -ForegroundColor Yellow
    
    # 1. Check Node.js version
    Write-Host "  🔧 Checking Node.js version..." -ForegroundColor White
    $nodeVersion = node --version 2>$null
    if ($nodeVersion) {
        Write-Host "  ✅ Node.js: $nodeVersion" -ForegroundColor Green
    } else {
        Write-Host "  ❌ Node.js not found" -ForegroundColor Red
        throw "Node.js not found or not accessible"
    }
    
    # 2. Install dependencies if needed
    Write-Host "  🔧 Checking dependencies..." -ForegroundColor White
    if (-not (Test-Path "node_modules")) {
        Write-Host "  📦 Installing dependencies..." -ForegroundColor Yellow
        npm install
    }
    Write-Host "  ✅ Dependencies verified" -ForegroundColor Green
    
    # 3. Create test reports directory
    Write-Host "  📁 Creating test reports directory..." -ForegroundColor White
    if (-not (Test-Path "test-reports")) {
        New-Item -ItemType Directory -Path "test-reports" | Out-Null
    }
    Write-Host "  ✅ Test reports directory ready" -ForegroundColor Green
    
    # 4. Verify test files exist
    Write-Host "  📄 Verifying test files..." -ForegroundColor White
    $testFiles = @(
        "test-master-runner.js",
        "test-e2e-comprehensive.js", 
        "test-ui-complete.js",
        "test-integration.js",
        "test-scenarios.js"
    )
    
    foreach ($testFile in $testFiles) {
        if (Test-Path $testFile) {
            Write-Host "    ✅ $testFile" -ForegroundColor Green
        } else {
            Write-Host "    ❌ $testFile - MISSING" -ForegroundColor Red
            throw "Required test file missing: $testFile"
        }
    }
    
    Write-Host "`n🚀 Launching Master Test Runner..." -ForegroundColor Green
    Write-Host ("-" * 60) -ForegroundColor Gray
    
    # Run the master test runner
    $process = Start-Process -FilePath "node" -ArgumentList "test-master-runner.js" -Wait -PassThru -NoNewWindow
    
    $endTime = Get-Date
    $duration = [math]::Round(($endTime - $startTime).TotalSeconds)
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Yellow
    Write-Host "🏁 COMPREHENSIVE TEST SUITE COMPLETED" -ForegroundColor Green
    Write-Host "⏱️  Total Duration: $duration seconds" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Yellow
    
    if ($process.ExitCode -eq 0) {
        Write-Host "🎉 ALL TESTS PASSED - APOLLO IS READY FOR BETA LAUNCH! 🚀" -ForegroundColor Green
        Write-Host "`n📊 Next Steps:" -ForegroundColor Yellow
        Write-Host "   1. Review detailed test reports in ./test-reports/" -ForegroundColor White
        Write-Host "   2. Verify all critical functionality is working" -ForegroundColor White
        Write-Host "   3. Proceed with beta deployment preparation" -ForegroundColor White
        Write-Host "   4. Notify beta testers and prepare launch sequence" -ForegroundColor White
        
        exit 0
    } 
    elseif ($process.ExitCode -eq 1) {
        Write-Host "⚠️  TESTS COMPLETED WITH ISSUES - REVIEW REQUIRED" -ForegroundColor Yellow
        Write-Host "`n📋 Action Items:" -ForegroundColor Yellow
        Write-Host "   1. Review failed tests in detailed reports" -ForegroundColor White
        Write-Host "   2. Fix identified issues" -ForegroundColor White
        Write-Host "   3. Re-run tests to verify fixes" -ForegroundColor White
        Write-Host "   4. Consider limited beta with known issues" -ForegroundColor White
        
        exit 1
    } 
    else {
        Write-Host "❌ CRITICAL TEST FAILURES - DO NOT LAUNCH" -ForegroundColor Red
        Write-Host "`n🚨 Emergency Actions:" -ForegroundColor Red
        Write-Host "   1. Review critical failure reports immediately" -ForegroundColor White
        Write-Host "   2. Fix all critical issues before any deployment" -ForegroundColor White
        Write-Host "   3. Run full test suite again after fixes" -ForegroundColor White
        Write-Host "   4. Consider delaying beta launch until issues resolved" -ForegroundColor White
        
        exit 2
    }
    
} 
catch {
    Write-Host "`n💥 Pre-flight check failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n🔧 Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   1. Ensure Node.js 18+ is installed" -ForegroundColor White
    Write-Host "   2. Run npm install to install dependencies" -ForegroundColor White
    Write-Host "   3. Verify all test files are present" -ForegroundColor White
    Write-Host "   4. Check file permissions and access rights" -ForegroundColor White
    Write-Host "   5. Run PowerShell as Administrator if needed" -ForegroundColor White
    
    exit 3
}