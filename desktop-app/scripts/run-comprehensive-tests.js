#!/usr/bin/env node

// 🚀 APOLLO COMPREHENSIVE TEST RUNNER
// One command to rule them all - runs every test for beta readiness!

const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs-extra');

console.log('🚀 APOLLO COMPREHENSIVE TEST SUITE');
console.log('=' + '='.repeat(50));
console.log('🎯 Mission: Validate 100% functionality for beta launch');
console.log('🛡️ Scope: Every component, button, API, and edge case');
console.log('⚡ Goal: Military-grade reliability certification');
console.log('=' + '='.repeat(50));

async function runComprehensiveTests() {
    const startTime = Date.now();
    
    try {
        // Ensure we're in the right directory
        process.chdir(path.join(__dirname, '..'));
        
        console.log('\n📋 Pre-flight Checklist:');
        
        // 1. Install dependencies if needed
        console.log('  🔧 Checking dependencies...');
        try {
            execSync('npm install', { stdio: 'inherit' });
            console.log('  ✅ Dependencies verified');
        } catch (error) {
            console.log('  ❌ Dependency installation failed');
            throw error;
        }
        
        // 2. Create test reports directory
        console.log('  📁 Creating test reports directory...');
        await fs.ensureDir('./test-reports');
        console.log('  ✅ Test reports directory ready');
        
        // 3. Verify test files exist
        console.log('  📄 Verifying test files...');
        const testFiles = [
            './test-master-runner.js',
            './test-e2e-comprehensive.js',
            './test-ui-complete.js',
            './test-integration.js',
            './test-scenarios.js'
        ];
        
        for (const testFile of testFiles) {
            if (await fs.pathExists(testFile)) {
                console.log(`    ✅ ${path.basename(testFile)}`);
            } else {
                console.log(`    ❌ ${path.basename(testFile)} - MISSING`);
                throw new Error(`Required test file missing: ${testFile}`);
            }
        }
        
        console.log('\n🚀 Launching Master Test Runner...');
        console.log('-'.repeat(60));
        
        // Run the master test runner
        const testProcess = spawn('node', ['test-master-runner.js'], {
            stdio: 'inherit',
            cwd: process.cwd()
        });
        
        return new Promise((resolve, reject) => {
            testProcess.on('close', (code) => {
                const duration = Math.round((Date.now() - startTime) / 1000);
                
                console.log('\n' + '='.repeat(60));
                console.log('🏁 COMPREHENSIVE TEST SUITE COMPLETED');
                console.log(`⏱️  Total Duration: ${duration} seconds`);
                console.log('=' + '='.repeat(60));
                
                if (code === 0) {
                    console.log('🎉 ALL TESTS PASSED - APOLLO IS READY FOR BETA LAUNCH! 🚀');
                    console.log('\n📊 Next Steps:');
                    console.log('   1. Review detailed test reports in ./test-reports/');
                    console.log('   2. Verify all critical functionality is working');
                    console.log('   3. Proceed with beta deployment preparation');
                    console.log('   4. Notify beta testers and prepare launch sequence');
                    
                    resolve({ success: true, code });
                } else if (code === 1) {
                    console.log('⚠️  TESTS COMPLETED WITH ISSUES - REVIEW REQUIRED');
                    console.log('\n📋 Action Items:');
                    console.log('   1. Review failed tests in detailed reports');
                    console.log('   2. Fix identified issues');
                    console.log('   3. Re-run tests to verify fixes');
                    console.log('   4. Consider limited beta with known issues');
                    
                    resolve({ success: false, code });
                } else {
                    console.log('❌ CRITICAL TEST FAILURES - DO NOT LAUNCH');
                    console.log('\n🚨 Emergency Actions:');
                    console.log('   1. Review critical failure reports immediately');
                    console.log('   2. Fix all critical issues before any deployment');
                    console.log('   3. Run full test suite again after fixes');
                    console.log('   4. Consider delaying beta launch until issues resolved');
                    
                    reject(new Error(`Test suite failed with code ${code}`));
                }
            });
            
            testProcess.on('error', (error) => {
                console.error('💥 Test process failed to start:', error);
                reject(error);
            });
        });
        
    } catch (error) {
        console.error('\n💥 Pre-flight check failed:', error.message);
        console.log('\n🔧 Troubleshooting:');
        console.log('   1. Ensure Node.js 18+ is installed');
        console.log('   2. Run "npm install" to install dependencies');
        console.log('   3. Verify all test files are present');
        console.log('   4. Check file permissions and access rights');
        
        throw error;
    }
}

// Show usage information
function showUsage() {
    console.log('\n📖 Usage:');
    console.log('  npm run test:comprehensive     # Run all tests');
    console.log('  node scripts/run-comprehensive-tests.js');
    console.log('\n🔧 Options:');
    console.log('  --help                         # Show this help');
    console.log('  --verbose                      # Verbose output');
    console.log('\n📊 What this script does:');
    console.log('  ✅ Validates environment and dependencies');
    console.log('  ✅ Tests every UI button and interaction');
    console.log('  ✅ Validates all API integrations');
    console.log('  ✅ Runs comprehensive threat scenarios');
    console.log('  ✅ Performs stress and performance testing');
    console.log('  ✅ Validates security hardening');
    console.log('  ✅ Tests cross-platform compatibility');
    console.log('  ✅ Generates detailed test reports');
    console.log('  ✅ Makes beta readiness recommendation');
}

// Handle command line arguments
if (process.argv.includes('--help')) {
    showUsage();
    process.exit(0);
}

// Run the comprehensive tests
if (require.main === module) {
    runComprehensiveTests()
        .then((result) => {
            if (result.success) {
                console.log('\n🎯 RESULT: READY FOR BETA LAUNCH! 🚀');
                process.exit(0);
            } else {
                console.log('\n⚠️  RESULT: Issues detected - review required');
                process.exit(1);
            }
        })
        .catch((error) => {
            console.error('\n💥 CRITICAL FAILURE:', error.message);
            console.log('\n🆘 Contact development team immediately if issues persist');
            process.exit(2);
        });
}

module.exports = { runComprehensiveTests };
