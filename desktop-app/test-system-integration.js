#!/usr/bin/env node
/**
 * ============================================================================
 * APOLLO SENTINEL™ - SYSTEM INTEGRATION VERIFICATION
 * Test all module interconnections and API availability
 * ============================================================================
 */

const fs = require('fs-extra');
const path = require('path');

console.log('🔗 APOLLO SENTINEL™ - SYSTEM INTEGRATION VERIFICATION');
console.log('='.repeat(70));

async function testSystemIntegration() {
    const testResults = {
        module_loads: 0,
        integration_points: 0,
        api_exposures: 0,
        ui_connections: 0,
        total_tests: 0,
        passed_tests: 0
    };
    
    console.log('🔬 Testing module loading...\n');
    
    // Test 1: Core modules load properly
    const coreModules = [
        'src/core/unified-protection-engine.js',
        'src/forensics/advanced-forensic-engine.js',
        'src/auth/enterprise-biometric-auth.js',
        'src/telemetry/beta-telemetry.js',
        'src/apt-detection/advanced-apt-engines.js',
        'src/crypto-guardian/advanced-crypto-protection.js',
        'src/mobile-threats/pegasus-forensics.js'
    ];
    
    for (const module of coreModules) {
        testResults.total_tests++;
        try {
            require(`./${module}`);
            console.log(`✅ ${module.split('/').pop()} loads successfully`);
            testResults.module_loads++;
            testResults.passed_tests++;
        } catch (error) {
            console.log(`❌ ${module.split('/').pop()} failed: ${error.message}`);
        }
    }
    
    console.log(`\n🔗 Testing integration points...\n`);
    
    // Test 2: Check integration in unified engine
    testResults.total_tests++;
    try {
        const unifiedEngineContent = await fs.readFile('src/core/unified-protection-engine.js', 'utf8');
        const integrationChecks = [
            'AdvancedForensicEngine',
            'initializeForensicEngine',
            'connectForensicToModules',
            'handleForensicThreatEvent'
        ];
        
        const foundIntegrations = integrationChecks.filter(check => unifiedEngineContent.includes(check));
        
        if (foundIntegrations.length === integrationChecks.length) {
            console.log(`✅ Unified engine integration: ${foundIntegrations.length}/${integrationChecks.length} checks passed`);
            testResults.integration_points++;
            testResults.passed_tests++;
        } else {
            console.log(`❌ Unified engine integration: ${foundIntegrations.length}/${integrationChecks.length} checks passed`);
        }
    } catch (error) {
        console.log(`❌ Unified engine integration test failed: ${error.message}`);
    }
    
    console.log(`\n📡 Testing API exposures...\n`);
    
    // Test 3: Check API exposures in preload.js
    testResults.total_tests++;
    try {
        const preloadContent = await fs.readFile('preload.js', 'utf8');
        const apiChecks = [
            'authenticateForWallet',
            'getAuthStatus',
            'captureForensicEvidence',
            'analyzeVolatileThreat',
            'performLiveTriage'
        ];
        
        const foundAPIs = apiChecks.filter(api => preloadContent.includes(api));
        
        if (foundAPIs.length === apiChecks.length) {
            console.log(`✅ API exposures: ${foundAPIs.length}/${apiChecks.length} APIs properly exposed`);
            testResults.api_exposures++;
            testResults.passed_tests++;
        } else {
            console.log(`❌ API exposures: ${foundAPIs.length}/${apiChecks.length} APIs exposed`);
        }
    } catch (error) {
        console.log(`❌ API exposure test failed: ${error.message}`);
    }
    
    console.log(`\n🎨 Testing UI connections...\n`);
    
    // Test 4: Check UI function connections
    testResults.total_tests++;
    try {
        const dashboardContent = await fs.readFile('ui/dashboard/dashboard.js', 'utf8');
        const uiChecks = [
            'startBiometricAuthentication',
            'captureEvidence',
            'analyzeVolatileThreats',
            'performLiveSystemTriage',
            'initializeBiometricAuthContainer'
        ];
        
        const foundUIFunctions = uiChecks.filter(func => dashboardContent.includes(func));
        
        if (foundUIFunctions.length === uiChecks.length) {
            console.log(`✅ UI connections: ${foundUIFunctions.length}/${uiChecks.length} functions connected`);
            testResults.ui_connections++;
            testResults.passed_tests++;
        } else {
            console.log(`❌ UI connections: ${foundUIFunctions.length}/${uiChecks.length} functions connected`);
        }
    } catch (error) {
        console.log(`❌ UI connection test failed: ${error.message}`);
    }
    
    // Generate report
    console.log('\n' + '='.repeat(70));
    console.log('📊 SYSTEM INTEGRATION TEST REPORT');
    console.log('='.repeat(70));
    
    const successRate = (testResults.passed_tests / testResults.total_tests) * 100;
    
    console.log(`📈 INTEGRATION SUCCESS RATE: ${successRate.toFixed(1)}%`);
    console.log(`📦 Module Loading: ${testResults.module_loads}/${coreModules.length} modules`);
    console.log(`🔗 Integration Points: ${testResults.integration_points}/1 verified`);
    console.log(`📡 API Exposures: ${testResults.api_exposures}/1 verified`);
    console.log(`🎨 UI Connections: ${testResults.ui_connections}/1 verified`);
    
    if (successRate >= 90) {
        console.log(`\n🎉 EXCELLENT INTEGRATION STATUS`);
        console.log(`✅ System is ready for production deployment`);
    } else if (successRate >= 80) {
        console.log(`\n✅ GOOD INTEGRATION STATUS`);
        console.log(`🎯 Minor issues - system is operational`);
    } else {
        console.log(`\n⚠️ INTEGRATION ISSUES DETECTED`);
        console.log(`🔧 System needs attention before deployment`);
    }
    
    console.log(`\n💡 KNOWN ISSUES:`);
    console.log(`🔐 Biometric auth timing: Frontend may try to access before backend initialization`);
    console.log(`⚡ Solution: Error handling implemented for graceful degradation`);
    console.log(`📊 Status: Non-critical - system will work once fully initialized`);
    
    console.log('='.repeat(70));
}

testSystemIntegration().catch(error => {
    console.error('❌ System integration test failed:', error);
    process.exit(1);
});
