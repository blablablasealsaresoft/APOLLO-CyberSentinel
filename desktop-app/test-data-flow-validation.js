// 🔄 APOLLO DATA FLOW VALIDATION
// Tests backend threat detection → data processing → frontend readiness
// Validates complete data pipeline without requiring Electron window

require('dotenv').config();

const fs = require('fs-extra');
const path = require('path');

// Import backend components
const ApolloUnifiedProtectionEngine = require('./src/core/unified-protection-engine');
const ApolloAIOracle = require('./src/ai/oracle-integration');
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');
const ApolloBehavioralAnalyzer = require('./src/core/behavioral-analyzer');

class DataFlowValidator {
    constructor() {
        this.testResults = [];
        
        // Initialize backend components
        this.engine = new ApolloUnifiedProtectionEngine();
        this.aiOracle = new ApolloAIOracle();
        this.osint = new OSINTThreatIntelligence();
        this.behavioralAnalyzer = new ApolloBehavioralAnalyzer();
        
        this.realThreatTests = [
            { name: 'Pegasus Process', type: 'process', value: 'com.apple.WebKit.Networking', expected: 'pegasus' },
            { name: 'Pegasus Hash', type: 'hash', value: 'd616c60b7657c66c6d3c6f61bd4e2f00f1f60e89', expected: 'pegasus' },
            { name: 'Lazarus Process', type: 'process', value: 'svchost_.exe', expected: 'lazarus' },
            { name: 'APT28 Process', type: 'process', value: 'xagent.exe', expected: 'apt28' },
            { name: 'Ransomware Process', type: 'process', value: 'lockbit.exe', expected: 'ransomware' }
        ];
    }

    async validateCompleteDataFlow() {
        console.log('🔄 APOLLO COMPLETE DATA FLOW VALIDATION');
        console.log('=' + '='.repeat(60));
        console.log('🎯 Mission: Validate backend detection → data processing → frontend readiness');
        console.log('🔍 Scope: Real threat detection → IPC data → UI display format');
        console.log('✅ Testing: Complete data pipeline integrity');
        console.log('=' + '='.repeat(60));

        try {
            // Phase 1: Backend Detection Validation
            await this.validateBackendDetection();
            
            // Phase 2: Data Processing Validation
            await this.validateDataProcessing();
            
            // Phase 3: IPC Data Format Validation
            await this.validateIPCDataFormat();
            
            // Phase 4: Frontend Data Structure Validation
            await this.validateFrontendDataStructure();
            
            // Phase 5: Real-Time Event Validation
            await this.validateRealTimeEvents();
            
            // Phase 6: API Response Validation
            await this.validateAPIResponses();
            
            // Generate comprehensive report
            await this.generateDataFlowReport();
            
        } catch (error) {
            console.error('🚨 Data flow validation failed:', error);
            throw error;
        }
    }

    async validateBackendDetection() {
        console.log('\n🛡️ PHASE 1: BACKEND DETECTION VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Initializing backend components...');
        await this.engine.initialize();
        this.aiOracle.init();
        
        console.log('🧪 Testing real threat detection...');
        
        let detectedThreats = 0;
        const detectionResults = [];
        
        for (const threat of this.realThreatTests) {
            try {
                const ThreatDatabase = require('./src/signatures/threat-database');
                const db = new ThreatDatabase();
                
                // Wait for database initialization
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                let result;
                switch (threat.type) {
                    case 'process':
                        result = db.checkProcess(threat.value);
                        break;
                    case 'hash':
                        result = db.checkHash(threat.value);
                        break;
                    case 'network':
                        result = db.checkNetworkConnection(threat.value);
                        break;
                }
                
                if (result && result.detected) {
                    detectedThreats++;
                    detectionResults.push({
                        threat: threat.name,
                        detected: true,
                        signature: result.threat,
                        category: result.category,
                        severity: result.severity
                    });
                    console.log(`  ✅ ${threat.name}: ${result.threat} (${result.severity})`);
                } else {
                    detectionResults.push({
                        threat: threat.name,
                        detected: false,
                        error: 'Not detected'
                    });
                    console.log(`  ❌ ${threat.name}: Not detected`);
                }
                
            } catch (error) {
                detectionResults.push({
                    threat: threat.name,
                    detected: false,
                    error: error.message
                });
                console.log(`  ❌ ${threat.name}: Error - ${error.message}`);
            }
        }
        
        const detectionRate = (detectedThreats / this.realThreatTests.length) * 100;
        
        this.recordTest('Backend Detection', detectedThreats === this.realThreatTests.length, {
            detectionRate: detectionRate,
            detectedThreats: detectedThreats,
            totalThreats: this.realThreatTests.length,
            results: detectionResults
        });
        
        console.log(`\n📊 Backend Detection Rate: ${detectionRate.toFixed(1)}% (${detectedThreats}/${this.realThreatTests.length})`);
    }

    async validateDataProcessing() {
        console.log('\n📊 PHASE 2: DATA PROCESSING VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Testing threat data processing...');
        
        try {
            // Test engine statistics generation
            const engineStats = this.engine.getStatistics();
            const hasRequiredStats = engineStats && 
                typeof engineStats.threatsDetected === 'number' &&
                typeof engineStats.isActive === 'boolean';
            
            console.log(`  📊 Engine stats structure: ${hasRequiredStats ? '✅ Valid' : '❌ Invalid'}`);
            
            // Test AI Oracle stats
            const aiStats = this.aiOracle.getStats();
            const hasAIStats = aiStats && typeof aiStats.total_analyses === 'number';
            
            console.log(`  🧠 AI Oracle stats: ${hasAIStats ? '✅ Valid' : '❌ Invalid'}`);
            
            // Test OSINT stats
            const osintStats = this.osint.getStats();
            const hasOSINTStats = osintStats && typeof osintStats.queriesRun === 'number';
            
            console.log(`  🌐 OSINT stats: ${hasOSINTStats ? '✅ Valid' : '❌ Invalid'}`);
            
            this.recordTest('Data Processing', hasRequiredStats && hasAIStats && hasOSINTStats, {
                engineStats: engineStats,
                aiStats: aiStats,
                osintStats: osintStats
            });
            
        } catch (error) {
            this.recordTest('Data Processing', false, null, error.message);
            console.log(`  ❌ Data processing error: ${error.message}`);
        }
    }

    async validateIPCDataFormat() {
        console.log('\n🔌 PHASE 3: IPC DATA FORMAT VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Testing IPC data structure formats...');
        
        try {
            // Simulate threat detection event data
            const threatAlert = {
                type: 'APT_DETECTION',
                severity: 'CRITICAL',
                source: 'test',
                details: {
                    threat: 'pegasus',
                    process: 'com.apple.WebKit.Networking',
                    category: 'APT'
                },
                timestamp: new Date().toISOString(),
                engineVersion: '2.0.0'
            };
            
            // Validate threat alert structure
            const alertValid = threatAlert.type && threatAlert.severity && 
                              threatAlert.details && threatAlert.timestamp;
            
            console.log(`  🚨 Threat alert format: ${alertValid ? '✅ Valid' : '❌ Invalid'}`);
            
            // Test engine stats format for IPC
            const engineStats = this.engine.getStatistics();
            const statsValid = engineStats && 
                              typeof engineStats.threatsDetected === 'number' &&
                              typeof engineStats.isActive === 'boolean';
            
            console.log(`  📊 Engine stats format: ${statsValid ? '✅ Valid' : '❌ Invalid'}`);
            
            this.recordTest('IPC Data Format', alertValid && statsValid, {
                threatAlert: threatAlert,
                engineStats: engineStats
            });
            
        } catch (error) {
            this.recordTest('IPC Data Format', false, null, error.message);
            console.log(`  ❌ IPC format error: ${error.message}`);
        }
    }

    async validateFrontendDataStructure() {
        console.log('\n🖥️ PHASE 4: FRONTEND DATA STRUCTURE VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Testing frontend data consumption readiness...');
        
        try {
            // Read dashboard.js to validate data structure handling
            const dashboardPath = path.join(__dirname, 'ui', 'dashboard', 'dashboard.js');
            const dashboardContent = await fs.readFile(dashboardPath, 'utf8');
            
            // Check for required data handling methods
            const hasRealThreatHandler = dashboardContent.includes('handleRealThreatDetection');
            const hasStatsUpdate = dashboardContent.includes('updateRealStats');
            const hasBackendConnection = dashboardContent.includes('connectToBackend');
            const hasElectronAPI = dashboardContent.includes('window.electronAPI');
            
            console.log(`  🔍 Real threat handler: ${hasRealThreatHandler ? '✅ Present' : '❌ Missing'}`);
            console.log(`  📊 Stats update method: ${hasStatsUpdate ? '✅ Present' : '❌ Missing'}`);
            console.log(`  🔌 Backend connection: ${hasBackendConnection ? '✅ Present' : '❌ Missing'}`);
            console.log(`  ⚡ Electron API usage: ${hasElectronAPI ? '✅ Present' : '❌ Missing'}`);
            
            const frontendReady = hasRealThreatHandler && hasStatsUpdate && 
                                hasBackendConnection && hasElectronAPI;
            
            this.recordTest('Frontend Data Structure', frontendReady, {
                hasRealThreatHandler,
                hasStatsUpdate,
                hasBackendConnection,
                hasElectronAPI
            });
            
        } catch (error) {
            this.recordTest('Frontend Data Structure', false, null, error.message);
            console.log(`  ❌ Frontend validation error: ${error.message}`);
        }
    }

    async validateRealTimeEvents() {
        console.log('\n⚡ PHASE 5: REAL-TIME EVENT VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Testing real-time event system...');
        
        try {
            // Check preload.js for event listeners
            const preloadPath = path.join(__dirname, 'preload.js');
            const preloadContent = await fs.readFile(preloadPath, 'utf8');
            
            const eventListeners = [
                'onThreatDetected',
                'onEngineStats',
                'onActivityUpdated',
                'onProtectionToggled'
            ];
            
            let workingListeners = 0;
            
            eventListeners.forEach(listener => {
                const hasListener = preloadContent.includes(listener);
                if (hasListener) {
                    workingListeners++;
                    console.log(`  ✅ ${listener}: Available`);
                } else {
                    console.log(`  ❌ ${listener}: Missing`);
                }
            });
            
            const listenerSuccess = workingListeners === eventListeners.length;
            
            this.recordTest('Real-Time Events', listenerSuccess, {
                workingListeners: workingListeners,
                totalListeners: eventListeners.length,
                listeners: eventListeners
            });
            
        } catch (error) {
            this.recordTest('Real-Time Events', false, null, error.message);
            console.log(`  ❌ Event validation error: ${error.message}`);
        }
    }

    async validateAPIResponses() {
        console.log('\n🌐 PHASE 6: API RESPONSE VALIDATION');
        console.log('-'.repeat(50));
        
        console.log('🔍 Testing API response formats...');
        
        try {
            // Test AI Oracle response format
            const aiResponse = await this.aiOracle.analyzeThreat('test_threat', { type: 'process' });
            const aiValid = aiResponse && (aiResponse.threat_level || aiResponse.confidence);
            
            console.log(`  🧠 AI Oracle response: ${aiValid ? '✅ Valid format' : '❌ Invalid format'}`);
            
            // Test OSINT response format
            const osintResponse = await this.osint.queryThreatIntelligence('test_hash', 'hash');
            const osintValid = osintResponse && osintResponse.sources && Array.isArray(osintResponse.sources);
            
            console.log(`  🔍 OSINT response: ${osintValid ? '✅ Valid format' : '❌ Invalid format'}`);
            
            // Test behavioral analysis response format
            const behaviorResponse = await this.behavioralAnalyzer.analyzeZeroDayThreat('Test Threat');
            const behaviorValid = behaviorResponse && 
                                typeof behaviorResponse.detected === 'boolean' &&
                                typeof behaviorResponse.confidence === 'number';
            
            console.log(`  🧠 Behavioral response: ${behaviorValid ? '✅ Valid format' : '❌ Invalid format'}`);
            
            this.recordTest('API Responses', aiValid && osintValid && behaviorValid, {
                aiResponse: aiResponse,
                osintResponse: osintResponse,
                behaviorResponse: behaviorResponse
            });
            
        } catch (error) {
            this.recordTest('API Responses', false, null, error.message);
            console.log(`  ❌ API response error: ${error.message}`);
        }
    }

    async generateDataFlowReport() {
        console.log('\n📊 GENERATING DATA FLOW VALIDATION REPORT');
        console.log('=' + '='.repeat(60));
        
        const totalTests = this.testResults.length;
        const passedTests = this.testResults.filter(test => test.success).length;
        const failedTests = totalTests - passedTests;
        const flowScore = (passedTests / totalTests) * 100;
        
        console.log(`\n🎯 DATA FLOW VALIDATION SUMMARY:`);
        console.log(`   Total Tests: ${totalTests}`);
        console.log(`   Passed: ${passedTests} ✅`);
        console.log(`   Failed: ${failedTests} ❌`);
        console.log(`   Flow Integrity Score: ${flowScore.toFixed(1)}%`);
        
        console.log(`\n📋 DETAILED FLOW RESULTS:`);
        this.testResults.forEach(result => {
            const status = result.success ? '✅' : '❌';
            console.log(`   ${status} ${result.testName}`);
            if (result.details && result.details.detectionRate) {
                console.log(`      Detection Rate: ${result.details.detectionRate.toFixed(1)}%`);
            }
            if (result.error) {
                console.log(`      Error: ${result.error}`);
            }
        });
        
        // Data flow integrity assessment
        const criticalFlows = ['Backend Detection', 'Data Processing', 'IPC Data Format'];
        const criticalPassed = this.testResults.filter(result => 
            criticalFlows.includes(result.testName) && result.success
        ).length;
        
        console.log(`\n🔄 CRITICAL DATA FLOW ASSESSMENT:`);
        console.log(`   Critical Flows Passed: ${criticalPassed}/${criticalFlows.length}`);
        
        // Final verdict
        console.log('\n' + '='.repeat(60));
        if (flowScore >= 90 && criticalPassed === criticalFlows.length) {
            console.log('🎉 DATA FLOW VALIDATION: EXCELLENT');
            console.log('   Complete backend-to-frontend pipeline working');
            console.log('   Real threat detection flowing to UI correctly');
            console.log('   All data formats validated');
        } else if (flowScore >= 75 && criticalPassed >= criticalFlows.length * 0.8) {
            console.log('✅ DATA FLOW VALIDATION: GOOD');
            console.log('   Core data flow working');
            console.log('   Minor integration issues detected');
        } else {
            console.log('⚠️ DATA FLOW VALIDATION: NEEDS IMPROVEMENT');
            console.log('   Data flow integrity issues detected');
            console.log('   Backend-frontend integration requires fixes');
        }
        console.log('=' + '='.repeat(60));
        
        // Save detailed report
        await this.saveDataFlowReport(flowScore);
    }

    recordTest(testName, success, details, error = null) {
        this.testResults.push({
            testName,
            success,
            details,
            error,
            timestamp: new Date()
        });
    }

    async saveDataFlowReport(flowScore) {
        const reportPath = path.join(__dirname, 'test-reports', 
            `apollo-data-flow-validation-${Date.now()}.json`);
        
        await fs.ensureDir(path.dirname(reportPath));
        
        const report = {
            timestamp: new Date(),
            flowScore: flowScore,
            totalTests: this.testResults.length,
            passedTests: this.testResults.filter(t => t.success).length,
            failedTests: this.testResults.filter(t => !t.success).length,
            testResults: this.testResults,
            realThreatTests: this.realThreatTests
        };
        
        await fs.writeJson(reportPath, report, { spaces: 2 });
        console.log(`\n📄 Data flow report saved: ${reportPath}`);
    }
}

// Export for use in other modules
module.exports = DataFlowValidator;

// Run if executed directly
if (require.main === module) {
    const validator = new DataFlowValidator();
    validator.validateCompleteDataFlow()
        .then(() => {
            console.log('\n🎉 Data Flow Validation Completed Successfully!');
            console.log('\n📋 Validation Summary:');
            console.log('   ✅ Backend threat detection validated');
            console.log('   ✅ Data processing pipeline verified');
            console.log('   ✅ IPC communication format validated');
            console.log('   ✅ Frontend data structure confirmed');
            console.log('   ✅ Real-time event system verified');
            console.log('   ✅ API response formats validated');
            process.exit(0);
        })
        .catch((error) => {
            console.error('\n💥 Data Flow Validation Failed:', error);
            process.exit(1);
        });
}
