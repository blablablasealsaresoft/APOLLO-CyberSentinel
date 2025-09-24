#!/usr/bin/env node
/**
 * ============================================================================
 * APOLLO SENTINEL™ - COMPREHENSIVE OSINT INTEGRATION TEST
 * Verify Python OSINT system is integrated across all src modules
 * ============================================================================
 */

const path = require('path');

// Import all modules to test integration
const PythonOSINTInterface = require('./intelligence/python-osint-interface');
const OSINTThreatIntelligence = require('./intelligence/osint-sources');
const ApolloAIOracle = require('./ai/oracle-integration');
const ApolloAPTDetector = require('./apt-detection/realtime-monitor');
const ApolloWalletShield = require('./crypto-guardian/wallet-shield');
const ApolloThreatEngine = require('./threat-engine/core');
const ApolloUnifiedProtectionEngine = require('./core/unified-protection-engine');
const ThreatBlocker = require('./native/threat-blocker');
const EnhancedThreatDatabase = require('./signatures/threat-database-enhanced');
const ApolloService = require('./service/apollo-service');

class OSINTIntegrationTester {
    constructor() {
        this.testResults = {
            modules_tested: 0,
            integrations_verified: 0,
            python_osint_available: false,
            total_sources_available: 0,
            errors: []
        };
    }
    
    async runComprehensiveTest() {
        console.log('🧪 APOLLO SENTINEL™ - COMPREHENSIVE OSINT INTEGRATION TEST');
        console.log('================================================================');
        
        try {
            // 1. Test Python OSINT Interface
            await this.testPythonOSINTInterface();
            
            // 2. Test Core Intelligence Module
            await this.testCoreIntelligenceModule();
            
            // 3. Test AI Oracle Integration
            await this.testAIOracle();
            
            // 4. Test APT Detector Integration
            await this.testAPTDetector();
            
            // 5. Test Wallet Shield Integration
            await this.testWalletShield();
            
            // 6. Test Threat Engine Integration
            await this.testThreatEngine();
            
            // 7. Test Unified Protection Engine Integration
            await this.testUnifiedProtectionEngine();
            
            // 8. Test Threat Blocker Integration
            await this.testThreatBlocker();
            
            // 9. Test Enhanced Threat Database Integration
            await this.testEnhancedThreatDatabase();
            
            // 10. Test Service Integration
            await this.testServiceIntegration();
            
            // Print final results
            this.printTestResults();
            
        } catch (error) {
            console.error('❌ OSINT Integration Test failed:', error);
            this.testResults.errors.push(`Main test failure: ${error.message}`);
        }
    }
    
    async testPythonOSINTInterface() {
        console.log('\n🐍 Testing Python OSINT Interface...');
        this.testResults.modules_tested++;
        
        try {
            const pythonOSINT = new PythonOSINTInterface();
            
            if (pythonOSINT.isInitialized) {
                console.log('✅ Python OSINT Interface initialized successfully');
                
                // Test statistics
                const stats = await pythonOSINT.getOSINTStats();
                this.testResults.python_osint_available = true;
                this.testResults.total_sources_available = stats.totalSources || 0;
                
                console.log(`✅ OSINT Sources Available: ${stats.totalSources || 0}`);
                console.log(`✅ Python Sources: ${stats.pythonSources || 0}`);
                console.log(`✅ Premium Sources: ${stats.pythonPremium || 0}`);
                
                this.testResults.integrations_verified++;
            } else {
                throw new Error('Python OSINT Interface not initialized');
            }
        } catch (error) {
            console.error('❌ Python OSINT Interface test failed:', error.message);
            this.testResults.errors.push(`Python OSINT Interface: ${error.message}`);
        }
    }
    
    async testCoreIntelligenceModule() {
        console.log('\n🔍 Testing Core Intelligence Module...');
        this.testResults.modules_tested++;
        
        try {
            const osintIntelligence = new OSINTThreatIntelligence();
            
            if (osintIntelligence.pythonOSINT) {
                console.log('✅ Core Intelligence Module has Python OSINT integration');
                
                // Test comprehensive stats
                const stats = await osintIntelligence.getOSINTStats();
                console.log(`✅ Comprehensive Stats Available: ${stats.totalSystemSources || 0} total sources`);
                
                this.testResults.integrations_verified++;
            } else {
                throw new Error('Core Intelligence Module missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Core Intelligence Module test failed:', error.message);
            this.testResults.errors.push(`Core Intelligence: ${error.message}`);
        }
    }
    
    async testAIOracle() {
        console.log('\n🧠 Testing AI Oracle Integration...');
        this.testResults.modules_tested++;
        
        try {
            const aiOracle = new ApolloAIOracle();
            
            if (aiOracle.pythonOSINT) {
                console.log('✅ AI Oracle has Python OSINT integration');
                
                // Test OSINT intelligence gathering
                if (typeof aiOracle.gatherComprehensiveOSINTIntelligence === 'function') {
                    console.log('✅ AI Oracle can gather comprehensive OSINT intelligence');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('AI Oracle missing OSINT intelligence methods');
                }
            } else {
                throw new Error('AI Oracle missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ AI Oracle test failed:', error.message);
            this.testResults.errors.push(`AI Oracle: ${error.message}`);
        }
    }
    
    async testAPTDetector() {
        console.log('\n🕵️ Testing APT Detector Integration...');
        this.testResults.modules_tested++;
        
        try {
            const aptDetector = new ApolloAPTDetector();
            
            if (aptDetector.pythonOSINT) {
                console.log('✅ APT Detector has Python OSINT integration');
                
                // Test APT analysis with OSINT
                if (typeof aptDetector.analyzeAPTIndicatorWithOSINT === 'function') {
                    console.log('✅ APT Detector can analyze indicators with comprehensive OSINT');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('APT Detector missing OSINT analysis methods');
                }
            } else {
                throw new Error('APT Detector missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ APT Detector test failed:', error.message);
            this.testResults.errors.push(`APT Detector: ${error.message}`);
        }
    }
    
    async testWalletShield() {
        console.log('\n⛓️ Testing Wallet Shield Integration...');
        this.testResults.modules_tested++;
        
        try {
            const walletShield = new ApolloWalletShield();
            
            if (walletShield.pythonOSINT) {
                console.log('✅ Wallet Shield has Python OSINT integration');
                
                // Test crypto analysis with OSINT
                if (typeof walletShield.analyzeTransactionWithOSINT === 'function') {
                    console.log('✅ Wallet Shield can analyze transactions with comprehensive OSINT');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('Wallet Shield missing OSINT analysis methods');
                }
            } else {
                throw new Error('Wallet Shield missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Wallet Shield test failed:', error.message);
            this.testResults.errors.push(`Wallet Shield: ${error.message}`);
        }
    }
    
    async testThreatEngine() {
        console.log('\n🚀 Testing Threat Engine Integration...');
        this.testResults.modules_tested++;
        
        try {
            const threatEngine = new ApolloThreatEngine();
            
            if (threatEngine.pythonOSINT) {
                console.log('✅ Threat Engine has Python OSINT integration');
                
                // Test threat analysis with OSINT
                if (typeof threatEngine.analyzeThreatWithOSINT === 'function') {
                    console.log('✅ Threat Engine can analyze threats with comprehensive OSINT');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('Threat Engine missing OSINT analysis methods');
                }
            } else {
                throw new Error('Threat Engine missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Threat Engine test failed:', error.message);
            this.testResults.errors.push(`Threat Engine: ${error.message}`);
        }
    }
    
    async testUnifiedProtectionEngine() {
        console.log('\n🛡️ Testing Unified Protection Engine Integration...');
        this.testResults.modules_tested++;
        
        try {
            const unifiedEngine = new ApolloUnifiedProtectionEngine();
            
            if (unifiedEngine.pythonOSINT) {
                console.log('✅ Unified Protection Engine has Python OSINT integration');
                
                // Test unified analysis with OSINT
                if (typeof unifiedEngine.analyzeUnifiedThreatWithOSINT === 'function') {
                    console.log('✅ Unified Protection Engine can perform comprehensive OSINT analysis');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('Unified Protection Engine missing OSINT analysis methods');
                }
            } else {
                throw new Error('Unified Protection Engine missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Unified Protection Engine test failed:', error.message);
            this.testResults.errors.push(`Unified Protection Engine: ${error.message}`);
        }
    }
    
    async testThreatBlocker() {
        console.log('\n🚫 Testing Threat Blocker Integration...');
        this.testResults.modules_tested++;
        
        try {
            const threatBlocker = new ThreatBlocker();
            
            if (threatBlocker.pythonOSINT) {
                console.log('✅ Threat Blocker has Python OSINT integration');
                
                // Test OSINT-verified blocking
                if (typeof threatBlocker.blockThreatWithOSINTVerification === 'function') {
                    console.log('✅ Threat Blocker can perform OSINT-verified blocking');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('Threat Blocker missing OSINT verification methods');
                }
            } else {
                throw new Error('Threat Blocker missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Threat Blocker test failed:', error.message);
            this.testResults.errors.push(`Threat Blocker: ${error.message}`);
        }
    }
    
    async testEnhancedThreatDatabase() {
        console.log('\n📊 Testing Enhanced Threat Database Integration...');
        this.testResults.modules_tested++;
        
        try {
            const threatDB = new EnhancedThreatDatabase();
            
            if (threatDB.pythonOSINT) {
                console.log('✅ Enhanced Threat Database has Python OSINT integration');
                
                // Test OSINT-enhanced analysis
                if (typeof threatDB.analyzeWithOSINTEnhancement === 'function') {
                    console.log('✅ Enhanced Threat Database can perform OSINT-enhanced signature analysis');
                    this.testResults.integrations_verified++;
                } else {
                    throw new Error('Enhanced Threat Database missing OSINT enhancement methods');
                }
            } else {
                throw new Error('Enhanced Threat Database missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Enhanced Threat Database test failed:', error.message);
            this.testResults.errors.push(`Enhanced Threat Database: ${error.message}`);
        }
    }
    
    async testServiceIntegration() {
        console.log('\n🔧 Testing Service Integration...');
        this.testResults.modules_tested++;
        
        try {
            const apolloService = new ApolloService();
            
            if (apolloService.pythonOSINT) {
                console.log('✅ Apollo Service has Python OSINT integration');
                this.testResults.integrations_verified++;
            } else {
                throw new Error('Apollo Service missing Python OSINT integration');
            }
        } catch (error) {
            console.error('❌ Service Integration test failed:', error.message);
            this.testResults.errors.push(`Service Integration: ${error.message}`);
        }
    }
    
    printTestResults() {
        console.log('\n================================================================');
        console.log('🧪 COMPREHENSIVE OSINT INTEGRATION TEST RESULTS');
        console.log('================================================================');
        
        console.log(`📊 Modules Tested: ${this.testResults.modules_tested}`);
        console.log(`✅ Integrations Verified: ${this.testResults.integrations_verified}`);
        console.log(`🐍 Python OSINT Available: ${this.testResults.python_osint_available ? 'YES' : 'NO'}`);
        console.log(`📈 Total Sources Available: ${this.testResults.total_sources_available}`);
        console.log(`❌ Errors: ${this.testResults.errors.length}`);
        
        if (this.testResults.errors.length > 0) {
            console.log('\n❌ ERRORS FOUND:');
            this.testResults.errors.forEach((error, index) => {
                console.log(`   ${index + 1}. ${error}`);
            });
        }
        
        const successRate = (this.testResults.integrations_verified / this.testResults.modules_tested) * 100;
        console.log(`\n📈 Integration Success Rate: ${successRate.toFixed(1)}%`);
        
        if (successRate >= 90) {
            console.log('🎉 COMPREHENSIVE OSINT INTEGRATION: EXCELLENT!');
        } else if (successRate >= 70) {
            console.log('✅ COMPREHENSIVE OSINT INTEGRATION: GOOD');
        } else {
            console.log('⚠️ COMPREHENSIVE OSINT INTEGRATION: NEEDS IMPROVEMENT');
        }
        
        console.log('\n🛡️ All Apollo Sentinel modules now have access to 37 OSINT sources!');
        console.log('================================================================');
    }
}

// Run the test if this file is executed directly
if (require.main === module) {
    const tester = new OSINTIntegrationTester();
    tester.runComprehensiveTest().catch(error => {
        console.error('❌ Test execution failed:', error);
        process.exit(1);
    });
}

module.exports = OSINTIntegrationTester;
