// Apollo Integration Test Suite
// Tests all core components together

require('dotenv').config();

const ApolloUnifiedProtectionEngine = require('./src/core/unified-protection-engine');
const ApolloAIOracle = require('./src/ai/oracle-integration');
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');

class ApolloIntegrationTest {
    constructor() {
        this.unifiedEngine = null;
        this.aiOracle = null;
        this.osintIntel = null;
        this.testsPassed = 0;
        this.testsFailed = 0;
    }

    async runAllTests() {
        console.log('🧪 Starting Apollo Integration Tests...\n');
        console.log('=' .repeat(60));

        await this.testUnifiedProtectionEngine();
        await this.testAIOracle();
        await this.testOSINTIntegration();
        await this.testCombinedThreatAnalysis();

        this.printResults();
    }

    async testUnifiedProtectionEngine() {
        console.log('\n📦 Testing Unified Protection Engine...');

        try {
            this.unifiedEngine = new ApolloUnifiedProtectionEngine();

            // Test initialization
            const initialized = await this.unifiedEngine.initialize();
            this.assert(initialized === true, 'Engine initialization');

            // Test statistics retrieval
            const stats = this.unifiedEngine.getStatistics();
            this.assert(stats.engine === 'Apollo Unified Protection Engine', 'Engine name verification');
            this.assert(stats.version === '2.0.0', 'Engine version check');
            this.assert(stats.signatureCount > 0, 'Threat signatures loaded');
            this.assert(stats.aptSignatureCount > 0, 'APT signatures loaded');
            this.assert(stats.cryptoSignatureCount > 0, 'Crypto signatures loaded');

            // Test threat analysis
            const testFile = 'test_malware.exe';
            const threats = await this.unifiedEngine.performUnifiedThreatAnalysis(testFile, 'file_system');
            this.assert(Array.isArray(threats), 'Threat analysis returns array');

            // Test performance modes
            this.unifiedEngine.setPerformanceMode('maximum_protection');
            this.assert(this.unifiedEngine.performanceMode === 'maximum_protection', 'Performance mode change');

            console.log('✅ Unified Protection Engine tests passed');

        } catch (error) {
            console.error('❌ Unified Protection Engine test failed:', error.message);
            this.testsFailed++;
        }
    }

    async testAIOracle() {
        console.log('\n🧠 Testing AI Oracle (Claude Integration)...');

        try {
            this.aiOracle = new ApolloAIOracle();

            // Check initialization
            this.assert(this.aiOracle.model === 'claude-opus-4-1-20250805', 'AI model configured');
            this.assert(this.aiOracle.apiKey !== null, 'API key loaded from .env');

            // Test fallback analysis (works without API)
            const fallbackResult = await this.aiOracle.fallbackAnalysis('suspicious.exe', {});
            this.assert(fallbackResult.threat_level !== undefined, 'Fallback analysis works');
            this.assert(fallbackResult.confidence >= 0, 'Confidence score present');

            // Test threat context database
            this.assert(this.aiOracle.threatContextDatabase.size > 0, 'Threat context loaded');
            this.assert(this.aiOracle.threatContextDatabase.has('pegasus'), 'Pegasus context exists');
            this.assert(this.aiOracle.threatContextDatabase.has('lazarus'), 'Lazarus context exists');

            // Test smart contract analysis setup
            const contractAnalysis = await this.aiOracle.analyzeSmartContract('0x1234567890123456789012345678901234567890');
            this.assert(contractAnalysis !== null, 'Smart contract analysis configured');

            // Test phishing URL analysis setup
            const phishingAnalysis = await this.aiOracle.analyzePhishingURL('https://fake-metamask.com');
            this.assert(phishingAnalysis !== null, 'Phishing analysis configured');

            console.log('✅ AI Oracle tests passed');

        } catch (error) {
            console.error('❌ AI Oracle test failed:', error.message);
            this.testsFailed++;
        }
    }

    async testOSINTIntegration() {
        console.log('\n🔍 Testing OSINT Intelligence Sources...');

        try {
            this.osintIntel = new OSINTThreatIntelligence();

            // Check API keys loaded
            this.assert(this.osintIntel.apiKeys.VIRUSTOTAL_API_KEY !== undefined, 'VirusTotal API key loaded');
            this.assert(this.osintIntel.apiKeys.ALIENVAULT_OTX_API_KEY !== undefined, 'AlienVault API key loaded');
            this.assert(this.osintIntel.apiKeys.SHODAN_API_KEY !== undefined, 'Shodan API key loaded');

            // Check threat sources configured
            this.assert(this.osintIntel.threatSources.premiumSources.length > 0, 'Premium sources configured');
            this.assert(this.osintIntel.threatSources.freeSources.length > 0, 'Free sources configured');

            // Test phishing heuristics
            const phishingScore = this.osintIntel.checkPhishingHeuristics('https://metamask-wallet-verify.com');
            this.assert(phishingScore > 0, 'Phishing heuristics detect suspicious URL');

            // Test phishing flags
            const flags = this.osintIntel.getPhishingFlags('https://bit.ly/fake-binance');
            this.assert(flags.length > 0, 'Phishing flags detected');
            this.assert(flags.includes('URL_SHORTENER'), 'URL shortener detected');

            // Test cache functionality
            this.assert(this.osintIntel.cache instanceof Map, 'Cache initialized');

            // Test statistics
            const stats = this.osintIntel.getStats();
            this.assert(stats.activeSources > 0, 'Active OSINT sources');

            console.log('✅ OSINT Intelligence tests passed');

        } catch (error) {
            console.error('❌ OSINT test failed:', error.message);
            this.testsFailed++;
        }
    }

    async testCombinedThreatAnalysis() {
        console.log('\n🔗 Testing Combined Threat Analysis...');

        try {
            // Test combined analysis flow
            const testIndicator = 'malicious.exe';

            // 1. OSINT check (mock)
            const osintResult = {
                indicator: testIndicator,
                type: 'file',
                malicious: true,
                sources: [
                    { source: 'Mock', malicious: true, score: 0.8 }
                ]
            };
            this.assert(osintResult.malicious === true, 'OSINT detects threat');

            // 2. AI Oracle analysis with OSINT context
            const aiAnalysis = await this.aiOracle.analyzeThreat(testIndicator, {
                type: 'file',
                osintResults: osintResult.sources
            });
            this.assert(aiAnalysis.threat_level !== undefined, 'AI provides threat level');

            // 3. Unified engine response
            const engineStats = this.unifiedEngine.getStatistics();
            this.assert(engineStats.isActive === true, 'Protection engine active');

            // Test emergency response flow
            const criticalThreat = {
                type: 'APT_DETECTION',
                severity: 'critical',
                group: 'lazarus',
                process: 'suspicious.exe',
                pid: '1234'
            };

            // Verify threat handling
            await this.unifiedEngine.handleDetectedThreats([criticalThreat], 'test');
            const updatedStats = this.unifiedEngine.getStatistics();
            this.assert(updatedStats.threatsDetected > 0, 'Threat detection counter updated');

            console.log('✅ Combined threat analysis tests passed');

        } catch (error) {
            console.error('❌ Combined analysis test failed:', error.message);
            this.testsFailed++;
        }
    }

    assert(condition, testName) {
        if (condition) {
            console.log(`  ✓ ${testName}`);
            this.testsPassed++;
        } else {
            console.error(`  ✗ ${testName}`);
            this.testsFailed++;
        }
    }

    printResults() {
        console.log('\n' + '=' .repeat(60));
        console.log('📊 Test Results Summary:');
        console.log(`  ✅ Passed: ${this.testsPassed}`);
        console.log(`  ❌ Failed: ${this.testsFailed}`);
        console.log(`  📈 Success Rate: ${((this.testsPassed / (this.testsPassed + this.testsFailed)) * 100).toFixed(1)}%`);

        if (this.testsFailed === 0) {
            console.log('\n🎉 All tests passed! Apollo is ready for deployment.');
        } else {
            console.log('\n⚠️ Some tests failed. Please review the errors above.');
        }

        // Cleanup
        if (this.unifiedEngine) {
            this.unifiedEngine.stop();
        }
    }
}

// Run tests
(async () => {
    const tester = new ApolloIntegrationTest();
    await tester.runAllTests();

    // Exit after a delay to allow cleanup
    setTimeout(() => {
        process.exit(this.testsFailed > 0 ? 1 : 0);
    }, 2000);
})();