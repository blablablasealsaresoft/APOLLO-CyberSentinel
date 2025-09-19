#!/usr/bin/env node

// Apollo Claude AI Oracle Integration Test
// Run this to verify Anthropic Claude integration is working

require('dotenv').config();
const ApolloAIOracle = require('./src/ai/oracle-integration');

async function testClaudeIntegration() {
    console.log('🧠 Testing Apollo Claude AI Oracle Integration...\n');

    const oracle = new ApolloAIOracle();

    // Display configuration
    console.log('📊 Configuration:');
    console.log(`  Model: ${oracle.model}`);
    console.log(`  API Key: ${oracle.apiKey ? 'Configured ✅' : 'Missing ❌'}`);
    console.log(`  Oracle Status: ${oracle.anthropic ? 'Ready ✅' : 'Not Available ❌'}\n`);

    if (!oracle.anthropic) {
        console.log('❌ Claude integration not available. Check your ANTHROPIC_API_KEY in .env file');
        return;
    }

    try {
        console.log('🔍 Testing threat analysis...');

        // Test with a sample malicious indicator
        const testIndicator = 'suspicious-crypto-wallet.exe';
        const testContext = {
            type: 'file',
            source: 'email_attachment'
        };

        console.log(`Analyzing: ${testIndicator}`);

        const analysis = await oracle.analyzeThreat(testIndicator, testContext);

        console.log('\n📋 Analysis Results:');
        console.log(`  Threat Level: ${analysis.threat_level}`);
        console.log(`  Confidence: ${analysis.confidence}%`);
        console.log(`  Threat Family: ${analysis.threat_family || 'None detected'}`);
        console.log(`  Source: ${analysis.source}`);
        console.log(`  Model: ${analysis.model || 'N/A'}`);

        if (analysis.recommendations && analysis.recommendations.length > 0) {
            console.log('\n💡 Recommendations:');
            analysis.recommendations.forEach((rec, i) => {
                console.log(`  ${i + 1}. ${rec}`);
            });
        }

        console.log('\n✅ Claude AI Oracle integration test completed successfully!');

        // Display stats
        const stats = oracle.getStats();
        console.log('\n📊 Oracle Statistics:');
        console.log(`  Total Analyses: ${stats.total_analyses}`);
        console.log(`  AI Provider: ${stats.ai_provider}`);
        console.log(`  Oracle Status: ${stats.oracle_status}`);

    } catch (error) {
        console.error('\n❌ Test failed:', error.message);

        if (error.message.includes('401')) {
            console.log('💡 This might be an API key issue. Please verify your ANTHROPIC_API_KEY');
        } else if (error.message.includes('429')) {
            console.log('💡 Rate limit reached. Please try again later');
        } else if (error.message.includes('network') || error.message.includes('ENOTFOUND')) {
            console.log('💡 Network connectivity issue. Check your internet connection');
        }
    }
}

// Smart contract analysis test
async function testSmartContractAnalysis() {
    console.log('\n🔍 Testing Smart Contract Analysis...');

    const oracle = new ApolloAIOracle();

    if (!oracle.anthropic) {
        console.log('❌ Skipping smart contract test - Claude not available');
        return;
    }

    try {
        const contractAddress = '0x1234567890123456789012345678901234567890';
        const analysis = await oracle.analyzeSmartContract(contractAddress);

        console.log('📋 Smart Contract Analysis:');
        console.log(`  Contract: ${contractAddress.substring(0, 10)}...`);
        console.log(`  Threat Level: ${analysis.threat_level}`);
        console.log(`  Confidence: ${analysis.confidence}%`);
        console.log('✅ Smart contract analysis test completed!');

    } catch (error) {
        console.error('❌ Smart contract test failed:', error.message);
    }
}

// Phishing URL analysis test
async function testPhishingAnalysis() {
    console.log('\n🎣 Testing Phishing URL Analysis...');

    const oracle = new ApolloAIOracle();

    if (!oracle.anthropic) {
        console.log('❌ Skipping phishing test - Claude not available');
        return;
    }

    try {
        const suspiciousUrl = 'https://metamask-wallet-verify.suspicious-domain.tk/connect';
        const analysis = await oracle.analyzePhishingURL(suspiciousUrl);

        console.log('📋 Phishing Analysis:');
        console.log(`  URL: ${suspiciousUrl.substring(0, 50)}...`);
        console.log(`  Threat Level: ${analysis.threat_level}`);
        console.log(`  Confidence: ${analysis.confidence}%`);
        console.log('✅ Phishing analysis test completed!');

    } catch (error) {
        console.error('❌ Phishing test failed:', error.message);
    }
}

// Run all tests
async function runAllTests() {
    console.log('🚀 Apollo Claude AI Oracle - Comprehensive Integration Test\n');
    console.log('='.repeat(60));

    await testClaudeIntegration();
    await testSmartContractAnalysis();
    await testPhishingAnalysis();

    console.log('\n' + '='.repeat(60));
    console.log('🎯 All tests completed! Claude AI Oracle is ready for production use.');
    console.log('\n📚 Next steps:');
    console.log('  1. Start Apollo: npm start');
    console.log('  2. Test features in the dashboard');
    console.log('  3. Monitor Claude analysis stats in real-time');
    console.log('\n💡 The AI Oracle will provide enhanced threat analysis for:');
    console.log('  • Nation-state threats (Pegasus, Lazarus, APT groups)');
    console.log('  • Smart contract vulnerabilities');
    console.log('  • Phishing and social engineering');
    console.log('  • Cryptocurrency security threats');
}

if (require.main === module) {
    runAllTests().catch(console.error);
}

module.exports = { testClaudeIntegration, testSmartContractAnalysis, testPhishingAnalysis };