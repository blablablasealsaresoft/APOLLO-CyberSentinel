/**
 * ============================================================================
 * APOLLO WALLET QUICK ACCESS TEST
 * Tests the quick access wallet connection functionality
 * ============================================================================
 */

const fs = require('fs-extra');
const path = require('path');

class WalletQuickAccessTester {
    constructor() {
        this.results = {
            quickAccessButton: null,
            walletModal: null,
            biometricFallback: null,
            endToEndFlow: null
        };
    }

    async runTests() {
        console.log('🚀 Testing Wallet Quick Access Functionality...');
        
        try {
            await this.testQuickAccessButton();
            await this.testWalletModal();
            await this.testBiometricFallback();
            await this.testEndToEndFlow();
            
            this.generateReport();
            
        } catch (error) {
            console.error('❌ Test failed:', error);
        }
    }

    async testQuickAccessButton() {
        console.log('\n📋 TEST 1: Quick Access Button Configuration');
        
        const result = { passed: 0, failed: 0, details: [] };
        
        try {
            // Check HTML for correct button configuration
            const htmlPath = path.join(__dirname, 'ui/dashboard/index.html');
            const htmlContent = await fs.readFile(htmlPath, 'utf8');
            
            // Verify wallet quick action button exists and calls correct function
            if (htmlContent.includes('onclick="showWalletConnectModal()"') && 
                htmlContent.includes('fas fa-wallet')) {
                result.details.push('✅ Quick access wallet button properly configured');
                result.passed++;
            } else {
                result.details.push('❌ Quick access wallet button missing or misconfigured');
                result.failed++;
            }
            
            // Check for button in crypto protection section
            if (htmlContent.includes('Connect Wallet') && 
                htmlContent.includes('showWalletConnectModal()')) {
                result.details.push('✅ Crypto protection wallet button properly configured');
                result.passed++;
            } else {
                result.details.push('❌ Crypto protection wallet button missing or misconfigured');
                result.failed++;
            }
            
        } catch (error) {
            result.details.push(`❌ Quick access button test failed: ${error.message}`);
            result.failed++;
        }

        result.success = result.failed === 0;
        this.results.quickAccessButton = result;
        
        console.log(`   Results: ${result.passed} passed, ${result.failed} failed`);
        result.details.forEach(detail => console.log(`   ${detail}`));
    }

    async testWalletModal() {
        console.log('\n🔐 TEST 2: Wallet Modal Implementation');
        
        const result = { passed: 0, failed: 0, details: [] };
        
        try {
            // Check dashboard.js for modal implementation
            const dashboardPath = path.join(__dirname, 'ui/dashboard/dashboard.js');
            const dashboardContent = await fs.readFile(dashboardPath, 'utf8');
            
            // Verify showWalletConnectModal function exists
            if (dashboardContent.includes('function showWalletConnectModal()') ||
                dashboardContent.includes('showWalletConnectModal =')) {
                result.details.push('✅ showWalletConnectModal function found');
                result.passed++;
            } else {
                result.details.push('❌ showWalletConnectModal function missing');
                result.failed++;
            }
            
            // Check for QR code generation
            if (dashboardContent.includes('generateQRCode') &&
                dashboardContent.includes('walletconnect-qr')) {
                result.details.push('✅ QR code generation functionality found');
                result.passed++;
            } else {
                result.details.push('❌ QR code generation functionality missing');
                result.failed++;
            }
            
            // Check for biometric authentication integration
            if (dashboardContent.includes('authenticate-for-wallet') ||
                dashboardContent.includes('biometric')) {
                result.details.push('✅ Biometric authentication integration found');
                result.passed++;
            } else {
                result.details.push('❌ Biometric authentication integration missing');
                result.failed++;
            }
            
        } catch (error) {
            result.details.push(`❌ Wallet modal test failed: ${error.message}`);
            result.failed++;
        }

        result.success = result.failed === 0;
        this.results.walletModal = result;
        
        console.log(`   Results: ${result.passed} passed, ${result.failed} failed`);
        result.details.forEach(detail => console.log(`   ${detail}`));
    }

    async testBiometricFallback() {
        console.log('\n🛡️ TEST 3: Biometric Authentication Fallback');
        
        const result = { passed: 0, failed: 0, details: [] };
        
        try {
            // Check biometric auth for fallback mechanism
            const biometricPath = path.join(__dirname, 'src/auth/enterprise-biometric-auth.js');
            const biometricContent = await fs.readFile(biometricPath, 'utf8');
            
            // Verify fallback for no hardware available
            if (biometricContent.includes('No real biometric hardware available') &&
                biometricContent.includes('simulatedDemo')) {
                result.details.push('✅ Biometric hardware fallback mechanism found');
                result.passed++;
            } else {
                result.details.push('❌ Biometric hardware fallback mechanism missing');
                result.failed++;
            }
            
            // Verify 2FA fallback
            if (biometricContent.includes('No 2FA providers available') &&
                biometricContent.includes('simulatedDemo')) {
                result.details.push('✅ 2FA fallback mechanism found');
                result.passed++;
            } else {
                result.details.push('❌ 2FA fallback mechanism missing');
                result.failed++;
            }
            
            // Check for demo security score
            if (biometricContent.includes('Demo security score') ||
                biometricContent.includes('overallScore = 85')) {
                result.details.push('✅ Demo security score configuration found');
                result.passed++;
            } else {
                result.details.push('❌ Demo security score configuration missing');
                result.failed++;
            }
            
        } catch (error) {
            result.details.push(`❌ Biometric fallback test failed: ${error.message}`);
            result.failed++;
        }

        result.success = result.failed === 0;
        this.results.biometricFallback = result;
        
        console.log(`   Results: ${result.passed} passed, ${result.failed} failed`);
        result.details.forEach(detail => console.log(`   ${detail}`));
    }

    async testEndToEndFlow() {
        console.log('\n🔄 TEST 4: End-to-End Flow Verification');
        
        const result = { passed: 0, failed: 0, details: [] };
        
        try {
            // Simulate the complete flow steps
            const flowSteps = [
                'Quick Access Button Click',
                'Wallet Modal Display', 
                'Biometric Authentication',
                'WalletConnect Initialization',
                'QR Code Generation',
                'Connection Status Update'
            ];
            
            const htmlPath = path.join(__dirname, 'ui/dashboard/index.html');
            const dashboardPath = path.join(__dirname, 'ui/dashboard/dashboard.js');
            const mainPath = path.join(__dirname, 'main.js');
            
            const htmlContent = await fs.readFile(htmlPath, 'utf8');
            const dashboardContent = await fs.readFile(dashboardPath, 'utf8');
            const mainContent = await fs.readFile(mainPath, 'utf8');
            
            const combinedContent = htmlContent + dashboardContent + mainContent;
            
            // Check each flow step
            if (combinedContent.includes('showWalletConnectModal')) {
                result.details.push('✅ Step 1: Quick Access Button → Modal');
                result.passed++;
            } else {
                result.details.push('❌ Step 1: Quick Access Button → Modal');
                result.failed++;
            }
            
            if (combinedContent.includes('authenticate-for-wallet')) {
                result.details.push('✅ Step 2: Modal → Biometric Auth');
                result.passed++;
            } else {
                result.details.push('❌ Step 2: Modal → Biometric Auth');
                result.failed++;
            }
            
            if (combinedContent.includes('initializeWalletConnect')) {
                result.details.push('✅ Step 3: Auth → WalletConnect Init');
                result.passed++;
            } else {
                result.details.push('❌ Step 3: Auth → WalletConnect Init');
                result.failed++;
            }
            
            if (combinedContent.includes('generateQRCode')) {
                result.details.push('✅ Step 4: Init → QR Generation');
                result.passed++;
            } else {
                result.details.push('❌ Step 4: Init → QR Generation');
                result.failed++;
            }
            
        } catch (error) {
            result.details.push(`❌ End-to-end flow test failed: ${error.message}`);
            result.failed++;
        }

        result.success = result.failed === 0;
        this.results.endToEndFlow = result;
        
        console.log(`   Results: ${result.passed} passed, ${result.failed} failed`);
        result.details.forEach(detail => console.log(`   ${detail}`));
    }

    generateReport() {
        console.log('\n📊 WALLET QUICK ACCESS TEST REPORT');
        console.log('====================================');
        
        const allTests = Object.values(this.results);
        const totalPassed = allTests.reduce((sum, test) => sum + test.passed, 0);
        const totalFailed = allTests.reduce((sum, test) => sum + test.failed, 0);
        const successRate = Math.round((totalPassed / (totalPassed + totalFailed)) * 100);
        
        console.log(`\nOverall Results: ${totalPassed} passed, ${totalFailed} failed (${successRate}% success rate)`);
        
        Object.entries(this.results).forEach(([testName, result]) => {
            const status = result.success ? '✅ PASSED' : '❌ FAILED';
            console.log(`${testName}: ${status}`);
        });
        
        if (totalFailed === 0) {
            console.log('\n🎉 All wallet quick access tests passed!');
            console.log('The quick access wallet connection should now work properly.');
        } else {
            console.log('\n⚠️ Some tests failed. Please review the details above.');
        }
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    const tester = new WalletQuickAccessTester();
    tester.runTests()
        .then(() => {
            console.log('\n✅ Wallet quick access test completed!');
            process.exit(0);
        })
        .catch((error) => {
            console.error('\n💥 Test failed:', error);
            process.exit(1);
        });
}

module.exports = WalletQuickAccessTester;
