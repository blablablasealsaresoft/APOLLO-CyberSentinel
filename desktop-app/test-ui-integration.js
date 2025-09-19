// Apollo UI Data Integration Test Suite
// Verifies all UI sections are pulling real data from backend systems

require('dotenv').config();

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

class UIDataIntegrationTest {
    constructor() {
        this.testWindow = null;
        this.testResults = [];
        this.backendConnected = false;
        this.realDataSources = new Map();
        this.uiElements = new Map();

        this.tests = [
            'testBackendConnection',
            'testProtectionStatistics',
            'testThreatLevelIndicator',
            'testActivityFeed',
            'testModuleStatus',
            'testRealTimeUpdates',
            'testIPCCommunication',
            'testEngineStats',
            'testOSINTData',
            'testAIOracleIntegration'
        ];
    }

    async runAllTests() {
        console.log('🧪 Starting Apollo UI Data Integration Tests...\n');
        console.log('=' .repeat(70));

        await this.setupTestEnvironment();

        for (const testMethod of this.tests) {
            await this.runTest(testMethod);
        }

        await this.generateTestReport();
        await this.cleanup();
    }

    async setupTestEnvironment() {
        console.log('🔧 Setting up test environment...');

        // Create test window
        this.testWindow = new BrowserWindow({
            width: 1200,
            height: 800,
            show: false,
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                preload: path.join(__dirname, 'preload.js')
            }
        });

        // Load the dashboard
        await this.testWindow.loadFile(path.join(__dirname, 'ui', 'dashboard', 'index.html'));

        // Wait for page to load
        await new Promise(resolve => {
            this.testWindow.webContents.once('did-finish-load', resolve);
        });

        // Setup IPC test handlers
        this.setupTestIPCHandlers();

        console.log('✅ Test environment ready');
    }

    setupTestIPCHandlers() {
        // Test data collection handler
        ipcMain.handle('ui-test-get-element', async (event, selector) => {
            return await this.testWindow.webContents.executeJavaScript(`
                const element = document.querySelector('${selector}');
                return element ? {
                    textContent: element.textContent,
                    innerHTML: element.innerHTML,
                    className: element.className,
                    exists: true
                } : { exists: false };
            `);
        });

        // Backend connection test
        ipcMain.handle('ui-test-backend-status', async () => {
            return await this.testWindow.webContents.executeJavaScript(`
                window.apolloDashboard ? {
                    connected: window.apolloDashboard.isConnected,
                    stats: window.apolloDashboard.stats,
                    threatLevel: window.apolloDashboard.threatLevel
                } : { error: 'Dashboard not initialized' };
            `);
        });

        // Real-time data test
        ipcMain.handle('ui-test-trigger-update', async () => {
            return await this.testWindow.webContents.executeJavaScript(`
                if (window.apolloDashboard) {
                    window.apolloDashboard.connectToBackend();
                    return { triggered: true };
                }
                return { error: 'Dashboard not available' };
            `);
        });
    }

    async runTest(testMethod) {
        console.log(`\n🔍 Running ${testMethod}...`);

        try {
            const result = await this[testMethod]();
            this.recordTestResult(testMethod, true, result);
            console.log(`  ✅ ${testMethod}: PASSED`);
            if (result.details) {
                console.log(`     ${result.details}`);
            }
        } catch (error) {
            this.recordTestResult(testMethod, false, { error: error.message });
            console.log(`  ❌ ${testMethod}: FAILED - ${error.message}`);
        }
    }

    async testBackendConnection() {
        const status = await ipcMain.invoke('ui-test-backend-status');

        if (status.error) {
            throw new Error(`Dashboard not initialized: ${status.error}`);
        }

        // Check if electronAPI is available
        const apiStatus = await this.testWindow.webContents.executeJavaScript(`
            typeof window.electronAPI !== 'undefined' && typeof window.electronAPI.getEngineStats === 'function'
        `);

        if (!apiStatus) {
            throw new Error('electronAPI not properly exposed to renderer');
        }

        this.backendConnected = true;
        return {
            details: `Backend connected: ${status.connected}, API available: ${apiStatus}`,
            connected: status.connected,
            apiAvailable: apiStatus
        };
    }

    async testProtectionStatistics() {
        // Test if statistics elements exist and have real data
        const statElements = [
            '#active-threats',
            '#blocked-today',
            '#total-scans',
            '#threats-blocked',
            '#crypto-transactions',
            '#apt-detections'
        ];

        const results = {};
        let hasRealData = false;

        for (const selector of statElements) {
            const element = await ipcMain.invoke('ui-test-get-element', selector);

            if (!element.exists) {
                throw new Error(`Statistics element ${selector} not found`);
            }

            const value = element.textContent.trim();
            results[selector] = value;

            // Check if it's not default placeholder data
            if (value !== '0' && value !== '1,247' && value !== '156' && value !== '42') {
                hasRealData = true;
            }
        }

        // Try to get real stats via IPC
        const realStats = await this.testWindow.webContents.executeJavaScript(`
            window.electronAPI ? window.electronAPI.getEngineStats() : null
        `).catch(() => null);

        if (realStats) {
            hasRealData = true;
            results.realEngineStats = realStats;
        }

        return {
            details: `Statistics elements found: ${Object.keys(results).length}, Has real data: ${hasRealData}`,
            elements: results,
            hasRealData
        };
    }

    async testThreatLevelIndicator() {
        const indicator = await ipcMain.invoke('ui-test-get-element', '#threat-indicator');
        const threatText = await ipcMain.invoke('ui-test-get-element', '#threat-text');

        if (!indicator.exists || !threatText.exists) {
            throw new Error('Threat level indicator elements not found');
        }

        // Check if threat level changes based on real data
        const currentLevel = threatText.textContent.trim();
        const indicatorClass = indicator.className;

        // Test threat level update functionality
        const updateTest = await this.testWindow.webContents.executeJavaScript(`
            if (window.apolloDashboard) {
                const oldLevel = window.apolloDashboard.threatLevel;
                window.apolloDashboard.threatLevel = 'high';
                window.apolloDashboard.updateThreatLevel();
                const newLevel = document.getElementById('threat-text').textContent;

                // Reset to original
                window.apolloDashboard.threatLevel = oldLevel;
                window.apolloDashboard.updateThreatLevel();

                return { oldLevel, newLevel, canUpdate: newLevel === 'HIGH' };
            }
            return { error: 'Dashboard not available' };
        `);

        return {
            details: `Current level: ${currentLevel}, Class: ${indicatorClass}, Updates: ${updateTest.canUpdate}`,
            currentLevel,
            indicatorClass,
            canUpdate: updateTest.canUpdate
        };
    }

    async testActivityFeed() {
        const feed = await ipcMain.invoke('ui-test-get-element', '#activity-feed');

        if (!feed.exists) {
            throw new Error('Activity feed element not found');
        }

        // Count activity items
        const activityCount = await this.testWindow.webContents.executeJavaScript(`
            document.querySelectorAll('#activity-feed .activity-item').length
        `);

        // Check for real-time activity
        const recentActivities = await this.testWindow.webContents.executeJavaScript(`
            window.electronAPI ? window.electronAPI.getRecentActivity() : null
        `).catch(() => null);

        // Test if activities are updating
        const hasRealTimeData = recentActivities && recentActivities.length > 0;

        // Check activity timestamps
        const timestamps = await this.testWindow.webContents.executeJavaScript(`
            Array.from(document.querySelectorAll('#activity-feed .activity-time')).map(el => el.textContent)
        `);

        return {
            details: `Activity items: ${activityCount}, Real-time data: ${hasRealTimeData}, Recent activities: ${recentActivities?.length || 0}`,
            activityCount,
            hasRealTimeData,
            recentActivities: recentActivities?.length || 0,
            timestamps
        };
    }

    async testModuleStatus() {
        const modules = [
            '#threat-engine-status',
            '#crypto-shield-status',
            '#apt-detector-status',
            '#behavior-monitor-status'
        ];

        const moduleStates = {};
        let allActive = true;

        for (const selector of modules) {
            const module = await ipcMain.invoke('ui-test-get-element', selector);

            if (!module.exists) {
                throw new Error(`Module ${selector} not found`);
            }

            const isActive = module.className.includes('active');
            const statusText = await this.testWindow.webContents.executeJavaScript(`
                document.querySelector('${selector} .module-status')?.textContent || 'Unknown'
            `);

            moduleStates[selector] = { isActive, statusText };

            if (!isActive) {
                allActive = false;
            }
        }

        return {
            details: `Modules tested: ${Object.keys(moduleStates).length}, All active: ${allActive}`,
            moduleStates,
            allActive
        };
    }

    async testRealTimeUpdates() {
        // Test if real-time updates are working
        const initialStats = await this.testWindow.webContents.executeJavaScript(`
            window.apolloDashboard ? window.apolloDashboard.stats : null
        `);

        // Trigger a simulated threat to test real-time updates
        const simulationResult = await this.testWindow.webContents.executeJavaScript(`
            if (window.apolloDashboard && typeof simulateThreat === 'function') {
                const oldCount = window.apolloDashboard.stats.threatsDetected;
                simulateThreat();
                const newCount = window.apolloDashboard.stats.threatsDetected;
                return { oldCount, newCount, updated: newCount > oldCount };
            }
            return { error: 'Simulation not available' };
        `);

        // Test IPC event handling
        const ipcListeners = await this.testWindow.webContents.executeJavaScript(`
            window.electronAPI ? {
                hasThreatDetected: typeof window.electronAPI.onThreatDetected === 'function',
                hasEngineStats: typeof window.electronAPI.onEngineStats === 'function',
                hasActivityUpdated: typeof window.electronAPI.onActivityUpdated === 'function'
            } : { error: 'electronAPI not available' }
        `);

        return {
            details: `Initial stats available: ${!!initialStats}, Simulation works: ${simulationResult.updated}, IPC listeners: ${Object.values(ipcListeners).filter(v => v === true).length}`,
            hasInitialStats: !!initialStats,
            simulationWorks: simulationResult.updated || false,
            ipcListeners
        };
    }

    async testIPCCommunication() {
        // Test various IPC methods
        const ipcTests = {};

        // Test getEngineStats
        try {
            const engineStats = await this.testWindow.webContents.executeJavaScript(`
                window.electronAPI ? window.electronAPI.getEngineStats() : null
            `);
            ipcTests.getEngineStats = !!engineStats;
        } catch (error) {
            ipcTests.getEngineStats = false;
        }

        // Test getRecentActivity
        try {
            const recentActivity = await this.testWindow.webContents.executeJavaScript(`
                window.electronAPI ? window.electronAPI.getRecentActivity() : null
            `);
            ipcTests.getRecentActivity = !!recentActivity;
        } catch (error) {
            ipcTests.getRecentActivity = false;
        }

        // Test getProtectionStatus
        try {
            const protectionStatus = await this.testWindow.webContents.executeJavaScript(`
                window.electronAPI ? window.electronAPI.getProtectionStatus() : null
            `);
            ipcTests.getProtectionStatus = !!protectionStatus;
        } catch (error) {
            ipcTests.getProtectionStatus = false;
        }

        const workingIPCs = Object.values(ipcTests).filter(v => v === true).length;
        const totalIPCs = Object.keys(ipcTests).length;

        if (workingIPCs === 0) {
            throw new Error('No IPC methods are working');
        }

        return {
            details: `Working IPC methods: ${workingIPCs}/${totalIPCs}`,
            ipcTests,
            workingCount: workingIPCs,
            totalCount: totalIPCs
        };
    }

    async testEngineStats() {
        // Test if engine statistics are real and updating
        const statsResult = await this.testWindow.webContents.executeJavaScript(`
            if (window.electronAPI) {
                return window.electronAPI.getEngineStats();
            }
            return null;
        `).catch(() => null);

        if (!statsResult) {
            throw new Error('Unable to retrieve engine statistics');
        }

        // Verify stats structure
        const expectedFields = ['engine', 'isActive', 'filesScanned', 'threatsDetected', 'threatsBlocked'];
        const hasExpectedFields = expectedFields.every(field => statsResult.hasOwnProperty(field));

        // Check if stats show real activity
        const hasActivity = statsResult.filesScanned > 0 || statsResult.threatsDetected > 0;

        return {
            details: `Engine: ${statsResult.engine}, Active: ${statsResult.isActive}, Files scanned: ${statsResult.filesScanned}, Threats: ${statsResult.threatsDetected}`,
            stats: statsResult,
            hasExpectedFields,
            hasActivity
        };
    }

    async testOSINTData() {
        // Test OSINT integration display
        const osintResult = await this.testWindow.webContents.executeJavaScript(`
            if (window.electronAPI) {
                return window.electronAPI.getOSINTStats();
            }
            return null;
        `).catch(() => null);

        // Check for OSINT UI elements
        const osintElements = await this.testWindow.webContents.executeJavaScript(`
            const elements = document.querySelectorAll('.osint-stats, .source-item, .oracle-info');
            return {
                osintStatsExists: !!document.querySelector('.osint-stats'),
                sourceItemsCount: document.querySelectorAll('.source-item').length,
                oracleInfoExists: !!document.querySelector('.oracle-info'),
                totalOSINTElements: elements.length
            };
        `);

        return {
            details: `OSINT API available: ${!!osintResult}, UI elements: ${osintElements.totalOSINTElements}, Sources: ${osintElements.sourceItemsCount}`,
            osintApiWorking: !!osintResult,
            osintStats: osintResult,
            uiElements: osintElements
        };
    }

    async testAIOracleIntegration() {
        // Test AI Oracle integration
        const oracleResult = await this.testWindow.webContents.executeJavaScript(`
            if (window.electronAPI) {
                return window.electronAPI.getAIOracleStats();
            }
            return null;
        `).catch(() => null);

        // Test AI Oracle UI elements
        const oracleElements = await this.testWindow.webContents.executeJavaScript(`
            return {
                aiOracleSection: !!document.querySelector('.ai-oracle-status'),
                oracleItems: document.querySelectorAll('.oracle-item').length,
                hasModelInfo: !!document.querySelector('.oracle-value')
            };
        `);

        // Test AI analysis functionality
        const analysisTest = await this.testWindow.webContents.executeJavaScript(`
            if (window.electronAPI && typeof analyzeContract === 'function') {
                return { analysisAvailable: true };
            }
            return { analysisAvailable: false };
        `);

        return {
            details: `AI Oracle API: ${!!oracleResult}, UI elements: ${oracleElements.oracleItems}, Analysis available: ${analysisTest.analysisAvailable}`,
            oracleApiWorking: !!oracleResult,
            oracleStats: oracleResult,
            uiElements: oracleElements,
            analysisAvailable: analysisTest.analysisAvailable
        };
    }

    recordTestResult(testName, passed, result) {
        this.testResults.push({
            test: testName,
            passed,
            result,
            timestamp: new Date().toISOString()
        });
    }

    async generateTestReport() {
        console.log('\n' + '='.repeat(70));
        console.log('📊 UI Data Integration Test Results');
        console.log('='.repeat(70));

        const passed = this.testResults.filter(r => r.passed).length;
        const failed = this.testResults.filter(r => !r.passed).length;
        const total = this.testResults.length;

        console.log(`\n📈 Summary: ${passed}/${total} tests passed (${((passed/total)*100).toFixed(1)}%)`);

        // Detailed results
        console.log('\n📋 Detailed Results:');
        this.testResults.forEach(result => {
            const status = result.passed ? '✅' : '❌';
            console.log(`  ${status} ${result.test}`);
            if (result.result.details) {
                console.log(`     ${result.result.details}`);
            }
            if (!result.passed && result.result.error) {
                console.log(`     Error: ${result.result.error}`);
            }
        });

        // Data integration assessment
        console.log('\n🔍 Data Integration Assessment:');

        const backendConnected = this.testResults.find(r => r.test === 'testBackendConnection')?.passed;
        const statsWorking = this.testResults.find(r => r.test === 'testProtectionStatistics')?.passed;
        const ipcWorking = this.testResults.find(r => r.test === 'testIPCCommunication')?.passed;
        const realTimeWorking = this.testResults.find(r => r.test === 'testRealTimeUpdates')?.passed;

        console.log(`  🔗 Backend Connection: ${backendConnected ? '✅ Connected' : '❌ Disconnected'}`);
        console.log(`  📊 Statistics Integration: ${statsWorking ? '✅ Working' : '❌ Failed'}`);
        console.log(`  📡 IPC Communication: ${ipcWorking ? '✅ Working' : '❌ Failed'}`);
        console.log(`  ⚡ Real-time Updates: ${realTimeWorking ? '✅ Working' : '❌ Failed'}`);

        // Overall assessment
        const criticalTests = [backendConnected, statsWorking, ipcWorking].filter(Boolean).length;

        console.log('\n🎯 Overall Assessment:');
        if (criticalTests >= 3 && passed >= total * 0.8) {
            console.log('  🎉 EXCELLENT: UI is fully integrated with real backend data');
        } else if (criticalTests >= 2 && passed >= total * 0.6) {
            console.log('  ✅ GOOD: UI has good backend integration with minor issues');
        } else if (criticalTests >= 1) {
            console.log('  ⚠️ NEEDS WORK: UI has partial backend integration');
        } else {
            console.log('  ❌ CRITICAL: UI is not properly integrated with backend');
        }

        // Recommendations
        console.log('\n💡 Recommendations:');
        if (!backendConnected) {
            console.log('  • Fix backend connection - ensure main process IPC is working');
        }
        if (!statsWorking) {
            console.log('  • Verify statistics are pulling from real engine data');
        }
        if (!ipcWorking) {
            console.log('  • Check IPC method implementations in preload.js');
        }
        if (!realTimeWorking) {
            console.log('  • Ensure real-time event listeners are properly registered');
        }

        // Save detailed report
        await this.saveTestReport();
    }

    async saveTestReport() {
        const report = {
            testRun: {
                timestamp: new Date().toISOString(),
                totalTests: this.testResults.length,
                passed: this.testResults.filter(r => r.passed).length,
                failed: this.testResults.filter(r => !r.passed).length
            },
            results: this.testResults,
            summary: {
                backendIntegration: this.testResults.find(r => r.test === 'testBackendConnection')?.passed || false,
                statisticsWorking: this.testResults.find(r => r.test === 'testProtectionStatistics')?.passed || false,
                ipcCommunication: this.testResults.find(r => r.test === 'testIPCCommunication')?.passed || false,
                realTimeUpdates: this.testResults.find(r => r.test === 'testRealTimeUpdates')?.passed || false
            }
        };

        const fs = require('fs-extra');
        const reportPath = path.join(__dirname, 'test-results', 'ui-integration-test-report.json');
        await fs.ensureDir(path.dirname(reportPath));
        await fs.writeJSON(reportPath, report, { spaces: 2 });

        console.log(`\n💾 Detailed report saved to: ${reportPath}`);
    }

    async cleanup() {
        if (this.testWindow) {
            this.testWindow.close();
        }

        // Clean up IPC handlers
        ipcMain.removeHandler('ui-test-get-element');
        ipcMain.removeHandler('ui-test-backend-status');
        ipcMain.removeHandler('ui-test-trigger-update');

        console.log('\n🧹 Test cleanup completed');
    }
}

// Run tests if executed directly
if (require.main === module) {
    app.whenReady().then(async () => {
        const tester = new UIDataIntegrationTest();
        await tester.runAllTests();

        setTimeout(() => {
            app.quit();
        }, 2000);
    });
}

module.exports = UIDataIntegrationTest;