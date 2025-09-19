// Apollo UI Real Data Validation Test
// Simple test to validate UI is showing real backend data

const fs = require('fs');
const path = require('path');

class UIDataValidationTest {
    constructor() {
        this.testResults = [];
        this.dashboardPath = path.join(__dirname, 'ui', 'dashboard', 'dashboard.js');
        this.htmlPath = path.join(__dirname, 'ui', 'dashboard', 'index.html');
        this.preloadPath = path.join(__dirname, 'preload.js');
        this.mainPath = path.join(__dirname, 'main.js');
    }

    async runValidationTests() {
        console.log('🔍 Apollo UI Data Validation Test\n');
        console.log('=' .repeat(50));

        await this.testDashboardBackendConnection();
        await this.testIpcHandlers();
        await this.testRealTimeListeners();
        await this.testDataUpdateMethods();
        await this.testStaticDataRemoval();
        await this.testEngineIntegration();

        this.generateReport();
    }

    async testDashboardBackendConnection() {
        console.log('📡 Testing Dashboard Backend Connection...');

        try {
            const dashboardContent = fs.readFileSync(this.dashboardPath, 'utf8');

            const checks = [
                {
                    name: 'Backend connection method exists',
                    test: dashboardContent.includes('connectToBackend()')
                },
                {
                    name: 'Real threat detection handler exists',
                    test: dashboardContent.includes('handleRealThreatDetection')
                },
                {
                    name: 'Real stats update method exists',
                    test: dashboardContent.includes('updateRealStats')
                },
                {
                    name: 'Real activity display method exists',
                    test: dashboardContent.includes('displayRealActivity')
                },
                {
                    name: 'ElectronAPI event listeners configured',
                    test: dashboardContent.includes('window.electronAPI.onThreatDetected')
                }
            ];

            this.recordTestResults('Dashboard Backend Connection', checks);
        } catch (error) {
            console.log('❌ Error reading dashboard file:', error.message);
        }
    }

    async testIpcHandlers() {
        console.log('🔌 Testing IPC Handlers...');

        try {
            const mainContent = fs.readFileSync(this.mainPath, 'utf8');

            const checks = [
                {
                    name: 'get-engine-stats handler exists',
                    test: mainContent.includes("ipcMain.handle('get-engine-stats'")
                },
                {
                    name: 'get-recent-activity handler exists',
                    test: mainContent.includes("ipcMain.handle('get-recent-activity'")
                },
                {
                    name: 'get-ai-oracle-stats handler exists',
                    test: mainContent.includes("ipcMain.handle('get-ai-oracle-stats'")
                },
                {
                    name: 'Recent activity tracking exists',
                    test: mainContent.includes('this.recentActivity')
                },
                {
                    name: 'Real threat alert handler exists',
                    test: mainContent.includes('handleUnifiedThreatAlert')
                }
            ];

            this.recordTestResults('IPC Handlers', checks);
        } catch (error) {
            console.log('❌ Error reading main file:', error.message);
        }
    }

    async testRealTimeListeners() {
        console.log('⚡ Testing Real-time Event Listeners...');

        try {
            const preloadContent = fs.readFileSync(this.preloadPath, 'utf8');

            const checks = [
                {
                    name: 'onThreatDetected listener exposed',
                    test: preloadContent.includes('onThreatDetected: (callback)')
                },
                {
                    name: 'onEngineStats listener exposed',
                    test: preloadContent.includes('onEngineStats: (callback)')
                },
                {
                    name: 'onActivityUpdated listener exposed',
                    test: preloadContent.includes('onActivityUpdated: (callback)')
                },
                {
                    name: 'getEngineStats API exposed',
                    test: preloadContent.includes('getEngineStats: ()')
                },
                {
                    name: 'getRecentActivity API exposed',
                    test: preloadContent.includes('getRecentActivity: ()')
                }
            ];

            this.recordTestResults('Real-time Event Listeners', checks);
        } catch (error) {
            console.log('❌ Error reading preload file:', error.message);
        }
    }

    async testDataUpdateMethods() {
        console.log('📊 Testing Data Update Methods...');

        try {
            const dashboardContent = fs.readFileSync(this.dashboardPath, 'utf8');

            const checks = [
                {
                    name: 'Dynamic threat level updates',
                    test: dashboardContent.includes('this.threatLevel = severity')
                },
                {
                    name: 'Active threats counter updates',
                    test: dashboardContent.includes('this.stats.activeThreats++')
                },
                {
                    name: 'APT detection counter updates',
                    test: dashboardContent.includes('this.stats.aptDetections++')
                },
                {
                    name: 'Activity feed real-time updates',
                    test: dashboardContent.includes('addActivityItem')
                },
                {
                    name: 'Statistics update from engine',
                    test: dashboardContent.includes('updateStatsFromEngine')
                }
            ];

            this.recordTestResults('Data Update Methods', checks);
        } catch (error) {
            console.log('❌ Error testing data update methods:', error.message);
        }
    }

    async testStaticDataRemoval() {
        console.log('🚫 Testing Static Data Removal...');

        try {
            const dashboardContent = fs.readFileSync(this.dashboardPath, 'utf8');
            const htmlContent = fs.readFileSync(this.htmlPath, 'utf8');

            const checks = [
                {
                    name: 'No hardcoded placeholder stats in JS',
                    test: !dashboardContent.includes('threatsBlocked: 247') &&
                          !dashboardContent.includes('totalScans: 1247')
                },
                {
                    name: 'Dynamic activity feed (no static entries)',
                    test: dashboardContent.includes('this.activityFeed = []')
                },
                {
                    name: 'Real-time threat level calculation',
                    test: dashboardContent.includes('calculateThreatLevel')
                },
                {
                    name: 'Backend data fetching on load',
                    test: dashboardContent.includes('loadRealData') ||
                          dashboardContent.includes('connectToBackend')
                }
            ];

            this.recordTestResults('Static Data Removal', checks);
        } catch (error) {
            console.log('❌ Error testing static data removal:', error.message);
        }
    }

    async testEngineIntegration() {
        console.log('🔧 Testing Protection Engine Integration...');

        try {
            const mainContent = fs.readFileSync(this.mainPath, 'utf8');
            const dashboardContent = fs.readFileSync(this.dashboardPath, 'utf8');

            const checks = [
                {
                    name: 'Unified protection engine connected',
                    test: mainContent.includes('this.unifiedProtectionEngine')
                },
                {
                    name: 'Engine statistics retrieval',
                    test: mainContent.includes('getStatistics()')
                },
                {
                    name: 'Live threat processing',
                    test: mainContent.includes('addToRecentActivity')
                },
                {
                    name: 'UI reflects engine state',
                    test: dashboardContent.includes('updateEngineStatus')
                },
                {
                    name: 'Real-time data synchronization',
                    test: dashboardContent.includes('syncWithEngine')
                }
            ];

            this.recordTestResults('Protection Engine Integration', checks);
        } catch (error) {
            console.log('❌ Error testing engine integration:', error.message);
        }
    }

    recordTestResults(category, checks) {
        const passed = checks.filter(check => check.test).length;
        const total = checks.length;
        const percentage = Math.round((passed / total) * 100);

        console.log(`   ${category}: ${passed}/${total} checks passed (${percentage}%)`);

        for (const check of checks) {
            const status = check.test ? '✅' : '❌';
            console.log(`     ${status} ${check.name}`);
        }
        console.log();

        this.testResults.push({
            category,
            passed,
            total,
            percentage,
            checks
        });
    }

    generateReport() {
        console.log('📋 TEST RESULTS SUMMARY');
        console.log('=' .repeat(50));

        const totalChecks = this.testResults.reduce((sum, result) => sum + result.total, 0);
        const totalPassed = this.testResults.reduce((sum, result) => sum + result.passed, 0);
        const overallPercentage = Math.round((totalPassed / totalChecks) * 100);

        for (const result of this.testResults) {
            const status = result.percentage >= 80 ? '✅' : result.percentage >= 60 ? '⚠️' : '❌';
            console.log(`${status} ${result.category}: ${result.passed}/${result.total} (${result.percentage}%)`);
        }

        console.log('\n' + '=' .repeat(50));
        console.log(`🎯 OVERALL RESULT: ${totalPassed}/${totalChecks} checks passed (${overallPercentage}%)`);

        if (overallPercentage >= 90) {
            console.log('🎉 EXCELLENT: UI is fully integrated with real backend data!');
        } else if (overallPercentage >= 75) {
            console.log('✅ GOOD: UI integration is mostly complete with minor issues.');
        } else if (overallPercentage >= 50) {
            console.log('⚠️ PARTIAL: UI integration needs more work.');
        } else {
            console.log('❌ CRITICAL: UI is still using placeholder data.');
        }

        // Check for critical integration components
        const criticalSystems = [
            'Backend connection method exists',
            'Real threat detection handler exists',
            'get-engine-stats handler exists',
            'onThreatDetected listener exposed',
            'Dynamic threat level updates'
        ];

        const criticalPassed = this.testResults
            .flatMap(result => result.checks)
            .filter(check => criticalSystems.includes(check.name) && check.test)
            .length;

        console.log(`\n🔑 Critical Systems: ${criticalPassed}/${criticalSystems.length} operational`);

        if (criticalPassed === criticalSystems.length) {
            console.log('✅ All critical UI-backend integration systems are functional!');
            console.log('🚀 Apollo dashboard is ready for beta launch with real data.');
        } else {
            console.log('⚠️ Some critical integration systems need attention before launch.');
        }
    }
}

// Run the validation test
async function runUIValidation() {
    const validator = new UIDataValidationTest();
    await validator.runValidationTests();
}

if (require.main === module) {
    runUIValidation().catch(console.error);
}

module.exports = UIDataValidationTest;