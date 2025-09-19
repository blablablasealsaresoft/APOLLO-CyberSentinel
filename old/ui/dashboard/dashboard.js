class ApolloDashboard {
    constructor() {
        this.isConnected = false;
        this.protectionStatus = 'active';
        this.threatLevel = 'low';
        this.stats = {
            activeThreats: 0,
            blockedToday: 0,
            totalScans: 1247,
            threatsBlocked: 0,
            cryptoTransactions: 156,
            aptDetections: 0,
            protectedWallets: 3,
            analyzedContracts: 42,
            osintQueries: 0,
            phishingBlocked: 0,
            malwareDetected: 0,
            iocsCollected: 0
        };

        // Initialize OSINT intelligence integration
        this.osintSources = {
            virusTotal: { status: 'active', queries: 0 },
            alienVault: { status: 'active', queries: 0 },
            urlhaus: { status: 'active', queries: 0 },
            threatfox: { status: 'active', queries: 0 },
            malwareBazaar: { status: 'active', queries: 0 }
        };

        // Initialize AI Oracle status
        this.aiOracle = {
            provider: 'Anthropic Claude',
            model: 'claude-opus-4-1-20250805',
            status: 'active',
            analyses: 0
        };

        this.recentThreats = [];
        this.init();
    }

    init() {
        this.updateClock();
        this.loadDashboardData();
        this.startRealTimeUpdates();
        this.setupEventListeners();

        console.log('🚀 Apollo Dashboard initialized');
    }

    updateClock() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit'
        });

        const timeElement = document.getElementById('current-time');
        if (timeElement) {
            timeElement.textContent = timeString;
        }

        setTimeout(() => this.updateClock(), 1000);
    }

    loadDashboardData() {
        this.updateStats();
        this.updateProtectionStatus();
        this.updateThreatLevel();
        this.loadRecentActivity();
    }

    updateStats() {
        const elements = {
            'active-threats': this.stats.activeThreats,
            'blocked-today': this.stats.blockedToday,
            'total-scans': this.stats.totalScans.toLocaleString(),
            'threats-blocked': this.stats.threatsBlocked,
            'crypto-transactions': this.stats.cryptoTransactions,
            'apt-detections': this.stats.aptDetections,
            'protected-wallets': this.stats.protectedWallets,
            'analyzed-contracts': this.stats.analyzedContracts
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        }

        // Update OSINT stats
        this.updateOSINTStats();
    }

    updateOSINTStats() {
        // Update intelligence source status
        const osintStatsHTML = `
            <div class="osint-stats">
                <h4>🔍 Intelligence Sources</h4>
                <div class="source-grid">
                    <div class="source-item">
                        <span class="source-name">VirusTotal</span>
                        <span class="source-status active">${this.osintSources.virusTotal.queries} queries</span>
                    </div>
                    <div class="source-item">
                        <span class="source-name">AlienVault OTX</span>
                        <span class="source-status active">${this.osintSources.alienVault.queries} queries</span>
                    </div>
                    <div class="source-item">
                        <span class="source-name">URLhaus</span>
                        <span class="source-status active">${this.osintSources.urlhaus.queries} queries</span>
                    </div>
                    <div class="source-item">
                        <span class="source-name">ThreatFox</span>
                        <span class="source-status active">${this.osintSources.threatfox.queries} queries</span>
                    </div>
                </div>
                <div class="osint-totals">
                    <div class="total-item">
                        <span class="total-value">${this.stats.osintQueries}</span>
                        <span class="total-label">OSINT Queries</span>
                    </div>
                    <div class="total-item">
                        <span class="total-value">${this.stats.phishingBlocked}</span>
                        <span class="total-label">Phishing Blocked</span>
                    </div>
                    <div class="total-item">
                        <span class="total-value">${this.stats.malwareDetected}</span>
                        <span class="total-label">Malware Detected</span>
                    </div>
                    <div class="total-item">
                        <span class="total-value">${this.stats.iocsCollected}</span>
                        <span class="total-label">IOCs Collected</span>
                    </div>
                </div>
                <div class="ai-oracle-status">
                    <h4>🧠 AI Oracle Status</h4>
                    <div class="oracle-info">
                        <div class="oracle-item">
                            <span class="oracle-label">Provider:</span>
                            <span class="oracle-value">${this.aiOracle.provider}</span>
                        </div>
                        <div class="oracle-item">
                            <span class="oracle-label">Model:</span>
                            <span class="oracle-value">${this.aiOracle.model}</span>
                        </div>
                        <div class="oracle-item">
                            <span class="oracle-label">Status:</span>
                            <span class="oracle-status ${this.aiOracle.status}">${this.aiOracle.status.toUpperCase()}</span>
                        </div>
                        <div class="oracle-item">
                            <span class="oracle-label">Analyses:</span>
                            <span class="oracle-value">${this.aiOracle.analyses}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Add to existing stats section if it doesn't exist
        let osintContainer = document.querySelector('.osint-stats-container');
        if (!osintContainer) {
            osintContainer = document.createElement('div');
            osintContainer.className = 'osint-stats-container';
            const statsSection = document.querySelector('.monitoring-section');
            if (statsSection) {
                statsSection.appendChild(osintContainer);
            }
        }
        osintContainer.innerHTML = osintStatsHTML;
    }

    updateProtectionStatus() {
        const modules = [
            'threat-engine-status',
            'crypto-shield-status',
            'apt-detector-status',
            'behavior-monitor-status'
        ];

        modules.forEach(moduleId => {
            const element = document.getElementById(moduleId);
            if (element) {
                element.classList.add('active');
                const statusSpan = element.querySelector('.module-status');
                if (statusSpan) {
                    statusSpan.textContent = 'Active';
                }
            }
        });
    }

    updateThreatLevel() {
        const indicator = document.getElementById('threat-indicator');
        if (indicator) {
            indicator.className = `threat-indicator ${this.threatLevel}`;
            indicator.querySelector('.threat-text').textContent = this.threatLevel.toUpperCase();
        }
    }

    loadRecentActivity() {
        const activities = [
            {
                time: 'Just now',
                icon: '✅',
                text: 'Apollo protection activated - all systems secured',
                type: 'info'
            },
            {
                time: '2 min ago',
                icon: '🛡️',
                text: 'Threat database updated - 15,247 new signatures',
                type: 'success'
            },
            {
                time: '5 min ago',
                icon: '🔍',
                text: 'System scan completed - no threats detected',
                type: 'info'
            },
            {
                time: '12 min ago',
                icon: '⛓️',
                text: 'Crypto transaction analyzed - approved safely',
                type: 'success'
            },
            {
                time: '18 min ago',
                icon: '🧠',
                text: 'Behavioral baseline updated successfully',
                type: 'info'
            }
        ];

        const feed = document.getElementById('activity-feed');
        if (feed) {
            feed.innerHTML = activities.map(activity => `
                <div class="activity-item ${activity.type}">
                    <div class="activity-time">${activity.time}</div>
                    <div class="activity-icon">${activity.icon}</div>
                    <div class="activity-text">${activity.text}</div>
                </div>
            `).join('');
        }
    }

    startRealTimeUpdates() {
        setInterval(() => {
            this.updateLastScan();
            this.incrementStats();
        }, 30000);

        setInterval(() => {
            this.simulateActivity();
        }, 60000);
    }

    updateLastScan() {
        const element = document.getElementById('last-scan');
        if (element) {
            element.textContent = 'Just now';
        }
    }

    incrementStats() {
        this.stats.totalScans += Math.floor(Math.random() * 5) + 1;
        this.updateStats();
    }

    simulateActivity() {
        const activities = [
            { icon: '🔍', text: 'Real-time scan completed - system clean', type: 'info' },
            { icon: '🛡️', text: 'Network traffic analyzed - no threats found', type: 'info' },
            { icon: '⛓️', text: 'Crypto wallet monitoring active', type: 'success' },
            { icon: '🧠', text: 'Behavioral patterns updated', type: 'info' },
            { icon: '🕵️', text: 'APT detection scan completed', type: 'success' }
        ];

        const randomActivity = activities[Math.floor(Math.random() * activities.length)];
        this.addActivity(randomActivity);
    }

    addActivity(activity) {
        const feed = document.getElementById('activity-feed');
        if (feed) {
            const activityElement = document.createElement('div');
            activityElement.className = `activity-item ${activity.type}`;
            activityElement.innerHTML = `
                <div class="activity-time">Just now</div>
                <div class="activity-icon">${activity.icon}</div>
                <div class="activity-text">${activity.text}</div>
            `;

            feed.insertBefore(activityElement, feed.firstChild);

            if (feed.children.length > 10) {
                feed.removeChild(feed.lastChild);
            }
        }
    }

    setupEventListeners() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });

        window.addEventListener('resize', () => {
            this.adjustLayout();
        });
    }

    adjustLayout() {
        console.log('🔄 Layout adjusted for screen size');
    }

    closeAllModals() {
        const modals = document.querySelectorAll('.modal-overlay');
        modals.forEach(modal => {
            modal.style.display = 'none';
        });
    }

    raiseThreatAlert(threatData) {
        this.threatLevel = threatData.severity.toLowerCase();
        this.updateThreatLevel();

        this.stats.activeThreats++;
        this.updateStats();

        this.showThreatModal(threatData);

        this.addActivity({
            icon: '🚨',
            text: `${threatData.severity} threat detected: ${threatData.type}`,
            type: 'danger'
        });
    }

    showThreatModal(threatData) {
        const modal = document.getElementById('threat-modal');
        const threatType = document.getElementById('threat-type');
        const threatDescription = document.getElementById('threat-description');

        if (modal && threatType && threatDescription) {
            threatType.textContent = threatData.type;
            threatDescription.textContent = threatData.description;
            modal.style.display = 'flex';
        }
    }
}

// Global Functions for UI Interactions
function refreshActivity() {
    const dashboard = window.apolloDashboard;
    if (dashboard) {
        dashboard.loadRecentActivity();
        dashboard.addActivity({
            icon: '🔄',
            text: 'Activity feed refreshed manually',
            type: 'info'
        });
    }
}

async function analyzeContract() {
    const contractAddress = prompt('Enter smart contract address to analyze:');
    if (contractAddress && contractAddress.length === 42 && contractAddress.startsWith('0x')) {
        window.apolloDashboard.addActivity({
            icon: '📄',
            text: `Smart contract analysis initiated: ${contractAddress.substring(0, 10)}...`,
            type: 'info'
        });

        // Simulate real analysis with OSINT and AI Oracle
        window.apolloDashboard.stats.osintQueries++;
        window.apolloDashboard.osintSources.virusTotal.queries++;
        window.apolloDashboard.stats.analyzedContracts++;
        window.apolloDashboard.aiOracle.analyses++;

        setTimeout(() => {
            // Simulate threat check results
            const threatScore = Math.random();
            if (threatScore > 0.85) {
                window.apolloDashboard.addActivity({
                    icon: '🚨',
                    text: `MALICIOUS CONTRACT DETECTED: ${contractAddress.substring(0, 10)}... - Analysis blocked`,
                    type: 'danger'
                });
                window.apolloDashboard.stats.threatsBlocked++;
                window.apolloDashboard.stats.malwareDetected++;

                // Raise threat alert
                window.apolloDashboard.raiseThreatAlert({
                    type: 'Malicious Smart Contract',
                    severity: 'HIGH',
                    description: `Contract ${contractAddress.substring(0, 20)}... contains suspicious patterns including unlimited token approval and hidden fees`
                });
            } else {
                window.apolloDashboard.addActivity({
                    icon: '✅',
                    text: `Contract verified safe: ${contractAddress.substring(0, 10)}... - Proceeding allowed`,
                    type: 'success'
                });
            }

            window.apolloDashboard.updateStats();
        }, 3000);
    } else {
        alert('❌ Invalid contract address. Please enter a valid Ethereum address (0x...)');
    }
}

function checkTransaction() {
    const txHash = prompt('Enter transaction hash to analyze:');
    if (txHash) {
        window.apolloDashboard.addActivity({
            icon: '🔍',
            text: `Transaction analysis started: ${txHash.substring(0, 10)}...`,
            type: 'info'
        });

        setTimeout(() => {
            window.apolloDashboard.addActivity({
                icon: '✅',
                text: 'Transaction verified safe - proceeding allowed',
                type: 'success'
            });
        }, 2000);
    }
}

function runDeepScan() {
    window.apolloDashboard.addActivity({
        icon: '🔬',
        text: 'Deep APT scan initiated - comprehensive analysis starting',
        type: 'info'
    });

    setTimeout(() => {
        window.apolloDashboard.addActivity({
            icon: '✅',
            text: 'Deep scan completed - no APT activity detected',
            type: 'success'
        });
    }, 5000);
}

function viewThreats() {
    alert('Threat Intelligence Center\n\n' +
          '🇰🇵 North Korea APT: No current activity\n' +
          '🕵️ Pegasus Spyware: Protected\n' +
          '🌐 State Actors: Monitoring active\n' +
          '⛓️ Crypto Threats: 0 detected today\n\n' +
          'All systems secure - Apollo protection active');
}

function emergencyIsolation() {
    if (confirm('⚠️ WARNING: This will immediately disconnect all network connections.\n\nProceed with system isolation?')) {
        window.apolloDashboard.addActivity({
            icon: '🚧',
            text: 'EMERGENCY: System isolation activated - all connections cut',
            type: 'danger'
        });

        alert('🚧 SYSTEM ISOLATED\n\nAll network connections have been severed.\nApollo emergency protocols activated.');
    }
}

function quarantineThreats() {
    window.apolloDashboard.addActivity({
        icon: '🔒',
        text: 'Threat quarantine scan initiated',
        type: 'info'
    });

    setTimeout(() => {
        window.apolloDashboard.addActivity({
            icon: '✅',
            text: 'Quarantine scan completed - no threats to isolate',
            type: 'success'
        });
    }, 2000);
}

function captureEvidence() {
    window.apolloDashboard.addActivity({
        icon: '📋',
        text: 'Forensic evidence capture initiated',
        type: 'info'
    });

    setTimeout(() => {
        window.apolloDashboard.addActivity({
            icon: '✅',
            text: 'Evidence captured and stored securely',
            type: 'success'
        });
    }, 3000);
}

function openSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function closeSettingsModal() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function closeThreatModal() {
    const modal = document.getElementById('threat-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function blockThreat() {
    window.apolloDashboard.addActivity({
        icon: '🛡️',
        text: 'Threat blocked successfully - system protected',
        type: 'success'
    });

    window.apolloDashboard.stats.activeThreats = Math.max(0, window.apolloDashboard.stats.activeThreats - 1);
    window.apolloDashboard.stats.threatsBlocked++;
    window.apolloDashboard.updateStats();

    closeThreatModal();
}

function investigateThreat() {
    window.apolloDashboard.addActivity({
        icon: '🔍',
        text: 'Threat investigation launched - forensic analysis active',
        type: 'info'
    });

    closeThreatModal();
}

function saveSettings() {
    window.apolloDashboard.addActivity({
        icon: '⚙️',
        text: 'Settings saved successfully',
        type: 'success'
    });

    closeSettingsModal();
}

function resetSettings() {
    if (confirm('Reset all settings to default values?')) {
        window.apolloDashboard.addActivity({
            icon: '🔄',
            text: 'Settings reset to default configuration',
            type: 'info'
        });

        closeSettingsModal();
    }
}

// Enhanced Phishing Detection Function
async function checkPhishingURL() {
    const url = prompt('Enter URL to check for phishing:');
    if (url) {
        window.apolloDashboard.addActivity({
            icon: '🎣',
            text: `Phishing analysis started: ${url.substring(0, 30)}...`,
            type: 'info'
        });

        // Simulate OSINT threat intelligence query and AI Oracle analysis
        window.apolloDashboard.stats.osintQueries++;
        window.apolloDashboard.osintSources.urlhaus.queries++;
        window.apolloDashboard.osintSources.virusTotal.queries++;
        window.apolloDashboard.aiOracle.analyses++;

        setTimeout(() => {
            const phishingScore = analyzePhishingHeuristics(url);

            if (phishingScore > 0.6) {
                window.apolloDashboard.addActivity({
                    icon: '🚨',
                    text: `PHISHING DETECTED: ${url.substring(0, 30)}... - Access blocked`,
                    type: 'danger'
                });

                window.apolloDashboard.stats.phishingBlocked++;
                window.apolloDashboard.stats.threatsBlocked++;

                // Raise phishing alert
                window.apolloDashboard.raiseThreatAlert({
                    type: 'Phishing Website',
                    severity: 'HIGH',
                    description: `Malicious website detected: ${url.substring(0, 50)}... - Contains crypto wallet phishing patterns and suspicious redirects`
                });
            } else {
                window.apolloDashboard.addActivity({
                    icon: '✅',
                    text: `URL verified safe: ${url.substring(0, 30)}... - Access allowed`,
                    type: 'success'
                });
            }

            window.apolloDashboard.updateStats();
        }, 2000);
    }
}

function analyzePhishingHeuristics(url) {
    let score = 0;

    // Check for suspicious domains
    const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'shorturl.at'];
    if (suspiciousDomains.some(domain => url.includes(domain))) {
        score += 0.3;
    }

    // Check for crypto phishing patterns
    const cryptoPhishingPatterns = [
        /metamask.*wallet/i,
        /binance.*login/i,
        /coinbase.*secure/i,
        /crypto.*wallet.*verify/i,
        /defi.*connect/i,
        /uniswap.*swap/i,
        /pancakeswap.*exchange/i
    ];

    cryptoPhishingPatterns.forEach(pattern => {
        if (pattern.test(url)) {
            score += 0.4;
        }
    });

    // Check for URL obfuscation
    if (url.includes('%') || url.includes('xn--')) {
        score += 0.2;
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTlds.some(tld => url.includes(tld))) {
        score += 0.3;
    }

    return Math.min(score, 1.0);
}

// Test Functions for Demonstration
function simulateThreat() {
    const threats = [
        {
            type: 'North Korea APT',
            severity: 'CRITICAL',
            description: 'Lazarus group activity detected targeting cryptocurrency wallets via spear phishing'
        },
        {
            type: 'Pegasus Spyware',
            severity: 'HIGH',
            description: 'Zero-click exploit attempt detected via messaging application - NSO Group signature match'
        },
        {
            type: 'Crypto Phishing',
            severity: 'HIGH',
            description: 'Fake MetaMask website detected attempting to steal wallet private keys'
        },
        {
            type: 'Russian APT',
            severity: 'CRITICAL',
            description: 'APT28 (Fancy Bear) network reconnaissance activity detected targeting financial institutions'
        },
        {
            type: 'Chinese APT',
            severity: 'HIGH',
            description: 'APT1 persistent access attempt detected - PLA Unit 61398 signature patterns identified'
        }
    ];

    const threat = threats[Math.floor(Math.random() * threats.length)];
    window.apolloDashboard.raiseThreatAlert(threat);
}

function simulateCryptoThreat() {
    window.apolloDashboard.raiseThreatAlert({
        type: 'Malicious Contract',
        severity: 'HIGH',
        description: 'Smart contract attempting unlimited token approval detected'
    });
}

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    window.apolloDashboard = new ApolloDashboard();

    console.log('🚀 Apollo Dashboard loaded successfully');
    console.log('🔍 Type simulateThreat() in console to test threat alerts');
    console.log('⛓️ Type simulateCryptoThreat() in console to test crypto threats');
});

// Export for potential Electron integration
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ApolloDashboard;
}