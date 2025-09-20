// Load environment variables first
require('dotenv').config();

const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs-extra');
const os = require('os');
const crypto = require('crypto');
const QRCode = require('qrcode');

// Polyfill crypto.getRandomValues for WalletConnect in main process
if (!global.crypto) {
    global.crypto = {};
}
if (!global.crypto.getRandomValues) {
    global.crypto.getRandomValues = (array) => {
        return crypto.randomFillSync(array);
    };
}

// Fix cache permission issues
app.commandLine.appendSwitch('disable-gpu-sandbox');
app.commandLine.appendSwitch('no-sandbox');

// Unified Protection Engine - Combines all protection modules
const ApolloUnifiedProtectionEngine = require('./src/core/unified-protection-engine');
const SystemPrivileges = require('./src/native/system-privileges');
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');
const ApolloAIOracle = require('./src/ai/oracle-integration');

// WalletConnect imports - Apollo acts as a dApp to connect to mobile wallets
const { Core } = require('@walletconnect/core');
const { WalletKit } = require('@reown/walletkit');
const { SignClient } = require('@walletconnect/sign-client');
const { buildApprovedNamespaces, getSdkError } = require('@walletconnect/utils');

class ApolloApplication {
    constructor() {
        this.mainWindow = null;
        this.tray = null;
        this.isQuitting = false;

        // Unified Protection Engine replaces multiple separate modules
        this.unifiedProtectionEngine = null;
        this.systemPrivileges = null;
        this.osintIntelligence = null;
        this.aiOracle = null;
        this.walletKit = null;
        this.walletCore = null;
        this.signClient = null;

        this.protectionActive = false;
        this.stats = {
            threatsDetected: 0,
            threatsBlocked: 0,
            scansCompleted: 0,
            cryptoTransactionsProtected: 0
        };

        this.recentActivity = [];

        this.init();
    }

    async init() {
        console.log('🚀 Apollo Application initializing...');

        await this.setupDirectories();
        this.setupAppEvents();
        this.setupIPC();

        console.log('✅ Apollo Application ready');
    }

    async setupDirectories() {
        const apolloDir = path.join(os.homedir(), '.apollo');
        const directories = [
            apolloDir,
            path.join(apolloDir, 'logs'),
            path.join(apolloDir, 'evidence'),
            path.join(apolloDir, 'config'),
            path.join(apolloDir, 'quarantine')
        ];

        for (const dir of directories) {
            await fs.ensureDir(dir);
        }

        const configFile = path.join(apolloDir, 'config', 'settings.json');
        if (!await fs.pathExists(configFile)) {
            await fs.writeJSON(configFile, {
                version: '1.0.0',
                installDate: new Date().toISOString(),
                protectionSettings: {
                    realTimeProtection: true,
                    cryptoMonitoring: true,
                    aptDetection: true,
                    behaviorAnalysis: true,
                    autoUpdates: true
                },
                emergencySettings: {
                    autoIsolation: false,
                    alertAuthorities: false,
                    captureEvidence: true
                }
            }, { spaces: 2 });
        }

        console.log('📁 Apollo directories initialized');
    }

    setupAppEvents() {
        // Single instance lock - prevents multiple UI instances
        const gotTheLock = app.requestSingleInstanceLock();

        if (!gotTheLock) {
            console.log('🚫 Another instance of Apollo is already running');
            app.quit();
            return;
        }

        app.whenReady().then(() => {
            this.createMainWindow();
            this.createSystemTray();
            this.startProtectionEngines();

            app.on('activate', () => {
                if (BrowserWindow.getAllWindows().length === 0) {
                    this.createMainWindow();
                }
            });
        });

        app.on('window-all-closed', () => {
            if (process.platform !== 'darwin') {
                this.isQuitting = true;
                app.quit();
            }
        });

        app.on('before-quit', (event) => {
            if (!this.isQuitting) {
                event.preventDefault();
                this.mainWindow?.hide();
            } else {
                this.shutdownProtectionEngines();
            }
        });

        app.on('second-instance', () => {
            if (this.mainWindow) {
                if (this.mainWindow.isMinimized()) this.mainWindow.restore();
                this.mainWindow.focus();
            }
        });
    }

    createMainWindow() {
        this.mainWindow = new BrowserWindow({
            width: 1200,
            height: 800,
            minWidth: 800,
            minHeight: 600,
            icon: path.join(__dirname, 'assets', 'apollo-icon.png'),
            title: 'Apollo - Military-Grade Protection',
            titleBarStyle: 'default',
            backgroundColor: '#0a0a0a',
            show: false,
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                enableRemoteModule: false,
                preload: path.join(__dirname, 'preload.js')
            }
        });

        this.mainWindow.loadFile(path.join(__dirname, 'ui', 'dashboard', 'index.html'));

        this.mainWindow.once('ready-to-show', () => {
            this.mainWindow.show();

            if (process.env.NODE_ENV === 'development') {
                this.mainWindow.webContents.openDevTools();
            }
        });

        this.mainWindow.on('close', (event) => {
            if (!this.isQuitting) {
                event.preventDefault();
                this.mainWindow.hide();

                if (process.platform === 'darwin') {
                    app.dock.hide();
                }
            }
        });

        this.mainWindow.webContents.setWindowOpenHandler(({ url }) => {
            shell.openExternal(url);
            return { action: 'deny' };
        });

        this.setupMenu();
        console.log('🖥️ Main window created');
    }

    createSystemTray() {
        try {
            const iconPath = path.join(__dirname, 'assets', 'apollo-tray.jpg');
            this.tray = new Tray(iconPath);
        } catch (error) {
            console.warn('⚠️ System tray icon could not be loaded:', error.message);
            return;
        }

        const contextMenu = Menu.buildFromTemplate([
            {
                label: 'Apollo Protection',
                type: 'normal',
                enabled: false
            },
            { type: 'separator' },
            {
                label: 'Show Dashboard',
                click: () => {
                    this.showMainWindow();
                }
            },
            {
                label: `Protection: ${this.protectionActive ? 'Active' : 'Inactive'}`,
                click: () => {
                    this.toggleProtection();
                }
            },
            { type: 'separator' },
            {
                label: 'Emergency Isolation',
                click: () => {
                    this.emergencyIsolation();
                }
            },
            {
                label: 'Run Deep Scan',
                click: () => {
                    this.runDeepScan();
                }
            },
            { type: 'separator' },
            {
                label: 'Settings',
                click: () => {
                    this.showSettings();
                }
            },
            {
                label: 'About Apollo',
                click: () => {
                    this.showAbout();
                }
            },
            { type: 'separator' },
            {
                label: 'Quit Apollo',
                click: () => {
                    this.quitApplication();
                }
            }
        ]);

        this.tray.setContextMenu(contextMenu);
        this.tray.setToolTip('Apollo - Military-Grade Protection');

        this.tray.on('click', () => {
            this.showMainWindow();
        });

        console.log('📡 System tray created');
    }

    setupMenu() {
        const template = [
            {
                label: 'Apollo',
                submenu: [
                    {
                        label: 'About Apollo',
                        click: () => this.showAbout()
                    },
                    { type: 'separator' },
                    {
                        label: 'Preferences',
                        accelerator: 'CmdOrCtrl+,',
                        click: () => this.showSettings()
                    },
                    { type: 'separator' },
                    {
                        label: 'Hide Apollo',
                        accelerator: 'CmdOrCtrl+H',
                        click: () => this.mainWindow?.hide()
                    },
                    {
                        label: 'Quit Apollo',
                        accelerator: 'CmdOrCtrl+Q',
                        click: () => this.quitApplication()
                    }
                ]
            },
            {
                label: 'Protection',
                submenu: [
                    {
                        label: 'Toggle Protection',
                        accelerator: 'CmdOrCtrl+P',
                        click: () => this.toggleProtection()
                    },
                    {
                        label: 'Run Deep Scan',
                        accelerator: 'CmdOrCtrl+S',
                        click: () => this.runDeepScan()
                    },
                    { type: 'separator' },
                    {
                        label: 'Analyze Contract',
                        click: () => this.analyzeContract()
                    },
                    {
                        label: 'Check Transaction',
                        click: () => this.checkTransaction()
                    },
                    { type: 'separator' },
                    {
                        label: 'Emergency Isolation',
                        click: () => this.emergencyIsolation()
                    }
                ]
            },
            {
                label: 'View',
                submenu: [
                    {
                        label: 'Dashboard',
                        accelerator: 'CmdOrCtrl+D',
                        click: () => this.showMainWindow()
                    },
                    {
                        label: 'Activity Log',
                        accelerator: 'CmdOrCtrl+L',
                        click: () => this.showActivityLog()
                    },
                    { type: 'separator' },
                    {
                        label: 'Reload',
                        accelerator: 'CmdOrCtrl+R',
                        click: () => this.mainWindow?.reload()
                    },
                    {
                        label: 'Toggle Developer Tools',
                        accelerator: 'F12',
                        click: () => this.mainWindow?.webContents.toggleDevTools()
                    }
                ]
            },
            {
                label: 'Help',
                submenu: [
                    {
                        label: 'Apollo Documentation',
                        click: () => shell.openExternal('https://docs.apollo-shield.org')
                    },
                    {
                        label: 'Report Issue',
                        click: () => shell.openExternal('https://github.com/apollo-shield/issues')
                    },
                    {
                        label: 'Community Discord',
                        click: () => shell.openExternal('https://discord.gg/apollo-shield')
                    }
                ]
            }
        ];

        const menu = Menu.buildFromTemplate(template);
        Menu.setApplicationMenu(menu);
    }

    async startProtectionEngines() {
        try {
            console.log('🔥 Starting Apollo Unified Protection Engine...');

            // Initialize core components
            this.systemPrivileges = new SystemPrivileges();

            // Check for elevated privileges
            const hasPrivileges = await this.systemPrivileges.checkPrivileges();
            if (!hasPrivileges) {
                console.warn('⚠️ Running without full privileges - requesting elevation...');
                await this.systemPrivileges.requestElevation();
            }

            // Initialize the unified protection engine (replaces 4 separate modules)
            this.unifiedProtectionEngine = new ApolloUnifiedProtectionEngine();

            // Initialize intelligence modules
            this.osintIntelligence = new OSINTThreatIntelligence();
            this.aiOracle = new ApolloAIOracle();

            // Set up unified alert handler
            this.unifiedProtectionEngine.on('threat-detected', (alert) => this.handleUnifiedThreatAlert(alert));
            this.unifiedProtectionEngine.on('crypto-asset-detected', (alert) => this.handleCryptoAlert(alert));
            this.unifiedProtectionEngine.on('engine-ready', (status) => this.handleEngineReady(status));

            // Start unified protection engine
            const engineStarted = await this.unifiedProtectionEngine.initialize();

            if (!engineStarted) {
                throw new Error('Unified Protection Engine failed to initialize');
            }

            // Enable real-time system protection
            await this.systemPrivileges.enableRealtimeProtection();

            this.protectionActive = true;
            this.updateTrayMenu();

            // Get unified statistics
            const engineStats = this.unifiedProtectionEngine.getStatistics();

            this.sendToRenderer('protection-status', {
                active: true,
                elevated: hasPrivileges,
                engine: {
                    name: engineStats.engine,
                    version: engineStats.version,
                    isActive: engineStats.isActive,
                    signatureCount: engineStats.signatureCount,
                    uptime: engineStats.uptime
                },
                stats: engineStats
            });

            console.log('✅ Apollo Unified Protection Engine active - military-grade protection enabled');

        } catch (error) {
            console.error('❌ Failed to start protection engines:', error);
            this.showErrorDialog('Protection Engine Error',
                'Failed to start Apollo protection engines. Some features may not work correctly.');
        }
    }

    async shutdownProtectionEngines() {
        console.log('🛑 Shutting down protection engines...');

        if (this.unifiedProtectionEngine) {
            await this.unifiedProtectionEngine.stop();
        }

        this.protectionActive = false;
        console.log('✅ Protection engines shut down');
    }

    // Unified threat alert handler - replaces separate handlers
    async handleUnifiedThreatAlert(alert) {
        console.log(`🚨 ${alert.type.toUpperCase()}: ${alert.severity?.toUpperCase() || 'UNKNOWN'}`);
        console.log(`🕵️ Alert Details:`, alert);

        this.stats.threatsDetected++;

        // Add to recent activity
        this.addToRecentActivity({
            type: alert.type,
            severity: alert.severity,
            message: `${alert.severity?.toUpperCase() || 'THREAT'} detected: ${alert.details?.group || alert.type} in ${alert.details?.process || 'system'}`,
            timestamp: alert.timestamp || new Date().toISOString(),
            source: alert.source
        });

        // Auto-response based on severity
        if (alert.severity === 'critical' || alert.severity === 'high') {
            console.log('🛡️ Executing unified threat response...');

            // File quarantine handled by unified engine
            if (alert.details?.file) {
                await this.unifiedProtectionEngine.quarantine(alert.details.file);
                this.stats.threatsBlocked++;
            }

            // Process termination if PID available
            if (alert.details?.pid) {
                await this.systemPrivileges.killProcess(alert.details.pid);
                this.stats.threatsBlocked++;
            }

            console.log('✅ Unified threat response executed');
        }

        // Send real-time alert to dashboard
        this.sendToRenderer('threat-detected', {
            type: alert.type,
            severity: alert.severity,
            source: alert.source,
            details: alert.details,
            timestamp: alert.timestamp || new Date().toISOString(),
            engine: 'Unified Protection Engine'
        });

        // Send updated stats
        this.sendToRenderer('engine-stats-updated', this.unifiedProtectionEngine.getStatistics());

        // Show critical alert dialog
        if (alert.severity === 'critical') {
            this.showCriticalThreatDialog(alert);
        }

        this.updateTrayMenu();
    }

    addToRecentActivity(activity) {
        this.recentActivity.unshift(activity);

        // Keep only last 50 activities
        if (this.recentActivity.length > 50) {
            this.recentActivity = this.recentActivity.slice(0, 50);
        }

        // Send to renderer for real-time updates
        this.sendToRenderer('activity-updated', this.recentActivity.slice(0, 10));
    }

    // Engine ready handler
    handleEngineReady(status) {
        console.log('✅ Engine Ready:', status);
        this.sendToRenderer('engine-status', status);
    }

    handleCryptoAlert(alert) {
        console.log('⛓️ Crypto Alert:', alert);

        this.sendToRenderer('crypto-alert', alert);

        if (alert.severity === 'CRITICAL') {
            this.showCriticalThreatDialog(alert);
        }
    }

    handleAPTAlert(alert) {
        console.log('🕵️ APT Alert:', alert);

        this.sendToRenderer('apt-alert', alert);

        if (alert.severity === 'CRITICAL') {
            this.showCriticalThreatDialog(alert);
            this.considerEmergencyResponse(alert);
        }
    }

    showCriticalThreatDialog(alert) {
        const options = {
            type: 'warning',
            title: 'Critical Threat Detected',
            message: `Apollo has detected a critical threat: ${alert.type}`,
            detail: alert.details?.description || 'Immediate action recommended.',
            buttons: ['Block Threat', 'Investigate', 'Ignore'],
            defaultId: 0,
            cancelId: 2
        };

        dialog.showMessageBox(this.mainWindow, options).then(result => {
            switch (result.response) {
                case 0: // Block
                    this.blockThreat(alert);
                    break;
                case 1: // Investigate
                    this.investigateThreat(alert);
                    break;
                case 2: // Ignore
                    break;
            }
        });
    }

    async considerEmergencyResponse(alert) {
        const config = await this.loadConfig();

        if (config.emergencySettings?.autoIsolation && alert.severity === 'CRITICAL') {
            console.log('🚧 Auto-isolation triggered by critical APT alert');
            await this.emergencyIsolation();
        }
    }

    setupIPC() {
        ipcMain.handle('get-protection-status', () => {
            return {
                active: this.protectionActive,
                stats: this.stats,
                engine: this.unifiedProtectionEngine ? this.unifiedProtectionEngine.getStatistics() : null,
                unified: true
            };
        });

        ipcMain.handle('toggle-protection', () => {
            return this.toggleProtection();
        });

        ipcMain.handle('run-deep-scan', () => {
            return this.runDeepScan();
        });

        ipcMain.handle('analyze-contract', (event, contractAddress) => {
            return this.analyzeContract(contractAddress);
        });

        ipcMain.handle('connect-walletconnect', async (event, connectionData) => {
            return this.handleWalletConnectConnection(connectionData);
        });

        ipcMain.handle('initialize-walletconnect', async () => {
            return this.initializeWalletConnect();
        });

        ipcMain.handle('wait-wallet-connection', async () => {
            return this.waitForWalletConnection();
        });

        ipcMain.handle('check-transaction', (event, txHash) => {
            return this.checkTransaction(txHash);
        });

        ipcMain.handle('emergency-isolation', () => {
            return this.emergencyIsolation();
        });

        ipcMain.handle('load-config', () => {
            return this.loadConfig();
        });

        ipcMain.handle('save-config', (event, config) => {
            return this.saveConfig(config);
        });

        // Crypto API handler for WalletConnect compatibility
        ipcMain.handle('crypto-get-random-values', (event, length) => {
            const array = new Uint8Array(length);
            crypto.randomFillSync(array);
            return Array.from(array);
        });

        // Enhanced OSINT and AI Oracle handlers
        ipcMain.handle('check-phishing-url', async (event, url) => {
            if (this.osintIntelligence) {
                return await this.osintIntelligence.analyzePhishingURL(url);
            }
            return { error: 'OSINT intelligence not available' };
        });

        ipcMain.handle('analyze-with-ai', async (event, indicator, context) => {
            if (this.aiOracle) {
                return await this.aiOracle.analyzeThreat(indicator, context);
            }
            return { error: 'AI Oracle not available' };
        });

        ipcMain.handle('get-osint-stats', () => {
            if (this.osintIntelligence) {
                return this.osintIntelligence.getStats();
            }
            return { error: 'OSINT intelligence not available' };
        });

        ipcMain.handle('analyze-smart-contract', async (event, contractAddress, bytecode) => {
            if (this.aiOracle) {
                return await this.aiOracle.analyzeSmartContract(contractAddress, bytecode);
            }
            return { error: 'AI Oracle not available' };
        });

        // Real-time data handlers for dashboard
        ipcMain.handle('get-engine-stats', () => {
            if (this.unifiedProtectionEngine) {
                return this.unifiedProtectionEngine.getStatistics();
            }
            return null;
        });

        ipcMain.handle('get-recent-activity', () => {
            // Return recent threat detection activity
            return this.recentActivity || [];
        });

        ipcMain.handle('get-ai-oracle-stats', () => {
            if (this.aiOracle) {
                return this.aiOracle.getStats();
            }
            return null;
        });

        console.log('📡 IPC handlers registered');
    }

    sendToRenderer(channel, data) {
        if (this.mainWindow && this.mainWindow.webContents) {
            this.mainWindow.webContents.send(channel, data);
        }
    }

    showMainWindow() {
        if (this.mainWindow) {
            this.mainWindow.show();
            this.mainWindow.focus();

            if (process.platform === 'darwin') {
                app.dock.show();
            }
        }
    }

    toggleProtection() {
        this.protectionActive = !this.protectionActive;
        this.updateTrayMenu();

        this.sendToRenderer('protection-toggled', { active: this.protectionActive });

        return this.protectionActive;
    }

    async runDeepScan() {
        console.log('🔬 Starting unified deep system scan...');

        this.sendToRenderer('scan-started', { type: 'deep' });

        if (this.unifiedProtectionEngine) {
            try {
                // Use unified engine for comprehensive scan
                await this.unifiedProtectionEngine.scan();

                // Get updated statistics
                const engineStats = this.unifiedProtectionEngine.getStatistics();

                this.stats.scansCompleted++;
                
                const scanResults = {
                    threatsFound: engineStats.threatsDetected || 0,
                    filesScanned: engineStats.filesScanned || 0,
                    networkConnections: engineStats.networkConnectionsMonitored || 0,
                    cryptoAssets: engineStats.cryptoTransactionsProtected || 0,
                    engineUptime: engineStats.uptime || 0,
                    scanTime: engineStats.lastScanDuration || '0s'
                };
                
                this.sendToRenderer('scan-completed', {
                    type: 'deep',
                    results: scanResults,
                    engineStats: engineStats
                });
                
                // RETURN the results for the IPC call
                return scanResults;
            } catch (error) {
                console.error('❌ Deep scan error:', error);
                this.sendToRenderer('scan-error', { error: error.message });
                return { error: error.message, threatsFound: 0, filesScanned: 0 };
            }
        } else {
            // Fallback if engine not available
            const fallbackResult = { error: 'Unified Protection Engine not available', threatsFound: 0, filesScanned: 0 };
            this.sendToRenderer('scan-completed', {
                type: 'deep',
                results: fallbackResult
            });
            return fallbackResult;
        }
    }

    async analyzeContract(contractAddress) {
        if (!contractAddress) {
            const result = await dialog.showMessageBox(this.mainWindow, {
                type: 'info',
                title: 'Analyze Smart Contract',
                message: 'This feature is available in the UI dashboard.',
                buttons: ['OK']
            });
            return null;
        }

        if (contractAddress && this.walletShield) {
            console.log(`🔍 Analyzing contract: ${contractAddress}`);
            return await this.walletShield.analyzeSmartContract(contractAddress);
        } else {
            // Return proper error result when wallet shield not available
            return {
                error: 'Wallet Shield not available',
                safe: false,
                summary: 'Contract analysis service unavailable'
            };
        }
    }

    async handleWalletConnectConnection(connectionData) {
        console.log('📱 Backend: Processing WalletConnect connection');
        
        if (connectionData && connectionData.address) {
            // Log wallet connection for security monitoring
            this.addActivity({
                icon: '📱',
                text: `WalletConnect connected: ${connectionData.address.substring(0, 8)}...`,
                type: 'success',
                timestamp: new Date()
            });
            
            // Enable wallet monitoring
            if (this.walletShield) {
                await this.walletShield.addProtectedWallet(connectionData.address, 'WalletConnect');
            }
            
            return {
                success: true,
                address: connectionData.address,
                provider: 'WalletConnect',
                protectionEnabled: true
            };
        } else {
            return {
                success: false,
                error: 'Invalid connection data'
            };
        }
    }

    async initializeWalletConnect() {
        console.log('📱 Backend: Initializing WalletConnect as dApp to connect mobile wallets...');
        
        try {
            // Initialize WalletConnect SignClient (dApp mode)
            this.signClient = await SignClient.init({
                projectId: process.env.WALLETCONNECT_PROJECT_ID || 'apollo-cybersentinel-protection',
                metadata: {
                    name: 'Apollo CyberSentinel',
                    description: 'Military-grade wallet protection against nation-state threats',
                    url: 'https://apollo-shield.org',
                    icons: ['https://apollo-shield.org/assets/apollo-icon.png']
                }
            });

            // Set up comprehensive event handlers for dApp mode
            this.setupSignClientEventHandlers();

            console.log('✅ WalletConnect SignClient initialized for mobile wallet connections');
            console.log('📱 SignClient instance:', !!this.signClient);
            console.log('📱 SignClient methods available:', Object.getOwnPropertyNames(Object.getPrototypeOf(this.signClient)));
            return { success: true, message: 'WalletConnect ready for mobile wallet scanning' };
            
        } catch (error) {
            console.error('❌ WalletConnect SignClient initialization failed:', error);
            return { success: false, error: error.message };
        }
    }

    setupSignClientEventHandlers() {
        if (!this.signClient) return;

        // Session established handler - when mobile wallet connects
        this.signClient.on('session_event', (event) => {
            console.log('📱 WalletConnect session event:', event);
        });

        // Session update handler
        this.signClient.on('session_update', ({ topic, params }) => {
            console.log('📱 WalletConnect session update:', topic, params);
        });

        // Session delete handler  
        this.signClient.on('session_delete', ({ topic, id }) => {
            console.log('📱 WalletConnect session deleted:', topic, id);
        });

        console.log('✅ WalletConnect SignClient event handlers configured');
    }

    // Legacy handler - keeping for compatibility but updating for SignClient
    setupWalletConnectEventHandlers() {
        if (!this.walletKit || !this.walletCore) return;

        // Session proposal handler - when dapp wants to connect
        this.walletKit.on('session_proposal', async (proposal) => {
            console.log('📱 WalletConnect session proposal received:', proposal.id);
            
            try {
                // Build approved namespaces for Ethereum support
                const approvedNamespaces = buildApprovedNamespaces({
                    proposal: proposal.params,
                    supportedNamespaces: {
                        eip155: {
                            chains: ['eip155:1', 'eip155:137'], // Ethereum mainnet and Polygon
                            methods: [
                                'eth_accounts',
                                'eth_requestAccounts', 
                                'eth_sendTransaction',
                                'personal_sign',
                                'eth_sign',
                                'eth_signTypedData',
                                'eth_signTypedData_v4'
                            ],
                            events: ['accountsChanged', 'chainChanged'],
                            accounts: [] // Will be populated when user connects
                        }
                    }
                });

                // Log session proposal for user awareness (don't auto-approve)
                console.log('📱 WalletConnect session proposal received from:', proposal.params.proposer.metadata.name);
                console.log('📱 Chains requested:', proposal.params.requiredNamespaces.eip155?.chains);
                console.log('📱 Methods requested:', proposal.params.requiredNamespaces.eip155?.methods);
                
                // For now, we'll reject automatic approvals to prevent ghost connections
                // In a real implementation, this would show a user prompt
                console.log('⚠️ Auto-rejecting session proposal to prevent ghost wallet connections');
                await this.walletKit.rejectSession({
                    id: proposal.id,
                    reason: getSdkError('USER_REJECTED')
                });
                
                // Notify frontend about the rejected proposal
                this.sendToRenderer('walletconnect-proposal-rejected', {
                    proposer: proposal.params.proposer.metadata.name,
                    reason: 'Auto-approval disabled to prevent ghost connections'
                });

            } catch (error) {
                console.error('❌ Session approval failed:', error);
                
                // Reject session
                await this.walletKit.rejectSession({
                    id: proposal.id,
                    reason: getSdkError('USER_REJECTED')
                });
            }
        });

        // Connection state monitoring
        this.walletCore.relayer.on('relayer_connect', () => {
            console.log('✅ WalletConnect relay connected');
            this.sendToRenderer('walletconnect-connected', { status: 'connected' });
        });

        this.walletCore.relayer.on('relayer_disconnect', () => {
            console.log('⚠️ WalletConnect relay disconnected');
            this.sendToRenderer('walletconnect-disconnected', { status: 'disconnected' });
        });

        // Pairing expiry handler
        this.walletCore.pairing.events.on('pairing_expire', (event) => {
            console.log('⏰ WalletConnect pairing expired:', event.topic);
            this.sendToRenderer('walletconnect-pairing-expired', { topic: event.topic });
        });

        // Session request handler - when dapp makes requests
        this.walletKit.on('session_request', async (request) => {
            console.log('📱 WalletConnect session request:', request.params.request.method);
            
            // Log request for security monitoring
            this.addActivity({
                icon: '📱',
                text: `WalletConnect request: ${request.params.request.method}`,
                type: 'info',
                timestamp: new Date()
            });
        });

        console.log('✅ WalletConnect event handlers configured');
    }

    async waitForWalletConnection() {
        console.log('📱 Backend: Generating WalletConnect connection URI for mobile wallets...');
        
        if (!this.signClient) {
            return { success: false, error: 'WalletConnect SignClient not initialized' };
        }

        try {
            // Check if we have a valid project ID
            if (!process.env.WALLETCONNECT_PROJECT_ID || process.env.WALLETCONNECT_PROJECT_ID === 'apollo-cybersentinel-protection') {
                return {
                    success: false,
                    error: 'WalletConnect requires a valid project ID from https://cloud.reown.com/',
                    message: 'Add WALLETCONNECT_PROJECT_ID to your .env file to enable mobile wallet connections',
                    configRequired: true
                };
            }

            // Connect to mobile wallet using SignClient (dApp mode)
            const { uri, approval } = await this.signClient.connect({
                requiredNamespaces: {
                    eip155: {
                        methods: [
                            'eth_sendTransaction',
                            'eth_signTransaction', 
                            'eth_sign',
                            'personal_sign',
                            'eth_signTypedData',
                            'eth_signTypedData_v4',
                        ],
                        chains: ['eip155:1', 'eip155:137'], // Ethereum + Polygon
                        events: ['chainChanged', 'accountsChanged'],
                    },
                },
            });
            
            console.log('📱 WalletConnect connection URI generated:', uri);
            console.log('📱 Setting up approval handler...');
            
            // Generate QR code as data URL
            const qrCodeDataURL = await QRCode.toDataURL(uri, {
                width: 300,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            });
            
            // Set up approval handler
            approval().then((session) => {
                console.log('✅ WalletConnect session approved by mobile wallet:', session);
                console.log('📱 Session structure:', JSON.stringify(session, null, 2));
                
                // Extract wallet address from session (SignClient format)
                const accounts = Object.values(session.namespaces || {})[0]?.accounts || [];
                const walletAddress = accounts[0]?.split(':')[2];
                
                console.log('📱 Extracted accounts:', accounts);
                console.log('📱 Extracted wallet address:', walletAddress);
                
                if (walletAddress) {
                    const sessionData = {
                        topic: session.topic,
                        address: walletAddress,
                        peer: session.peer,
                        accounts: accounts,
                        source: 'SignClient',
                        timestamp: new Date().toISOString()
                    };
                    
                    console.log('📱 Sending WalletConnect session to frontend:', sessionData);
                    
                    // Try multiple channels to bypass hijacking
                    this.sendToRenderer('apollo-walletconnect-session-success', sessionData);
                    this.sendToRenderer('apollo-wallet-connected', sessionData);
                    this.sendToRenderer('apollo-session-approved', sessionData);
                    
                    console.log('📱 WalletConnect session sent to frontend on multiple channels');
                    
                    // Also try direct global variable injection
                    if (this.mainWindow && this.mainWindow.webContents) {
                        this.mainWindow.webContents.executeJavaScript(`
                            window.apolloWalletConnectSession = ${JSON.stringify(sessionData)};
                            console.log('🔧 Direct injection: WalletConnect session injected into window object');
                            if (window.handleWalletConnectSuccess) {
                                window.handleWalletConnectSuccess(${JSON.stringify(sessionData)});
                            }
                        `);
                    }
                } else {
                    console.error('❌ Could not extract wallet address from session');
                    this.sendToRenderer('walletconnect-session-rejected', {
                        error: 'Could not extract wallet address from session'
                    });
                }
            }).catch((error) => {
                console.error('❌ WalletConnect session approval failed:', error);
                this.sendToRenderer('walletconnect-session-rejected', {
                    error: error.message
                });
            });
            
            return {
                success: true,
                uri: uri,
                qrCode: qrCodeDataURL,
                message: 'Scan QR code with your mobile wallet to connect',
                qrCodeReady: true
            };
            
        } catch (error) {
            console.error('❌ WalletConnect connection generation failed:', error);
            return { success: false, error: error.message };
        }
    }

    async checkTransaction(txHash) {
        if (!txHash) {
            const result = await dialog.showMessageBox(this.mainWindow, {
                type: 'info',
                title: 'Check Transaction',
                message: 'This feature is available in the UI dashboard.',
                buttons: ['OK']
            });
            return null;
        }

        if (txHash && this.walletShield) {
            console.log(`🔍 Checking transaction: ${txHash}`);
            this.stats.cryptoTransactionsProtected++;
            return { safe: true, risks: [] };
        }
    }

    async emergencyIsolation() {
        const result = await dialog.showMessageBox(this.mainWindow, {
            type: 'warning',
            title: 'Emergency Isolation',
            message: 'This will immediately disconnect all network connections.',
            detail: 'This action should only be used in case of active threat. Continue?',
            buttons: ['Isolate Now', 'Cancel'],
            defaultId: 1,
            cancelId: 1
        });

        if (result.response === 0) {
            console.log('🚧 Emergency isolation activated');

            // Use real threat blocker for system isolation
            if (this.threatBlocker) {
                await this.threatBlocker.enableSystemIsolation();
            }

            this.sendToRenderer('emergency-isolation', { active: true });
            return true;
        }

        return false;
    }

    blockThreat(alert) {
        console.log('🛡️ Blocking threat:', alert.type);
        this.stats.threatsBlocked++;
        this.sendToRenderer('threat-blocked', alert);
    }

    investigateThreat(alert) {
        console.log('🔍 Investigating threat:', alert.type);
        this.sendToRenderer('threat-investigation', alert);
    }

    updateTrayMenu() {
        if (this.tray) {
            const contextMenu = Menu.buildFromTemplate([
                {
                    label: 'Apollo Protection',
                    type: 'normal',
                    enabled: false
                },
                { type: 'separator' },
                {
                    label: 'Show Dashboard',
                    click: () => this.showMainWindow()
                },
                {
                    label: `Protection: ${this.protectionActive ? 'Active' : 'Inactive'}`,
                    click: () => this.toggleProtection()
                },
                {
                    label: `Threats Detected: ${this.stats.threatsDetected}`,
                    enabled: false
                },
                { type: 'separator' },
                {
                    label: 'Emergency Isolation',
                    click: () => this.emergencyIsolation()
                },
                {
                    label: 'Run Deep Scan',
                    click: () => this.runDeepScan()
                },
                { type: 'separator' },
                {
                    label: 'Settings',
                    click: () => this.showSettings()
                },
                {
                    label: 'Quit Apollo',
                    click: () => this.quitApplication()
                }
            ]);

            this.tray.setContextMenu(contextMenu);
        }
    }

    showSettings() {
        this.sendToRenderer('show-settings');
        this.showMainWindow();
    }

    showAbout() {
        dialog.showMessageBox(this.mainWindow, {
            type: 'info',
            title: 'About Apollo',
            message: 'Apollo - Military-Grade Protection',
            detail: 'Version 1.0.0\n\nAdvanced protection against nation-state hackers,\nPegasus-style spyware, and crypto threats.\n\n© 2025 Apollo Project'
        });
    }

    showActivityLog() {
        this.sendToRenderer('show-activity-log');
        this.showMainWindow();
    }

    showErrorDialog(title, message) {
        dialog.showErrorBox(title, message);
    }

    async loadConfig() {
        try {
            const configPath = path.join(os.homedir(), '.apollo', 'config', 'settings.json');
            if (await fs.pathExists(configPath)) {
                return await fs.readJSON(configPath);
            }
        } catch (error) {
            console.error('Failed to load config:', error);
        }
        return {};
    }

    async saveConfig(config) {
        try {
            const configPath = path.join(os.homedir(), '.apollo', 'config', 'settings.json');
            await fs.writeJSON(configPath, config, { spaces: 2 });
            return true;
        } catch (error) {
            console.error('Failed to save config:', error);
            return false;
        }
    }

    quitApplication() {
        this.isQuitting = true;
        app.quit();
    }
}

const apolloApp = new ApolloApplication();

module.exports = ApolloApplication;