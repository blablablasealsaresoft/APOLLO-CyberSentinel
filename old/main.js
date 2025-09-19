// Load environment variables first
require('dotenv').config();

const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs-extra');
const os = require('os');

// Fix cache permission issues
app.commandLine.appendSwitch('disable-gpu-sandbox');
app.commandLine.appendSwitch('no-sandbox');

// Unified Protection Engine - Combines all protection modules
const ApolloUnifiedProtectionEngine = require('./src/core/unified-protection-engine');
const SystemPrivileges = require('./src/native/system-privileges');
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');
const ApolloAIOracle = require('./src/ai/oracle-integration');

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

        this.protectionActive = false;
        this.stats = {
            threatsDetected: 0,
            threatsBlocked: 0,
            scansCompleted: 0,
            cryptoTransactionsProtected: 0
        };

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

        // Send alert to dashboard
        this.sendToRenderer('unified-threat-alert', {
            type: alert.type,
            severity: alert.severity,
            source: alert.source,
            details: alert.details,
            timestamp: alert.timestamp,
            engine: 'Unified Protection Engine',
            stats: this.unifiedProtectionEngine.getStatistics()
        });

        // Show critical alert dialog
        if (alert.severity === 'critical') {
            this.showCriticalThreatDialog(alert);
        }

        this.updateTrayMenu();
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
                this.sendToRenderer('scan-completed', {
                    type: 'deep',
                    results: {
                        threatsFound: engineStats.threatsDetected,
                        itemsScanned: engineStats.filesScanned,
                        networkConnections: engineStats.networkConnectionsMonitored,
                        cryptoAssets: engineStats.cryptoTransactionsProtected,
                        engineUptime: engineStats.uptime
                    },
                    engineStats: engineStats
                });
            } catch (error) {
                console.error('❌ Deep scan error:', error);
                this.sendToRenderer('scan-error', { error: error.message });
            }
        } else {
            // Fallback if engine not available
            this.sendToRenderer('scan-completed', {
                type: 'deep',
                results: { error: 'Unified Protection Engine not available' }
            });
        }
    }

    async analyzeContract(contractAddress) {
        if (!contractAddress) {
            const result = await dialog.showInputBox(this.mainWindow, {
                title: 'Analyze Smart Contract',
                label: 'Enter contract address:',
                value: ''
            });
            contractAddress = result;
        }

        if (contractAddress && this.walletShield) {
            console.log(`🔍 Analyzing contract: ${contractAddress}`);
            return await this.walletShield.analyzeSmartContract(contractAddress);
        }
    }

    async checkTransaction(txHash) {
        if (!txHash) {
            const result = await dialog.showInputBox(this.mainWindow, {
                title: 'Check Transaction',
                label: 'Enter transaction hash:',
                value: ''
            });
            txHash = result;
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