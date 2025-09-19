#!/usr/bin/env node

const { app } = require('electron');
const path = require('path');
const fs = require('fs-extra');
const os = require('os');
const { fork } = require('child_process');

const SystemPrivileges = require('../native/system-privileges');
const ThreatBlocker = require('../native/threat-blocker');
const ApolloThreatEngine = require('../threat-engine/core');
const ApolloWalletShield = require('../crypto-guardian/wallet-shield');
const ApolloAPTDetector = require('../apt-detection/realtime-monitor');

class ApolloService {
    constructor() {
        this.isService = process.argv.includes('--service');
        this.isInstall = process.argv.includes('--install');
        this.isUninstall = process.argv.includes('--uninstall');

        this.systemPrivileges = null;
        this.threatBlocker = null;
        this.threatEngine = null;
        this.walletShield = null;
        this.aptDetector = null;

        this.serviceConfig = {
            name: 'ApolloProtection',
            displayName: 'Apollo Security Protection Service',
            description: 'Military-grade protection against nation-state threats',
            startType: 'auto'
        };

        this.init();
    }

    async init() {
        // Handle service installation/uninstallation
        if (this.isInstall) {
            await this.installService();
            process.exit(0);
        } else if (this.isUninstall) {
            await this.uninstallService();
            process.exit(0);
        }

        // Initialize protection components
        if (this.isService) {
            await this.runAsService();
        } else {
            console.log('🚀 Apollo Service starting in standalone mode...');
            await this.startProtection();
        }
    }

    async installService() {
        console.log('📦 Installing Apollo Service...');

        this.systemPrivileges = new SystemPrivileges();

        // Check for admin privileges
        const hasPrivileges = await this.systemPrivileges.checkPrivileges();
        if (!hasPrivileges) {
            console.error('❌ Administrator privileges required for service installation');
            console.log('Please run: apollo-service --install as Administrator/root');
            process.exit(1);
        }

        try {
            // Create service based on platform
            const success = await this.systemPrivileges.createSystemService();

            if (success) {
                console.log('✅ Apollo Service installed successfully');
                console.log('Service will start automatically on system boot');

                // Create service configuration
                await this.createServiceConfig();

                // Set up auto-start
                await this.configureAutoStart();

                console.log('\n📋 Service Information:');
                console.log(`Name: ${this.serviceConfig.name}`);
                console.log(`Status: Installed`);
                console.log(`Start Type: Automatic`);
                console.log('\nTo start service manually:');

                if (os.platform() === 'win32') {
                    console.log('  sc start ApolloProtection');
                } else if (os.platform() === 'darwin') {
                    console.log('  sudo launchctl load /Library/LaunchDaemons/com.apollo.shield.plist');
                } else {
                    console.log('  sudo systemctl start apollo.service');
                }
            } else {
                throw new Error('Service installation failed');
            }
        } catch (error) {
            console.error('❌ Failed to install service:', error);
            process.exit(1);
        }
    }

    async uninstallService() {
        console.log('🗑️ Uninstalling Apollo Service...');

        this.systemPrivileges = new SystemPrivileges();

        const hasPrivileges = await this.systemPrivileges.checkPrivileges();
        if (!hasPrivileges) {
            console.error('❌ Administrator privileges required for service uninstallation');
            process.exit(1);
        }

        try {
            const platform = os.platform();

            if (platform === 'win32') {
                // Stop and delete Windows service
                await this.systemPrivileges.executePrivilegedCommand('sc stop ApolloProtection');
                await this.systemPrivileges.executePrivilegedCommand('sc delete ApolloProtection');
            } else if (platform === 'darwin') {
                // Unload and remove macOS daemon
                await this.systemPrivileges.executePrivilegedCommand('launchctl unload /Library/LaunchDaemons/com.apollo.shield.plist');
                await fs.unlink('/Library/LaunchDaemons/com.apollo.shield.plist');
            } else {
                // Stop and disable Linux systemd service
                await this.systemPrivileges.executePrivilegedCommand('systemctl stop apollo.service');
                await this.systemPrivileges.executePrivilegedCommand('systemctl disable apollo.service');
                await fs.unlink('/etc/systemd/system/apollo.service');
                await this.systemPrivileges.executePrivilegedCommand('systemctl daemon-reload');
            }

            console.log('✅ Apollo Service uninstalled successfully');
        } catch (error) {
            console.error('❌ Failed to uninstall service:', error);
            process.exit(1);
        }
    }

    async createServiceConfig() {
        const configDir = path.join(os.homedir(), '.apollo', 'service');
        await fs.ensureDir(configDir);

        const config = {
            version: '1.0.0',
            installed: new Date().toISOString(),
            service: this.serviceConfig,
            protection: {
                autoStart: true,
                realTimeProtection: true,
                threatEngine: true,
                aptDetector: true,
                cryptoGuardian: true,
                networkMonitoring: true,
                behavioralAnalysis: true
            },
            logging: {
                enabled: true,
                level: 'info',
                path: path.join(configDir, 'logs')
            }
        };

        await fs.writeJSON(path.join(configDir, 'config.json'), config, { spaces: 2 });
        await fs.ensureDir(config.logging.path);
    }

    async configureAutoStart() {
        const platform = os.platform();

        if (platform === 'win32') {
            // Windows: Configure service recovery options
            try {
                await this.systemPrivileges.executePrivilegedCommand(
                    'sc failure ApolloProtection reset= 86400 actions= restart/5000/restart/10000/restart/30000'
                );
            } catch (error) {
                console.warn('Could not configure service recovery:', error);
            }
        }
    }

    async runAsService() {
        console.log('🔄 Apollo Service starting in background mode...');

        // Set up service lifecycle handlers
        this.setupServiceHandlers();

        // Start protection
        await this.startProtection();

        // Log service start
        await this.logServiceEvent('SERVICE_START', 'Apollo Service started successfully');

        // Keep service running
        setInterval(() => {
            this.healthCheck();
        }, 60000); // Health check every minute
    }

    setupServiceHandlers() {
        // Handle service stop signals
        process.on('SIGTERM', async () => {
            console.log('📴 Service stop signal received');
            await this.stopProtection();
            process.exit(0);
        });

        process.on('SIGINT', async () => {
            console.log('🛑 Service interrupt signal received');
            await this.stopProtection();
            process.exit(0);
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', async (error) => {
            console.error('❌ Uncaught exception:', error);
            await this.logServiceEvent('ERROR', `Uncaught exception: ${error.message}`);
            // Don't exit - try to recover
        });

        process.on('unhandledRejection', async (reason, promise) => {
            console.error('❌ Unhandled rejection:', reason);
            await this.logServiceEvent('ERROR', `Unhandled rejection: ${reason}`);
        });
    }

    async startProtection() {
        console.log('🚀 Initializing Apollo Protection Components...');

        try {
            // Initialize system privileges and threat blocker
            this.systemPrivileges = new SystemPrivileges();
            this.threatBlocker = new ThreatBlocker();

            // Check and request privileges if needed
            const hasPrivileges = await this.systemPrivileges.checkPrivileges();
            if (!hasPrivileges) {
                console.warn('⚠️ Running without full privileges - protection limited');
            }

            // Initialize protection engines
            console.log('🛡️ Starting Threat Detection Engine...');
            this.threatEngine = new ApolloThreatEngine();

            console.log('⛓️ Starting Crypto Guardian...');
            this.walletShield = new ApolloWalletShield();

            console.log('🕵️ Starting APT Detector...');
            this.aptDetector = new ApolloAPTDetector();

            // Set up threat response handlers
            this.setupThreatHandlers();

            // Start continuous monitoring
            await this.threatEngine.startContinuousMonitoring();

            // Enable real-time protection
            await this.systemPrivileges.enableRealtimeProtection();

            console.log('✅ Apollo Protection Active - All systems operational');

            // Update service status
            await this.updateServiceStatus('RUNNING');

            return true;
        } catch (error) {
            console.error('❌ Failed to start protection:', error);
            await this.logServiceEvent('ERROR', `Failed to start protection: ${error.message}`);
            return false;
        }
    }

    setupThreatHandlers() {
        // Handle threats from Threat Engine
        this.threatEngine.onAlert(async (alert) => {
            console.log('🚨 Threat Engine Alert:', alert);
            await this.handleThreat(alert);
        });

        // Handle crypto threats
        this.walletShield.onAlert(async (alert) => {
            console.log('⛓️ Crypto Guardian Alert:', alert);
            await this.handleCryptoThreat(alert);
        });

        // Handle APT detections
        this.aptDetector.onAlert(async (alert) => {
            console.log('🕵️ APT Detector Alert:', alert);
            await this.handleAPTThreat(alert);
        });
    }

    async handleThreat(alert) {
        await this.logServiceEvent('THREAT_DETECTED', `${alert.type}: ${alert.category}`);

        if (alert.severity === 'CRITICAL' || alert.severity === 'HIGH') {
            // Take immediate action
            if (alert.details?.pid) {
                await this.threatBlocker.blockProcess({
                    pid: alert.details.pid,
                    name: alert.details.processName || 'Unknown',
                    path: alert.details.path
                });
            }

            if (alert.details?.address) {
                await this.threatBlocker.blockNetworkThreat({
                    ip: alert.details.address,
                    port: alert.details.port,
                    domain: alert.details.domain
                });
            }

            if (alert.details?.path) {
                await this.threatBlocker.quarantineFile(alert.details.path, alert.type);
            }
        }

        // Notify user if UI is available
        this.notifyUser(alert);
    }

    async handleCryptoThreat(alert) {
        await this.logServiceEvent('CRYPTO_THREAT', alert.type);

        if (alert.severity === 'CRITICAL') {
            // Emergency wallet protection
            console.log('🔒 Activating emergency wallet protection');

            // Block malicious contract/transaction
            if (alert.details?.address) {
                await this.threatBlocker.blockNetworkThreat({
                    ip: alert.details.address,
                    domain: alert.details.url
                });
            }
        }

        this.notifyUser(alert);
    }

    async handleAPTThreat(alert) {
        await this.logServiceEvent('APT_DETECTED', `${alert.group}: ${alert.type}`);

        if (alert.severity === 'CRITICAL') {
            // Initiate emergency response
            console.log('🚨 Critical APT activity - initiating emergency response');

            // Check if we should auto-isolate
            const config = await this.loadServiceConfig();
            if (config?.protection?.autoIsolate) {
                await this.threatBlocker.enableSystemIsolation();
            }
        }

        this.notifyUser(alert);
    }

    async stopProtection() {
        console.log('🛑 Stopping Apollo Protection...');

        try {
            if (this.threatEngine) await this.threatEngine.shutdown();
            if (this.walletShield) await this.walletShield.shutdown();
            if (this.aptDetector) await this.aptDetector.shutdown();

            await this.updateServiceStatus('STOPPED');
            await this.logServiceEvent('SERVICE_STOP', 'Apollo Service stopped');

            console.log('✅ Apollo Protection stopped');
        } catch (error) {
            console.error('Error stopping protection:', error);
        }
    }

    async healthCheck() {
        const status = {
            timestamp: new Date().toISOString(),
            service: 'RUNNING',
            components: {
                threatEngine: this.threatEngine?.getStatus(),
                walletShield: this.walletShield?.getProtectionStatus(),
                aptDetector: this.aptDetector?.getDetectionStatus(),
                threatBlocker: this.threatBlocker?.getStatus()
            },
            system: {
                memory: process.memoryUsage(),
                uptime: process.uptime(),
                platform: os.platform(),
                privileges: this.systemPrivileges?.isElevated
            }
        };

        // Write health status
        const statusFile = path.join(os.homedir(), '.apollo', 'service', 'health.json');
        await fs.writeJSON(statusFile, status, { spaces: 2 });

        // Check if components are responsive
        if (!this.threatEngine?.isRunning) {
            console.warn('⚠️ Threat Engine not running - restarting...');
            this.threatEngine = new ApolloThreatEngine();
            await this.threatEngine.startContinuousMonitoring();
        }
    }

    async logServiceEvent(type, message) {
        const logDir = path.join(os.homedir(), '.apollo', 'service', 'logs');
        await fs.ensureDir(logDir);

        const logEntry = {
            timestamp: new Date().toISOString(),
            type,
            message,
            pid: process.pid
        };

        const logFile = path.join(logDir, `service_${new Date().toISOString().split('T')[0]}.log`);
        await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
    }

    async loadServiceConfig() {
        try {
            const configFile = path.join(os.homedir(), '.apollo', 'service', 'config.json');
            return await fs.readJSON(configFile);
        } catch {
            return null;
        }
    }

    async updateServiceStatus(status) {
        const statusFile = path.join(os.homedir(), '.apollo', 'service', 'status');
        await fs.writeFile(statusFile, status);
    }

    notifyUser(alert) {
        // If running as service, we need IPC to notify the UI
        // For now, just log it
        console.log('📢 User notification:', alert);

        // In production, would use:
        // - Windows: Toast notifications
        // - macOS: Notification Center
        // - Linux: libnotify
    }
}

// Start the service
new ApolloService();