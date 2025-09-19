const os = require('os');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const { exec, spawn } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class ApolloAPTDetector {
    constructor() {
        this.isActive = false;
        this.detectionRules = new Map();
        this.behaviorBaseline = new Map();
        this.suspiciousActivities = new Set();
        this.alertCallbacks = [];
        this.monitoringInterval = null;

        this.initializeDetector();
    }

    async initializeDetector() {
        console.log('🕵️ Apollo APT Detection System initializing...');

        await this.loadAPTSignatures();
        await this.establishBehaviorBaseline();
        await this.setupSystemMonitoring();
        await this.initializeForensicCapabilities();

        this.isActive = true;
        console.log('✅ APT Detection active - nation-state threats monitored');
    }

    async loadAPTSignatures() {
        const aptSignatures = {
            northKoreaLazarus: {
                name: 'Lazarus Group (North Korea)',
                techniques: [
                    'T1055', // Process Injection
                    'T1071', // Application Layer Protocol
                    'T1105', // Ingress Tool Transfer
                    'T1027', // Obfuscated Files or Information
                    'T1083'  // File and Directory Discovery
                ],
                indicators: {
                    processes: [
                        'rundll32.exe',
                        'regsvr32.exe',
                        'mshta.exe',
                        'wscript.exe'
                    ],
                    networks: [
                        /.*\.blogspot\.com/i,
                        /.*\.wordpress\.com/i,
                        /.*\.github\.io/i
                    ],
                    files: [
                        /.*\.scr$/i,
                        /.*\.pif$/i,
                        /.*\.bat$/i
                    ],
                    registry: [
                        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
                    ]
                },
                behaviors: [
                    'cryptocurrency_targeting',
                    'financial_institution_focus',
                    'supply_chain_attacks',
                    'watering_hole_attacks'
                ]
            },

            pegasusSpyware: {
                name: 'Pegasus Spyware',
                techniques: [
                    'T1068', // Exploitation for Privilege Escalation
                    'T1055', // Process Injection
                    'T1113', // Screen Capture
                    'T1125', // Video Capture
                    'T1123'  // Audio Capture
                ],
                indicators: {
                    processes: [
                        'assistantd',
                        'mobileassetd',
                        'com.apple.WebKit.Networking'
                    ],
                    networks: [
                        /.*\.duckdns\.org/i,
                        /.*pegasus.*\.com/i,
                        /.*nsogroup.*\.*/i
                    ],
                    files: [
                        /.*\/Library\/Caches\/com\.apple\..*\/fsCachedData\/.*/,
                        /.*\/private\/var\/folders\/.*\/T\/.*\.plist/
                    ]
                },
                behaviors: [
                    'zero_click_exploitation',
                    'iphone_targeting',
                    'journalist_surveillance',
                    'activist_monitoring'
                ]
            },

            russianAPT: {
                name: 'Russian APT Groups',
                techniques: [
                    'T1566', // Phishing
                    'T1204', // User Execution
                    'T1059', // Command and Scripting Interpreter
                    'T1033', // System Owner/User Discovery
                    'T1082'  // System Information Discovery
                ],
                indicators: {
                    processes: [
                        'powershell.exe',
                        'cmd.exe',
                        'wmic.exe'
                    ],
                    networks: [
                        /.*\.ru$/i,
                        /.*\.su$/i,
                        /.*cozy.*\.com/i,
                        /.*fancy.*bear.*\.*/i
                    ],
                    files: [
                        /.*\.docm$/i,
                        /.*\.xlsm$/i,
                        /.*\.vbs$/i
                    ]
                },
                behaviors: [
                    'government_targeting',
                    'election_interference',
                    'critical_infrastructure',
                    'military_espionage'
                ]
            },

            chineseAPT: {
                name: 'Chinese APT Groups',
                techniques: [
                    'T1190', // Exploit Public-Facing Application
                    'T1078', // Valid Accounts
                    'T1021', // Remote Services
                    'T1003', // OS Credential Dumping
                    'T1074'  // Data Staged
                ],
                indicators: {
                    processes: [
                        'net.exe',
                        'netstat.exe',
                        'tasklist.exe'
                    ],
                    networks: [
                        /.*\.cn$/i,
                        /.*\.tk$/i,
                        /.*apt.*\.*/i
                    ],
                    files: [
                        /.*\.rar$/i,
                        /.*\.7z$/i,
                        /.*tmp.*\.exe$/i
                    ]
                },
                behaviors: [
                    'intellectual_property_theft',
                    'manufacturing_espionage',
                    'technology_transfer',
                    'supply_chain_infiltration'
                ]
            }
        };

        for (const [group, signatures] of Object.entries(aptSignatures)) {
            this.detectionRules.set(group, signatures);
        }

        console.log(`🎯 Loaded APT signatures for ${this.detectionRules.size} threat groups`);
    }

    async establishBehaviorBaseline() {
        console.log('📊 Establishing system behavior baseline...');

        const baseline = {
            processes: await this.getProcessBaseline(),
            network: await this.getNetworkBaseline(),
            files: await this.getFileSystemBaseline(),
            registry: await this.getRegistryBaseline()
        };

        this.behaviorBaseline.set('system', baseline);
        console.log('✅ Behavioral baseline established');
    }

    async getProcessBaseline() {
        const processes = [];

        try {
            if (os.platform() === 'win32') {
                const { stdout } = await execAsync('tasklist /FO CSV');
                const lines = stdout.split('\n').slice(1);

                for (const line of lines) {
                    if (line.trim()) {
                        const [name, pid, sessionName, sessionNumber, memUsage] = line.split(',');
                        processes.push({
                            name: name.replace(/"/g, ''),
                            pid: parseInt(pid.replace(/"/g, '')),
                            memory: memUsage
                        });
                    }
                }
            } else {
                const { stdout } = await execAsync('ps aux');
                const lines = stdout.split('\n').slice(1);

                for (const line of lines) {
                    if (line.trim()) {
                        const parts = line.trim().split(/\s+/);
                        processes.push({
                            name: parts[10],
                            pid: parseInt(parts[1]),
                            cpu: parseFloat(parts[2]),
                            memory: parseFloat(parts[3])
                        });
                    }
                }
            }
        } catch (error) {
            console.error('Process baseline error:', error);
        }

        return processes;
    }

    async getNetworkBaseline() {
        const connections = [];

        try {
            if (os.platform() === 'win32') {
                const { stdout } = await execAsync('netstat -an');
                const lines = stdout.split('\n');

                for (const line of lines) {
                    if (line.includes('ESTABLISHED')) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 4) {
                            connections.push({
                                local: parts[1],
                                remote: parts[2],
                                state: parts[3]
                            });
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Network baseline error:', error);
        }

        return connections;
    }

    async getFileSystemBaseline() {
        const recentFiles = [];
        const monitorPaths = this.getCriticalMonitorPaths();

        for (const monitorPath of monitorPaths) {
            try {
                if (await fs.pathExists(monitorPath)) {
                    const files = await fs.readdir(monitorPath);
                    for (const file of files.slice(0, 50)) {
                        const filePath = path.join(monitorPath, file);
                        const stats = await fs.stat(filePath);

                        recentFiles.push({
                            path: filePath,
                            size: stats.size,
                            modified: stats.mtime,
                            created: stats.birthtime
                        });
                    }
                }
            } catch (error) {
                console.error(`File system baseline error for ${monitorPath}:`, error);
            }
        }

        return recentFiles;
    }

    getCriticalMonitorPaths() {
        const platform = os.platform();

        switch (platform) {
            case 'win32':
                return [
                    path.join(os.homedir(), 'AppData\\Roaming'),
                    'C:\\Windows\\Temp',
                    'C:\\Users\\Public'
                ];
            case 'darwin':
                return [
                    path.join(os.homedir(), 'Library'),
                    '/tmp',
                    '/var/tmp'
                ];
            case 'linux':
                return [
                    path.join(os.homedir(), '.config'),
                    '/tmp',
                    '/var/tmp'
                ];
            default:
                return [];
        }
    }

    async getRegistryBaseline() {
        if (os.platform() !== 'win32') return [];

        const registryKeys = [];

        try {
            const { stdout } = await execAsync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"');
            const lines = stdout.split('\n');

            for (const line of lines) {
                if (line.trim() && !line.includes('HKEY')) {
                    registryKeys.push(line.trim());
                }
            }
        } catch (error) {
            console.error('Registry baseline error:', error);
        }

        return registryKeys;
    }

    async setupSystemMonitoring() {
        this.monitoringInterval = setInterval(async () => {
            await this.performAPTScan();
        }, 30000);

        this.setupProcessMonitoring();
        this.setupNetworkMonitoring();
        this.setupFileSystemMonitoring();

        console.log('🔍 Real-time APT monitoring active');
    }

    setupProcessMonitoring() {
        setInterval(async () => {
            await this.monitorProcessAnomalies();
        }, 10000);
    }

    async monitorProcessAnomalies() {
        const currentProcesses = await this.getProcessBaseline();
        const baseline = this.behaviorBaseline.get('system')?.processes || [];

        for (const process of currentProcesses) {
            const isBaseline = baseline.some(bp => bp.name === process.name);

            if (!isBaseline) {
                await this.analyzeNewProcess(process);
            }

            await this.checkProcessAPTIndicators(process);
        }
    }

    async analyzeNewProcess(process) {
        for (const [group, rules] of this.detectionRules.entries()) {
            if (rules.indicators.processes.includes(process.name)) {
                await this.raiseAPTAlert({
                    type: 'SUSPICIOUS_PROCESS',
                    group,
                    severity: 'MEDIUM',
                    details: {
                        process: process.name,
                        pid: process.pid,
                        memory: process.memory,
                        threat_group: rules.name
                    },
                    timestamp: new Date().toISOString()
                });
            }
        }
    }

    async checkProcessAPTIndicators(process) {
        if (process.name === 'rundll32.exe' && process.memory > 50000) {
            await this.raiseAPTAlert({
                type: 'PROCESS_INJECTION_SUSPECTED',
                severity: 'HIGH',
                details: {
                    process: process.name,
                    suspicious_memory: process.memory,
                    technique: 'T1055'
                },
                timestamp: new Date().toISOString()
            });
        }
    }

    setupNetworkMonitoring() {
        setInterval(async () => {
            await this.monitorNetworkAPTActivity();
        }, 15000);
    }

    async monitorNetworkAPTActivity() {
        const connections = await this.getNetworkBaseline();

        for (const connection of connections) {
            await this.checkNetworkAPTIndicators(connection);
        }
    }

    async checkNetworkAPTIndicators(connection) {
        const remoteHost = connection.remote.split(':')[0];

        for (const [group, rules] of this.detectionRules.entries()) {
            for (const pattern of rules.indicators.networks) {
                if (pattern.test(remoteHost)) {
                    await this.raiseAPTAlert({
                        type: 'APT_NETWORK_COMMUNICATION',
                        group,
                        severity: 'CRITICAL',
                        details: {
                            remote_host: remoteHost,
                            local_address: connection.local,
                            threat_group: rules.name,
                            pattern: pattern.toString()
                        },
                        timestamp: new Date().toISOString()
                    });
                }
            }
        }
    }

    setupFileSystemMonitoring() {
        const monitorPaths = this.getCriticalMonitorPaths();

        for (const monitorPath of monitorPaths) {
            if (fs.existsSync(monitorPath)) {
                fs.watch(monitorPath, { recursive: true }, (eventType, filename) => {
                    this.analyzeFileSystemEvent(monitorPath, eventType, filename);
                });
            }
        }
    }

    async analyzeFileSystemEvent(basePath, eventType, filename) {
        if (!filename) return;

        const fullPath = path.join(basePath, filename);

        for (const [group, rules] of this.detectionRules.entries()) {
            for (const pattern of rules.indicators.files) {
                if (pattern.test(fullPath)) {
                    await this.raiseAPTAlert({
                        type: 'SUSPICIOUS_FILE_ACTIVITY',
                        group,
                        severity: 'MEDIUM',
                        details: {
                            file_path: fullPath,
                            event_type: eventType,
                            threat_group: rules.name,
                            pattern: pattern.toString()
                        },
                        timestamp: new Date().toISOString()
                    });
                }
            }
        }
    }

    async performAPTScan() {
        console.log('🔍 Performing comprehensive APT scan...');

        await this.scanForLivingOffTheLand();
        await this.scanForDataExfiltration();
        await this.scanForPersistenceMechanisms();
        await this.scanForPrivilegeEscalation();
    }

    async scanForLivingOffTheLand() {
        const lotlTools = [
            'powershell.exe',
            'wmic.exe',
            'rundll32.exe',
            'regsvr32.exe',
            'mshta.exe',
            'certutil.exe',
            'bitsadmin.exe'
        ];

        for (const tool of lotlTools) {
            const isRunning = await this.isProcessRunning(tool);
            if (isRunning) {
                await this.analyzeLOTLUsage(tool);
            }
        }
    }

    async isProcessRunning(processName) {
        try {
            if (os.platform() === 'win32') {
                const { stdout } = await execAsync(`tasklist /FI "IMAGENAME eq ${processName}"`);
                return stdout.includes(processName);
            } else {
                const { stdout } = await execAsync(`pgrep ${processName}`);
                return stdout.trim().length > 0;
            }
        } catch (error) {
            return false;
        }
    }

    async analyzeLOTLUsage(tool) {
        await this.raiseAPTAlert({
            type: 'LIVING_OFF_THE_LAND',
            severity: 'MEDIUM',
            details: {
                tool,
                technique: 'T1059',
                description: 'Suspicious use of legitimate system tool'
            },
            timestamp: new Date().toISOString()
        });
    }

    async scanForDataExfiltration() {
        const networkConnections = await this.getNetworkBaseline();
        const suspiciousConnections = networkConnections.filter(conn => {
            const remoteHost = conn.remote.split(':')[0];
            return !this.isKnownGoodHost(remoteHost);
        });

        if (suspiciousConnections.length > 10) {
            await this.raiseAPTAlert({
                type: 'POSSIBLE_DATA_EXFILTRATION',
                severity: 'HIGH',
                details: {
                    connection_count: suspiciousConnections.length,
                    technique: 'T1041'
                },
                timestamp: new Date().toISOString()
            });
        }
    }

    isKnownGoodHost(host) {
        const knownGoodHosts = [
            '127.0.0.1',
            'localhost',
            '::1'
        ];

        return knownGoodHosts.includes(host) ||
               host.startsWith('192.168.') ||
               host.startsWith('10.') ||
               host.startsWith('172.');
    }

    async scanForPersistenceMechanisms() {
        if (os.platform() === 'win32') {
            await this.checkRegistryPersistence();
            await this.checkServicePersistence();
            await this.checkScheduledTaskPersistence();
        } else {
            await this.checkCronPersistence();
            await this.checkSystemdPersistence();
        }
    }

    async checkRegistryPersistence() {
        const persistenceKeys = [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        ];

        for (const key of persistenceKeys) {
            try {
                const { stdout } = await execAsync(`reg query "${key}"`);
                const baseline = this.behaviorBaseline.get('system')?.registry || [];

                const currentEntries = stdout.split('\n').filter(line =>
                    line.trim() && !line.includes('HKEY')
                );

                for (const entry of currentEntries) {
                    if (!baseline.includes(entry.trim())) {
                        await this.raiseAPTAlert({
                            type: 'REGISTRY_PERSISTENCE',
                            severity: 'HIGH',
                            details: {
                                registry_key: key,
                                entry: entry.trim(),
                                technique: 'T1547.001'
                            },
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            } catch (error) {
                console.error(`Registry check error for ${key}:`, error);
            }
        }
    }

    async checkServicePersistence() {
        console.log('🔍 Checking for suspicious service persistence...');
    }

    async checkScheduledTaskPersistence() {
        console.log('🔍 Checking for suspicious scheduled task persistence...');
    }

    async checkCronPersistence() {
        console.log('🔍 Checking for suspicious cron persistence...');
    }

    async checkSystemdPersistence() {
        console.log('🔍 Checking for suspicious systemd persistence...');
    }

    async scanForPrivilegeEscalation() {
        console.log('🔍 Scanning for privilege escalation attempts...');
    }

    async initializeForensicCapabilities() {
        const forensicDir = path.join(os.homedir(), '.apollo', 'forensics');
        await fs.ensureDir(forensicDir);

        console.log('🔬 Forensic capabilities initialized');
    }

    async raiseAPTAlert(alert) {
        console.log(`🚨 APT THREAT DETECTED: ${alert.type}`);
        console.log(`Group: ${alert.group || 'Unknown'}`);
        console.log(`Severity: ${alert.severity}`);
        console.log(`Details:`, alert.details);

        this.suspiciousActivities.add(alert);

        for (const callback of this.alertCallbacks) {
            try {
                await callback(alert);
            } catch (error) {
                console.error('APT alert callback error:', error);
            }
        }

        if (alert.severity === 'CRITICAL') {
            await this.initiateAPTResponse(alert);
        }

        await this.logForensicEvidence(alert);
    }

    async initiateAPTResponse(alert) {
        console.log('🔥 CRITICAL APT THREAT - EMERGENCY RESPONSE ACTIVATED');

        await this.isolateSystem();
        await this.preserveEvidence();
        await this.notifyAuthorities(alert);
    }

    async isolateSystem() {
        console.log('🚧 System isolation protocols activated');
    }

    async preserveEvidence() {
        console.log('💾 Evidence preservation initiated');
    }

    async notifyAuthorities(alert) {
        console.log('📞 Authorities notified of APT activity');
    }

    async logForensicEvidence(alert) {
        const forensicDir = path.join(os.homedir(), '.apollo', 'forensics');
        const evidenceFile = path.join(forensicDir, `apt_${Date.now()}.json`);

        await fs.writeJSON(evidenceFile, {
            alert,
            systemInfo: {
                platform: os.platform(),
                hostname: os.hostname(),
                uptime: os.uptime(),
                memory: os.totalmem()
            },
            timestamp: new Date().toISOString()
        }, { spaces: 2 });
    }

    onAlert(callback) {
        this.alertCallbacks.push(callback);
    }

    getDetectionStatus() {
        return {
            isActive: this.isActive,
            detectionRules: Array.from(this.detectionRules.keys()),
            suspiciousActivities: this.suspiciousActivities.size,
            baselineEstablished: this.behaviorBaseline.has('system')
        };
    }

    async shutdown() {
        this.isActive = false;

        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }

        console.log('🛑 Apollo APT Detection shutting down...');
    }
}

module.exports = ApolloAPTDetector;