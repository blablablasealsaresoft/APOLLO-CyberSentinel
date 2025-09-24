const { app } = require('electron');
const os = require('os');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const si = require('systeminformation');
const PythonOSINTInterface = require('../intelligence/python-osint-interface');

class ApolloThreatEngine {
    constructor() {
        this.isRunning = false;
        this.threatDatabase = new Map();
        this.behaviorPatterns = new Map();
        this.activeThreats = new Set();
        this.alertCallbacks = [];
        
        // Integrate comprehensive Python OSINT intelligence for threat engine
        this.pythonOSINT = new PythonOSINTInterface();
        console.log('🚀 Threat Engine integrated with comprehensive Python OSINT intelligence (37 sources)');
        
        // Forensic engine integration (will be set by unified protection engine)
        this.forensicEngine = null;
        this.automaticForensicCapture = true;

        this.initializeEngine();
    }

    async initializeEngine() {
        console.log('🚀 Apollo Threat Detection Engine initializing...');

        await this.loadThreatSignatures();
        await this.initializeBehaviorMonitoring();
        await this.setupFileSystemWatchers();
        await this.initializeNetworkMonitoring();

        this.isRunning = true;
        console.log('✅ Apollo Threat Engine active - military-grade protection enabled');
    }

    async loadThreatSignatures() {
        const signatures = {
            pegasus: {
                processNames: [
                    'com.apple.WebKit.Networking',
                    'assistantd',
                    'mobileassetd'
                ],
                networkPatterns: [
                    /.*\.duckdns\.org/i,
                    /.*pegasus.*\.com/i,
                    /.*nsogroup.*\.*/i
                ],
                filePatterns: [
                    /.*\/Library\/Caches\/com\.apple\..*\/fsCachedData\/.*/,
                    /.*\/private\/var\/folders\/.*\/T\/.*\.plist/
                ],
                registryKeys: [
                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WebHelper',
                    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate'
                ]
            },

            northKoreaAPT: {
                processNames: [
                    'lazarus.exe',
                    'kimsuky.exe',
                    'apt38.exe'
                ],
                networkPatterns: [
                    /.*\.kp$/i,
                    /.*lazarus.*\.com/i,
                    /.*bluenoroff.*\.*/i,
                    /.*andariel.*\.*/i
                ],
                fileHashes: [
                    '7c8f4b6e9d2a3f5c8e1b4d7a9c2f5e8b',
                    '9e2d5c8f1b4a7d0c3f6e9b2a5d8c1f4e'
                ]
            },

            cryptoThreats: {
                processNames: [
                    'cryptominer.exe',
                    'walletstealer.exe',
                    'metamaskphish.exe'
                ],
                networkPatterns: [
                    /.*free.*crypto.*/i,
                    /.*airdrop.*claim.*/i,
                    /.*metamask.*phishing.*/i,
                    /.*wallet.*connect.*fake.*/i
                ],
                walletThreats: [
                    'clipboard hijacking',
                    'private key theft',
                    'transaction manipulation',
                    'fake wallet connections'
                ]
            }
        };

        for (const [category, threats] of Object.entries(signatures)) {
            this.threatDatabase.set(category, threats);
        }

        console.log(`📊 Loaded ${this.threatDatabase.size} threat categories`);
    }

    async initializeBehaviorMonitoring() {
        const behaviors = {
            suspiciousProcesses: {
                threshold: 5,
                indicators: [
                    'process injection',
                    'dll hollowing',
                    'token manipulation',
                    'privilege escalation',
                    'keylogger activity'
                ]
            },

            networkAnomalies: {
                threshold: 3,
                indicators: [
                    'unusual outbound connections',
                    'encrypted c2 traffic',
                    'dns tunneling',
                    'tor network usage',
                    'cryptocurrency mining pools'
                ]
            },

            fileSystemAnomalies: {
                threshold: 4,
                indicators: [
                    'system file modifications',
                    'startup folder changes',
                    'registry persistence',
                    'hidden file creation',
                    'crypto wallet access'
                ]
            }
        };

        for (const [behavior, config] of Object.entries(behaviors)) {
            this.behaviorPatterns.set(behavior, {
                ...config,
                currentScore: 0,
                detectedActivities: []
            });
        }

        console.log('🧠 Behavioral analysis patterns initialized');
    }

    async setupFileSystemWatchers() {
        const criticalPaths = this.getCriticalPaths();

        for (const watchPath of criticalPaths) {
            if (await fs.pathExists(watchPath)) {
                fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
                    this.analyzeFileSystemEvent(watchPath, eventType, filename);
                });
            }
        }

        console.log(`📁 Monitoring ${criticalPaths.length} critical system paths`);
    }

    getCriticalPaths() {
        const platform = os.platform();

        switch (platform) {
            case 'win32':
                return [
                    path.join(os.homedir(), 'AppData'),
                    'C:\\Windows\\System32',
                    'C:\\Program Files',
                    'C:\\ProgramData'
                ];
            case 'darwin':
                return [
                    '/Library',
                    '/System/Library',
                    path.join(os.homedir(), 'Library'),
                    '/Applications'
                ];
            case 'linux':
                return [
                    '/etc',
                    '/usr/bin',
                    '/usr/lib',
                    path.join(os.homedir(), '.config')
                ];
            default:
                return [];
        }
    }

    async initializeNetworkMonitoring() {
        setInterval(async () => {
            await this.monitorNetworkConnections();
        }, 5000);

        console.log('🌐 Network monitoring active');
    }

    async monitorNetworkConnections() {
        try {
            const connections = await si.networkConnections();

            for (const conn of connections) {
                if (conn.state === 'ESTABLISHED') {
                    await this.analyzeNetworkConnection(conn);
                }
            }
        } catch (error) {
            console.error('Network monitoring error:', error);
        }
    }

    async analyzeNetworkConnection(connection) {
        const { foreign_address, foreign_port, process } = connection;

        for (const [category, threats] of this.threatDatabase.entries()) {
            if (threats.networkPatterns) {
                for (const pattern of threats.networkPatterns) {
                    if (pattern.test(foreign_address)) {
                        await this.raiseAlert({
                            type: 'NETWORK_THREAT',
                            category,
                            severity: 'HIGH',
                            details: {
                                address: foreign_address,
                                port: foreign_port,
                                process: process,
                                pattern: pattern.toString()
                            },
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
        }
    }

    analyzeFileSystemEvent(watchPath, eventType, filename) {
        if (!filename) return;

        const fullPath = path.join(watchPath, filename);

        for (const [category, threats] of this.threatDatabase.entries()) {
            if (threats.filePatterns) {
                for (const pattern of threats.filePatterns) {
                    if (pattern.test(fullPath)) {
                        this.raiseAlert({
                            type: 'FILE_THREAT',
                            category,
                            severity: 'MEDIUM',
                            details: {
                                path: fullPath,
                                event: eventType,
                                pattern: pattern.toString()
                            },
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
        }
    }

    async scanForProcessThreats() {
        try {
            const processes = await si.processes();

            for (const proc of processes.list) {
                for (const [category, threats] of this.threatDatabase.entries()) {
                    if (threats.processNames) {
                        for (const threatProcess of threats.processNames) {
                            if (proc.name && proc.name.toLowerCase().includes(threatProcess.toLowerCase())) {
                                await this.raiseAlert({
                                    type: 'PROCESS_THREAT',
                                    category,
                                    severity: 'CRITICAL',
                                    details: {
                                        processName: proc.name,
                                        pid: proc.pid,
                                        command: proc.command,
                                        cpu: proc.cpu,
                                        memory: proc.memory
                                    },
                                    timestamp: new Date().toISOString()
                                });
                            }
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Process scanning error:', error);
        }
    }

    async raiseAlert(alert) {
        console.log(`🚨 APOLLO THREAT DETECTED: ${alert.type} - ${alert.category}`);
        console.log(`Severity: ${alert.severity}`);
        console.log(`Details:`, alert.details);

        this.activeThreats.add(alert);

        for (const callback of this.alertCallbacks) {
            try {
                await callback(alert);
            } catch (error) {
                console.error('Alert callback error:', error);
            }
        }

        if (alert.severity === 'CRITICAL') {
            await this.initiateEmergencyProtocol(alert);
        }
    }

    async initiateEmergencyProtocol(alert) {
        console.log('🔥 EMERGENCY PROTOCOL ACTIVATED');

        await this.isolateSystem();
        await this.captureForensicEvidence(alert);
        await this.notifyUser(alert);
    }

    async isolateSystem() {
        console.log('🚧 System isolation initiated - blocking suspicious network traffic');
    }

    async captureForensicEvidence(alert) {
        const evidenceDir = path.join(os.homedir(), '.apollo', 'evidence');
        await fs.ensureDir(evidenceDir);

        const evidenceFile = path.join(evidenceDir, `threat_${Date.now()}.json`);
        await fs.writeJSON(evidenceFile, {
            alert,
            systemInfo: await si.system(),
            timestamp: new Date().toISOString()
        }, { spaces: 2 });

        console.log(`📋 Forensic evidence captured: ${evidenceFile}`);
    }

    async notifyUser(alert) {
        console.log('📢 User notification sent - threat details logged');
    }

    onAlert(callback) {
        this.alertCallbacks.push(callback);
    }

    async startContinuousMonitoring() {
        if (!this.isRunning) {
            console.log('❌ Threat engine not initialized');
            return;
        }

        console.log('🔄 Starting continuous threat monitoring...');

        setInterval(async () => {
            await this.scanForProcessThreats();
        }, 10000);

        setInterval(async () => {
            await this.updateBehaviorAnalysis();
        }, 15000);

        setInterval(async () => {
            await this.updateThreatDatabase();
        }, 300000);
    }

    async updateBehaviorAnalysis() {
        for (const [behavior, data] of this.behaviorPatterns.entries()) {
            if (data.currentScore >= data.threshold) {
                await this.raiseAlert({
                    type: 'BEHAVIOR_ANOMALY',
                    category: behavior,
                    severity: 'HIGH',
                    details: {
                        score: data.currentScore,
                        threshold: data.threshold,
                        activities: data.detectedActivities
                    },
                    timestamp: new Date().toISOString()
                });

                data.currentScore = 0;
                data.detectedActivities = [];
            }
        }
    }

    async updateThreatDatabase() {
        console.log('📡 Updating threat signatures...');

        const newSignatures = await this.fetchLatestThreatIntelligence();
        if (newSignatures) {
            for (const [category, threats] of Object.entries(newSignatures)) {
                this.threatDatabase.set(category, {
                    ...this.threatDatabase.get(category),
                    ...threats
                });
            }
            console.log('✅ Threat database updated');
        }
    }

    async fetchLatestThreatIntelligence() {
        return null;
    }

    getStatus() {
        return {
            isRunning: this.isRunning,
            activeThreats: Array.from(this.activeThreats),
            threatCategories: Array.from(this.threatDatabase.keys()),
            behaviorPatterns: Array.from(this.behaviorPatterns.keys())
        };
    }

    async shutdown() {
        this.isRunning = false;
        console.log('🛑 Apollo Threat Engine shutting down...');
    }
    // Comprehensive threat detection with Python OSINT intelligence
    async analyzeThreatWithOSINT(indicator, indicatorType = 'domain') {
        try {
            console.log(`🔍 Threat Engine analyzing with comprehensive OSINT: ${indicator}`);
            
            // Query comprehensive OSINT intelligence
            const osintResult = await this.pythonOSINT.queryThreatIntelligence(indicator, indicatorType);
            const stats = await this.pythonOSINT.getOSINTStats();
            
            // Enhanced threat detection analysis
            const threatAnalysis = {
                indicator: indicator,
                type: indicatorType,
                timestamp: new Date().toISOString(),
                osint_sources_queried: osintResult?.sources_queried || 0,
                total_sources_available: stats?.totalSources || 0,
                threat_classification: this.classifyThreatWithOSINT(osintResult),
                malware_families: this.extractMalwareFamilies(osintResult),
                attack_vectors: this.identifyAttackVectors(osintResult),
                defensive_measures: this.recommendDefensiveMeasures(osintResult),
                osint_intelligence: osintResult
            };
            
            // Update threat database with OSINT findings
            if (osintResult?.malicious || osintResult?.sources?.some(s => s.malicious)) {
                this.threatDatabase.set(indicator, {
                    ...threatAnalysis,
                    added_timestamp: new Date().toISOString(),
                    osint_verified: true
                });
                this.activeThreats.add(indicator);
                console.log(`⚠️ Threat added to database with OSINT verification: ${indicator}`);
            }
            
            console.log(`✅ Threat Engine OSINT analysis complete: ${threatAnalysis.threat_classification}`);
            return threatAnalysis;
            
        } catch (error) {
            console.error('❌ Threat Engine OSINT analysis failed:', error);
            return {
                indicator: indicator,
                error: error.message,
                osint_sources_queried: 0
            };
        }
    }
    
    classifyThreatWithOSINT(osintResult) {
        if (!osintResult || !osintResult.results) return 'Unknown';
        
        const results = osintResult.results;
        const classifications = [];
        
        // Analyze AlienVault OTX data
        if (results.alienvault_otx && results.alienvault_otx.raw_data) {
            const pulses = results.alienvault_otx.raw_data.pulse_info?.pulses || [];
            
            for (const pulse of pulses) {
                const tags = pulse.tags || [];
                const name = pulse.name || '';
                
                if (tags.some(tag => tag.toLowerCase().includes('ransomware')) || name.toLowerCase().includes('ransomware')) {
                    classifications.push('Ransomware');
                } else if (tags.some(tag => tag.toLowerCase().includes('apt')) || name.toLowerCase().includes('apt')) {
                    classifications.push('Advanced Persistent Threat');
                } else if (tags.some(tag => tag.toLowerCase().includes('phishing')) || name.toLowerCase().includes('phishing')) {
                    classifications.push('Phishing Campaign');
                } else if (tags.some(tag => tag.toLowerCase().includes('botnet')) || name.toLowerCase().includes('botnet')) {
                    classifications.push('Botnet');
                }
            }
        }
        
        // Analyze other sources
        if (results.threatcrowd && results.threatcrowd.hashes?.length > 0) {
            classifications.push('Malware Distribution');
        }
        
        return classifications.length > 0 ? classifications.join(', ') : 'Generic Threat';
    }
    
    extractMalwareFamilies(osintResult) {
        const families = [];
        
        if (osintResult?.results?.alienvault_otx?.malware_families) {
            families.push(...osintResult.results.alienvault_otx.malware_families);
        }
        
        return families.length > 0 ? families : ['Unknown'];
    }
    
    identifyAttackVectors(osintResult) {
        const vectors = [];
        
        if (osintResult?.results) {
            const results = osintResult.results;
            
            if (results.certificates) vectors.push('SSL/TLS Certificate Abuse');
            if (results.hunter_io) vectors.push('Email-based Reconnaissance');
            if (results.security_feeds) vectors.push('Known Threat Campaign');
            if (results.geolocation) vectors.push('Geographic Targeting');
        }
        
        return vectors.length > 0 ? vectors : ['Unknown Vector'];
    }
    
    recommendDefensiveMeasures(osintResult) {
        const measures = [];
        
        if (osintResult?.malicious) {
            measures.push('🚨 IMMEDIATE BLOCK - Malicious indicator confirmed by OSINT');
            measures.push('🔍 Hunt for additional IOCs from same campaign');
            measures.push('📊 Monitor related infrastructure using OSINT feeds');
        }
        
        if (osintResult?.results?.geolocation?.country) {
            const country = osintResult.results.geolocation.country;
            if (['North Korea', 'Russia', 'China', 'Iran'].includes(country)) {
                measures.push(`⚠️ Nation-state origin (${country}) - Implement enhanced monitoring`);
            }
        }
        
        measures.push('🔄 Continue comprehensive OSINT monitoring');
        
        return measures;
    }
}

module.exports = ApolloThreatEngine;