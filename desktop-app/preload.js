const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Core protection APIs
    getProtectionStatus: () => ipcRenderer.invoke('get-protection-status'),
    toggleProtection: () => ipcRenderer.invoke('toggle-protection'),
    runDeepScan: () => ipcRenderer.invoke('run-deep-scan'),
    analyzeContract: (address) => ipcRenderer.invoke('analyze-contract', address),
    checkTransaction: (hash) => ipcRenderer.invoke('check-transaction', hash),
    emergencyIsolation: () => ipcRenderer.invoke('emergency-isolation'),
    loadConfig: () => ipcRenderer.invoke('load-config'),
    saveConfig: (config) => ipcRenderer.invoke('save-config', config),

    // Enhanced OSINT and AI Oracle APIs
    checkPhishingURL: (url) => ipcRenderer.invoke('check-phishing-url', url),
    analyzeWithAI: (indicator, context) => ipcRenderer.invoke('analyze-with-ai', indicator, context),
    getOSINTStats: () => ipcRenderer.invoke('get-osint-stats'),
    analyzeSmartContract: (address, bytecode) => ipcRenderer.invoke('analyze-smart-contract', address, bytecode),
    initializeWalletConnect: () => ipcRenderer.invoke('initialize-walletconnect'),
    waitForWalletConnection: () => ipcRenderer.invoke('wait-wallet-connection'),
    getCryptoRandomValues: (length) => ipcRenderer.invoke('crypto-get-random-values', length),

    // Real-time data APIs for dashboard
    getEngineStats: () => ipcRenderer.invoke('get-engine-stats'),
    getRecentActivity: () => ipcRenderer.invoke('get-recent-activity'),
    getAIOracleStats: () => ipcRenderer.invoke('get-ai-oracle-stats'),
    getNetworkStats: () => ipcRenderer.invoke('get-network-stats'),
    getSystemPerformance: () => ipcRenderer.invoke('get-system-performance'),

    // Security scanning operations
    scanForMalware: () => ipcRenderer.invoke('scan-for-malware'),
    scanForDDoS: () => ipcRenderer.invoke('scan-for-ddos'),

    // Real OSINT intelligence operations
    refreshThreatFeeds: () => ipcRenderer.invoke('refresh-threat-feeds'),
    refreshOSINT: () => ipcRenderer.invoke('refresh-threat-feeds'),
    getThreatIntelligence: () => ipcRenderer.invoke('get-threat-intelligence'),
    queryIOC: (indicator, type) => ipcRenderer.invoke('query-ioc', indicator, type),
    executeEmergencyIsolation: () => ipcRenderer.invoke('emergency-isolation'),
    
    // Evidence capture and quarantine operations
    captureEvidence: () => ipcRenderer.invoke('capture-evidence'),
    quarantineThreats: () => ipcRenderer.invoke('quarantine-threats'),
    refreshThreats: () => ipcRenderer.invoke('refresh-threat-feeds'),

    // Real-time event listeners
    onThreatDetected: (callback) => ipcRenderer.on('threat-detected', callback),
    onEngineStats: (callback) => ipcRenderer.on('engine-stats-updated', callback),
    onActivityUpdated: (callback) => ipcRenderer.on('activity-updated', callback),
    onProtectionToggled: (callback) => ipcRenderer.on('protection-toggled', callback),
    onScanStarted: (callback) => ipcRenderer.on('scan-started', callback),
    onScanCompleted: (callback) => ipcRenderer.on('scan-completed', callback),
    onEmergencyIsolation: (callback) => ipcRenderer.on('emergency-isolation', callback),
    onThreatBlocked: (callback) => ipcRenderer.on('threat-blocked', callback),
    onWalletConnectSessionApproved: (callback) => ipcRenderer.on('walletconnect-session-approved', callback),
    onApolloWalletConnectSuccess: (callback) => ipcRenderer.on('apollo-walletconnect-session-success', callback),
    onApolloWalletConnected: (callback) => ipcRenderer.on('apollo-wallet-connected', callback),
    onApolloSessionApproved: (callback) => ipcRenderer.on('apollo-session-approved', callback),
        onWalletConnectProposalRejected: (callback) => ipcRenderer.on('walletconnect-proposal-rejected', callback),
        onWalletConnectSessionRejected: (callback) => ipcRenderer.on('walletconnect-session-rejected', callback),
        
        // Scan progress and reporting event listeners
        onScanProgress: (callback) => ipcRenderer.on('scan-progress', callback),
        onScanCompleted: (callback) => ipcRenderer.on('scan-completed', callback),

    // Legacy support
    onThreatAlert: (callback) => ipcRenderer.on('threat-alert', callback),
    onCryptoAlert: (callback) => ipcRenderer.on('crypto-alert', callback),
    onAPTAlert: (callback) => ipcRenderer.on('apt-alert', callback),
    onShowSettings: (callback) => ipcRenderer.on('show-settings', callback),
    onShowActivityLog: (callback) => ipcRenderer.on('show-activity-log', callback),

    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});

// Legacy support for apolloAPI
contextBridge.exposeInMainWorld('apolloAPI', {
    getProtectionStatus: () => ipcRenderer.invoke('get-protection-status'),
    toggleProtection: () => ipcRenderer.invoke('toggle-protection'),
    runDeepScan: () => ipcRenderer.invoke('run-deep-scan'),
    analyzeContract: (address) => ipcRenderer.invoke('analyze-contract', address),
    checkTransaction: (hash) => ipcRenderer.invoke('check-transaction', hash),
    emergencyIsolation: () => ipcRenderer.invoke('emergency-isolation'),
    loadConfig: () => ipcRenderer.invoke('load-config'),
    saveConfig: (config) => ipcRenderer.invoke('save-config', config),
    checkPhishingURL: (url) => ipcRenderer.invoke('check-phishing-url', url),
    analyzeWithAI: (indicator, context) => ipcRenderer.invoke('analyze-with-ai', indicator, context),
    getOSINTStats: () => ipcRenderer.invoke('get-osint-stats'),
    getThreatIntelligence: () => ipcRenderer.invoke('get-threat-intelligence'),
    refreshOSINT: () => ipcRenderer.invoke('refresh-threat-feeds'),
    executeEmergencyIsolation: () => ipcRenderer.invoke('emergency-isolation'),
    analyzeSmartContract: (address, bytecode) => ipcRenderer.invoke('analyze-smart-contract', address, bytecode),
    refreshThreats: () => ipcRenderer.invoke('refresh-threat-feeds'),
    getNetworkStats: () => ipcRenderer.invoke('get-network-stats'),
    getSystemPerformance: () => ipcRenderer.invoke('get-system-performance'),
    scanForMalware: () => ipcRenderer.invoke('scan-for-malware'),
    scanForDDoS: () => ipcRenderer.invoke('scan-for-ddos'),
    
    // Comprehensive Python OSINT Intelligence
    queryDomainIntelligence: (domain) => ipcRenderer.invoke('query-domain-intelligence', domain),
    analyzeCryptoTransaction: (txHash, blockchain) => ipcRenderer.invoke('analyze-crypto-transaction', txHash, blockchain),
    queryThreatIntelligence: (indicator, type) => ipcRenderer.invoke('query-threat-intelligence', indicator, type),
    getComprehensiveOSINTStats: () => ipcRenderer.invoke('get-osint-stats'),
    
    // Advanced Nation-State Threat Analysis (NEW)
    analyzeNationStateThreat: (indicator, type, context) => ipcRenderer.invoke('analyze-nation-state-threat', indicator, type, context),
    analyzeAPTThreat: (indicator, type) => ipcRenderer.invoke('analyze-apt-threat', indicator, type),
    analyzeCryptoThreat: (indicator, type) => ipcRenderer.invoke('analyze-crypto-threat', indicator, type),
    analyzeMobileSpyware: (backupPath, platform) => ipcRenderer.invoke('analyze-mobile-spyware', backupPath, platform),
    
    // Enterprise Biometric Authentication (REVOLUTIONARY)
    authenticateForWallet: (walletType, securityLevel) => ipcRenderer.invoke('authenticate-for-wallet', walletType, securityLevel),
    authorizeWalletConnection: (walletProvider, walletAddress, connectionType) => ipcRenderer.invoke('authorize-wallet-connection', walletProvider, walletAddress, connectionType),
    getAuthStatus: () => ipcRenderer.invoke('get-auth-status'),
    getTelemetryAnalytics: () => ipcRenderer.invoke('get-telemetry-analytics'),
    
    // Advanced Forensic Evidence Capture (NIST SP 800-86 COMPLIANT)
    captureForensicEvidence: (incidentId, evidenceType, priority) => ipcRenderer.invoke('capture-forensic-evidence', incidentId, evidenceType, priority),
    analyzeVolatileThreat: (threatIndicator, analysisType) => ipcRenderer.invoke('analyze-volatile-threat', threatIndicator, analysisType),
    analyzeMemoryForensics: (memoryDumpPath) => ipcRenderer.invoke('analyze-memory-forensics', memoryDumpPath),
    performLiveTriage: () => ipcRenderer.invoke('perform-live-triage'),

    onThreatAlert: (callback) => ipcRenderer.on('threat-alert', callback),
    onCryptoAlert: (callback) => ipcRenderer.on('crypto-alert', callback),
    onAPTAlert: (callback) => ipcRenderer.on('apt-alert', callback),
    onProtectionToggled: (callback) => ipcRenderer.on('protection-toggled', callback),
    onScanStarted: (callback) => ipcRenderer.on('scan-started', callback),
    onScanCompleted: (callback) => ipcRenderer.on('scan-completed', callback),
    onEmergencyIsolation: (callback) => ipcRenderer.on('emergency-isolation', callback),
    onThreatBlocked: (callback) => ipcRenderer.on('threat-blocked', callback),
    onShowSettings: (callback) => ipcRenderer.on('show-settings', callback),
    onShowActivityLog: (callback) => ipcRenderer.on('show-activity-log', callback),

    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});