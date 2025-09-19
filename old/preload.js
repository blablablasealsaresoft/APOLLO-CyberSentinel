const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('apolloAPI', {
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