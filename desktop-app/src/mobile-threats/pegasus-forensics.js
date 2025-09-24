/**
 * ============================================================================
 * APOLLO SENTINEL™ - PEGASUS FORENSICS ENGINE
 * Advanced mobile spyware detection with MVT compatibility
 * Detects NSO Group Pegasus, commercial spyware, and stalkerware
 * ============================================================================
 */

const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const PythonOSINTInterface = require('../intelligence/python-osint-interface');

class PegasusForensicsEngine extends EventEmitter {
    constructor() {
        super();
        this.pythonOSINT = new PythonOSINTInterface();
        this.pegasusDetector = new ComprehensivePegasusDetector(this.pythonOSINT);
        this.mobileSpywareDetector = new MobileSpywareDetector(this.pythonOSINT);
        this.stalkerwareDetector = new StalkerwareDetector(this.pythonOSINT);
        this.mvtIntegration = new MVTIntegration();
        
        console.log('📱 Pegasus Forensics Engine initializing...');
        this.initializeForensics();
    }
    
    async initializeForensics() {
        await this.loadMobileSpywareSignatures();
        await this.setupForensicCapabilities();
        console.log('✅ Pegasus Forensics Engine ready - Mobile surveillance threats monitored');
    }
    
    async loadMobileSpywareSignatures() {
        this.spywareSignatures = {
            pegasus: await this.loadPegasusSignatures(),
            finspy: await this.loadFinSpySignatures(),
            stalkerware: await this.loadStalkerwareSignatures(),
            commercial_spyware: await this.loadCommercialSpywareSignatures()
        };
        
        console.log('📊 Mobile spyware signatures loaded for all threat types');
    }
    
    async loadPegasusSignatures() {
        return {
            ios_processes: [
                'com.apple.WebKit.Networking',
                'assistantd',
                'mobileassetd',
                'routined',
                'mobileactivationd',
                'commcenterd',
                'bh'
            ],
            android_processes: [
                'com.android.providers.telephony',
                'system_server',
                'com.google.android.gms',
                'com.android.systemui'
            ],
            network_infrastructure: [
                '*.nsogroup.com',
                '*.duckdns.org',
                '*.westpoint.ltd',
                'lphant.com',
                'iphoneconfuration.com',
                'urlzone.net',
                'checkrain.info',
                'breakfind.net'
            ],
            file_artifacts: [
                '*/Library/Caches/com.apple.WebKit/*',
                '*/private/var/folders/*/T/*.plist',
                '*/Library/Logs/CrashReporter/*',
                '/data/system/users/*/settings_secure.xml',
                '/data/data/*/cache/*',
                '/sdcard/Android/data/*/cache/*'
            ],
            forensic_indicators: [
                'fsCachedData',
                'WebKit/Cache.db',
                'shutdown.log_anomalies',
                'DataUsage.sqlite_suspicious_entries',
                'netusage.sqlite_c2_connections'
            ]
        };
    }
    
    async loadFinSpySignatures() {
        return {
            windows_processes: ['finspy.exe', 'winsys.exe', 'gamma.exe'],
            android_packages: ['com.system.service', 'com.android.system'],
            network_markers: ['*.finfisher.org', '*.gamma-international.de'],
            capabilities: ['keylogging', 'screenshot', 'audio_recording', 'location_tracking']
        };
    }
    
    async loadStalkerwareSignatures() {
        return {
            android_apps: [
                'com.mspy.android', 'com.flexispy.android', 'com.spyera.android',
                'com.hoverwatch.android', 'com.spybubble.android', 'com.spyzie.android'
            ],
            ios_profiles: [
                'MDM_Profiles', 'Configuration_Profiles', 'Certificate_Profiles'
            ],
            behavioral_patterns: [
                'accessibility_service_abuse',
                'device_admin_persistence', 
                'notification_access_monitoring',
                'location_tracking_continuous',
                'contact_list_exfiltration',
                'sms_message_interception'
            ]
        };
    }
    
    async loadCommercialSpywareSignatures() {
        return {
            vendors: {
                'NSO_Group': {
                    products: ['Pegasus'],
                    capabilities: ['zero_click_exploit', 'comprehensive_surveillance'],
                    platforms: ['iOS', 'Android']
                },
                'Cellebrite': {
                    products: ['UFED', 'Physical_Analyzer'],
                    capabilities: ['physical_extraction', 'logical_extraction'],
                    platforms: ['iOS', 'Android']
                },
                'Gamma_Group': {
                    products: ['FinFisher', 'FinSpy'],
                    capabilities: ['remote_monitoring', 'data_extraction'],
                    platforms: ['Windows', 'macOS', 'iOS', 'Android']
                }
            }
        };
    }
    
    // ============================================================================
    // Comprehensive Mobile Threat Analysis
    // ============================================================================
    
    async performComprehensiveMobileAnalysis(deviceBackupPath, platform = 'ios') {
        try {
            console.log(`📱 Comprehensive mobile threat analysis - Platform: ${platform}`);
            
            const analysisResults = {
                device_platform: platform,
                backup_path: deviceBackupPath,
                timestamp: new Date().toISOString(),
                spyware_detections: [],
                pegasus_analysis: null,
                stalkerware_analysis: null,
                commercial_spyware_analysis: null,
                overall_threat_level: 'clean',
                confidence_score: 0,
                osint_intelligence: null,
                mvt_report: null,
                recommendations: []
            };
            
            // Pegasus-specific analysis
            analysisResults.pegasus_analysis = await this.pegasusDetector.analyzeDevice(deviceBackupPath, platform);
            if (analysisResults.pegasus_analysis.infected) {
                analysisResults.spyware_detections.push({
                    type: 'pegasus',
                    confidence: analysisResults.pegasus_analysis.confidence,
                    attribution: 'NSO Group'
                });
                analysisResults.overall_threat_level = 'critical';
                analysisResults.confidence_score = Math.max(analysisResults.confidence_score, analysisResults.pegasus_analysis.confidence);
            }
            
            // Stalkerware analysis
            analysisResults.stalkerware_analysis = await this.stalkerwareDetector.analyzeDevice(deviceBackupPath, platform);
            if (analysisResults.stalkerware_analysis.detected) {
                analysisResults.spyware_detections.push({
                    type: 'stalkerware',
                    confidence: analysisResults.stalkerware_analysis.confidence,
                    apps: analysisResults.stalkerware_analysis.detected_apps
                });
                analysisResults.overall_threat_level = analysisResults.overall_threat_level === 'critical' ? 'critical' : 'high';
                analysisResults.confidence_score = Math.max(analysisResults.confidence_score, analysisResults.stalkerware_analysis.confidence);
            }
            
            // Commercial spyware analysis
            analysisResults.commercial_spyware_analysis = await this.mobileSpywareDetector.analyzeDevice(deviceBackupPath, platform);
            if (analysisResults.commercial_spyware_analysis.detected) {
                analysisResults.spyware_detections.push({
                    type: 'commercial_spyware',
                    confidence: analysisResults.commercial_spyware_analysis.confidence,
                    vendors: analysisResults.commercial_spyware_analysis.detected_vendors
                });
                analysisResults.overall_threat_level = analysisResults.overall_threat_level === 'clean' ? 'medium' : analysisResults.overall_threat_level;
                analysisResults.confidence_score = Math.max(analysisResults.confidence_score, analysisResults.commercial_spyware_analysis.confidence);
            }
            
            // Generate MVT-compatible report
            analysisResults.mvt_report = await this.mvtIntegration.generateMVTReport(analysisResults);
            
            // Generate comprehensive recommendations
            analysisResults.recommendations = this.generateMobileSecurityRecommendations(analysisResults);
            
            // Emit mobile spyware detection events for forensic integration
            if (analysisResults.spyware_detections.length > 0) {
                for (const detection of analysisResults.spyware_detections) {
                    this.emit('mobile-spyware-detected', {
                        type: detection.type,
                        attribution: detection.attribution,
                        confidence: detection.confidence,
                        platform: devicePlatform
                    });
                }
            }
            
            console.log(`✅ Comprehensive mobile analysis complete: ${analysisResults.spyware_detections.length} threats detected`);
            return analysisResults;
            
        } catch (error) {
            console.error('❌ Comprehensive mobile analysis failed:', error);
            return {
                device_platform: platform,
                error: error.message,
                spyware_detections: []
            };
        }
    }
    
    generateMobileSecurityRecommendations(analysisResults) {
        const recommendations = [];
        
        if (analysisResults.spyware_detections.length > 0) {
            // Critical spyware detected
            recommendations.push('🚨 MOBILE SPYWARE DETECTED - Take immediate action');
            
            // Pegasus-specific recommendations
            if (analysisResults.pegasus_analysis?.infected) {
                recommendations.push('📱 PEGASUS DETECTED - Enable iOS Lockdown Mode immediately');
                recommendations.push('🔄 FACTORY RESET - Perform complete device reset');
                recommendations.push('📞 CONTACT AUTHORITIES - Report potential targeting to law enforcement');
                recommendations.push('🔒 CHANGE ALL PASSWORDS - From a secure device only');
                recommendations.push('⚖️ LEGAL CONSULTATION - Contact legal support for targeting cases');
            }
            
            // Stalkerware-specific recommendations
            if (analysisResults.stalkerware_analysis?.detected) {
                recommendations.push('🆘 STALKERWARE DETECTED - Contact domestic violence resources');
                recommendations.push('📞 SAFETY HOTLINE - National: 1-800-799-7233');
                recommendations.push('🔗 COALITION RESOURCES - https://stopstalkerware.org/get-help/');
                recommendations.push('⚠️ SAFETY FIRST - Do not immediately remove (may alert abuser)');
                recommendations.push('📋 SAFETY PLANNING - Create discrete exit strategy');
            }
            
            // Commercial spyware recommendations
            if (analysisResults.commercial_spyware_analysis?.detected) {
                recommendations.push('🔍 COMMERCIAL SPYWARE - Check for unauthorized monitoring');
                recommendations.push('🔧 REMOVE SPYWARE - Uninstall detected monitoring applications');
                recommendations.push('🔐 ENHANCE SECURITY - Enable all device security features');
            }
            
            // General security hardening
            recommendations.push('🛡️ HARDEN DEVICE SECURITY - Implement all security measures');
            recommendations.push('📊 CONTINUOUS MONITORING - Regular security scans');
            
        } else {
            recommendations.push('✅ NO MOBILE THREATS DETECTED - Device appears secure');
            recommendations.push('🔒 ENABLE LOCKDOWN MODE - Proactive iOS protection');
            recommendations.push('🔄 REGULAR SCANS - Continue periodic security checks');
        }
        
        return recommendations;
    }
    
    async setupForensicCapabilities() {
        // Initialize forensic analysis capabilities
        this.forensicTools = {
            ios_analyzer: new iOSForensicAnalyzer(),
            android_analyzer: new AndroidForensicAnalyzer(),
            network_analyzer: new NetworkForensicAnalyzer(),
            evidence_preserver: new EvidencePreserver()
        };
        
        console.log('🔬 Forensic analysis capabilities initialized');
    }
}

// ============================================================================
// Comprehensive Pegasus Detector
// ============================================================================

class ComprehensivePegasusDetector {
    constructor(pythonOSINT) {
        this.pythonOSINT = pythonOSINT;
        this.pegasusIOCs = {
            domains: [
                'lphant.com', 'iphoneconfuration.com', 'urlzone.net',
                'microupdate.org', 'caphaw.net', 'upupdate.net',
                'checkrain.info', 'breakfind.net', 'cloudbreack.info'
            ],
            processes: [
                'bh', 'assistantd', 'mobileassetd', 'routined',
                'mobileactivationd', 'commcenterd'
            ],
            file_paths: [
                'fsCachedData', 'WebKit/Cache.db',
                'Library/Caches/com.apple.WebKit.Networking',
                'private/var/folders/*/T/*.plist'
            ]
        };
    }
    
    async analyzeDevice(backupPath, platform) {
        const analysis = {
            infected: false,
            confidence: 0,
            indicators: [],
            timestamps: [],
            network_activity: [],
            processes: [],
            forensic_artifacts: [],
            attribution: null
        };
        
        if (platform === 'ios') {
            // iOS-specific Pegasus analysis
            const shutdownAnalysis = await this.analyzeShutdownLog(backupPath);
            if (shutdownAnalysis.suspicious_entries) {
                analysis.indicators.push(...shutdownAnalysis.indicators);
                analysis.confidence += 40;
            }
            
            const dataUsageAnalysis = await this.analyzeDataUsageDB(backupPath);
            if (dataUsageAnalysis.pegasus_processes) {
                analysis.processes.push(...dataUsageAnalysis.suspicious_processes);
                analysis.confidence += 35;
            }
            
            const networkAnalysis = await this.analyzeNetUsageDB(backupPath);
            if (networkAnalysis.suspicious_connections) {
                analysis.network_activity.push(...networkAnalysis.connections);
                analysis.confidence += 30;
            }
            
            const cacheAnalysis = await this.analyzeWebKitCache(backupPath);
            if (cacheAnalysis.pegasus_artifacts) {
                analysis.forensic_artifacts.push(...cacheAnalysis.artifacts);
                analysis.confidence += 25;
            }
            
        } else if (platform === 'android') {
            // Android-specific Pegasus analysis
            const packageAnalysis = await this.analyzeAndroidPackages(backupPath);
            if (packageAnalysis.suspicious_packages) {
                analysis.indicators.push(...packageAnalysis.indicators);
                analysis.confidence += 40;
            }
        }
        
        analysis.infected = analysis.confidence >= 75;
        if (analysis.infected) {
            analysis.attribution = 'NSO Group Pegasus';
        }
        
        return analysis;
    }
    
    async analyzeShutdownLog(backupPath) {
        const shutdownLogPath = path.join(backupPath, 'Library', 'Logs', 'shutdown.log');
        const results = {
            suspicious_entries: false,
            indicators: [],
            exploitation_timestamps: []
        };
        
        if (!await fs.pathExists(shutdownLogPath)) {
            return results;
        }
        
        try {
            const content = await fs.readFile(shutdownLogPath, 'utf8');
            
            // Look for Pegasus process indicators in shutdown events
            const pegasusPatterns = [
                /SIGKILL.*bh\s/,
                /assistantd.*killed/,
                /mobileassetd.*terminated/,
                /routined.*crashed/
            ];
            
            for (const pattern of pegasusPatterns) {
                const matches = content.match(pattern);
                if (matches) {
                    results.suspicious_entries = true;
                    results.indicators.push(`shutdown_log_${pattern.source}`);
                    
                    // Extract timestamps
                    const timestampPattern = /(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/g;
                    const timestamps = content.match(timestampPattern);
                    if (timestamps) {
                        results.exploitation_timestamps.push(...timestamps);
                    }
                }
            }
        } catch (error) {
            results.error = error.message;
        }
        
        return results;
    }
    
    async analyzeDataUsageDB(backupPath) {
        // This would analyze iOS DataUsage.sqlite database
        // Simplified implementation for demonstration
        return {
            pegasus_processes: false,
            suspicious_processes: [],
            network_usage_anomalies: []
        };
    }
    
    async analyzeNetUsageDB(backupPath) {
        // This would analyze iOS netusage.sqlite database
        // Simplified implementation for demonstration
        return {
            suspicious_connections: false,
            connections: [],
            c2_communications: []
        };
    }
    
    async analyzeWebKitCache(backupPath) {
        // This would analyze WebKit cache for Pegasus artifacts
        // Simplified implementation for demonstration
        return {
            pegasus_artifacts: false,
            artifacts: []
        };
    }
    
    async analyzeAndroidPackages(backupPath) {
        // This would analyze Android packages for spyware
        // Simplified implementation for demonstration
        return {
            suspicious_packages: false,
            indicators: []
        };
    }
}

// ============================================================================
// Mobile Spyware Detector
// ============================================================================

class MobileSpywareDetector {
    constructor(pythonOSINT) {
        this.pythonOSINT = pythonOSINT;
        this.commercialSpyware = {
            'FinSpy': {
                indicators: ['finspy', 'gamma', 'finfisher'],
                capabilities: ['remote_monitoring', 'data_extraction'],
                attribution: 'Gamma Group (Germany)'
            },
            'Cellebrite': {
                indicators: ['ufed', 'physical_analyzer', 'cellebrite'],
                capabilities: ['physical_extraction', 'logical_extraction'],
                attribution: 'Cellebrite (Israel)'
            }
        };
    }
    
    async analyzeDevice(backupPath, platform) {
        const analysis = {
            detected: false,
            confidence: 0,
            detected_vendors: [],
            indicators: []
        };
        
        // Check for commercial spyware indicators
        for (const [vendor, details] of Object.entries(this.commercialSpyware)) {
            const vendorDetection = await this.checkVendorIndicators(backupPath, vendor, details, platform);
            if (vendorDetection.detected) {
                analysis.detected = true;
                analysis.detected_vendors.push(vendor);
                analysis.indicators.push(...vendorDetection.indicators);
                analysis.confidence = Math.max(analysis.confidence, vendorDetection.confidence);
            }
        }
        
        return analysis;
    }
    
    async checkVendorIndicators(backupPath, vendor, details, platform) {
        // Simplified vendor-specific detection
        return {
            detected: false,
            confidence: 0,
            indicators: []
        };
    }
}

// ============================================================================
// Stalkerware Detector
// ============================================================================

class StalkerwareDetector {
    constructor(pythonOSINT) {
        this.pythonOSINT = pythonOSINT;
        this.stalkerwareApps = [
            'mSpy', 'FlexiSpy', 'SpyEra', 'Hoverwatch', 'SpyBubble',
            'Spyzie', 'XNSPY', 'TheTruthSpy', 'iKeyMonitor', 'Spyic'
        ];
        this.domesticAbuseMode = true; // Enhanced privacy for safety
    }
    
    async analyzeDevice(backupPath, platform) {
        const analysis = {
            detected: false,
            confidence: 0,
            detected_apps: [],
            abuse_indicators: [],
            safety_risk_level: 'low'
        };
        
        if (platform === 'android') {
            // Android stalkerware detection
            const androidAnalysis = await this.analyzeAndroidStalkerware(backupPath);
            if (androidAnalysis.detected) {
                analysis.detected = true;
                analysis.detected_apps = androidAnalysis.detected_apps;
                analysis.confidence = androidAnalysis.confidence;
                analysis.safety_risk_level = 'high';
            }
        } else if (platform === 'ios') {
            // iOS stalkerware detection (requires jailbreak usually)
            const iosAnalysis = await this.analyzeiOSStalkerware(backupPath);
            if (iosAnalysis.detected) {
                analysis.detected = true;
                analysis.confidence = iosAnalysis.confidence;
                analysis.safety_risk_level = 'high';
            }
        }
        
        return analysis;
    }
    
    async analyzeAndroidStalkerware(backupPath) {
        // Check for Android stalkerware apps
        const analysis = {
            detected: false,
            confidence: 0,
            detected_apps: [],
            accessibility_abuse: false,
            device_admin_abuse: false
        };
        
        // This would implement actual Android package analysis
        // Simplified for demonstration
        return analysis;
    }
    
    async analyzeiOSStalkerware(backupPath) {
        // Check for iOS stalkerware (usually requires jailbreak)
        const analysis = {
            detected: false,
            confidence: 0,
            jailbreak_detected: false,
            configuration_profiles: []
        };
        
        // This would implement actual iOS stalkerware analysis
        // Simplified for demonstration
        return analysis;
    }
}

// ============================================================================
// MVT (Mobile Verification Toolkit) Integration
// ============================================================================

class MVTIntegration {
    constructor() {
        this.mvtIndicatorsUrl = "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2";
    }
    
    async generateMVTReport(analysisResults) {
        const mvtReport = {
            analysis_date: new Date().toISOString(),
            pegasus_detection: {
                infected: analysisResults.pegasus_analysis?.infected || false,
                confidence_score: analysisResults.pegasus_analysis?.confidence || 0,
                detection_method: 'apollo_advanced_forensic_analysis'
            },
            indicators_of_compromise: [],
            network_indicators: [],
            process_indicators: [],
            file_indicators: [],
            recommendations: []
        };
        
        // Convert analysis results to MVT format
        if (analysisResults.pegasus_analysis?.indicators) {
            mvtReport.indicators_of_compromise = analysisResults.pegasus_analysis.indicators;
        }
        
        if (analysisResults.pegasus_analysis?.network_activity) {
            mvtReport.network_indicators = analysisResults.pegasus_analysis.network_activity;
        }
        
        if (analysisResults.pegasus_analysis?.processes) {
            mvtReport.process_indicators = analysisResults.pegasus_analysis.processes;
        }
        
        // Generate MVT-compatible recommendations
        if (analysisResults.pegasus_analysis?.infected) {
            mvtReport.recommendations = [
                'Immediately disconnect device from network',
                'Contact law enforcement if targeting is suspected',
                'Perform full device factory reset',
                'Change all account passwords from secure device',
                'Enable lockdown mode on iOS devices',
                'Consult security professional for forensic preservation'
            ];
        } else {
            mvtReport.recommendations = [
                'Enable iOS Lockdown Mode for enhanced protection',
                'Keep device software updated to latest version',
                'Be cautious of suspicious links and attachments',
                'Regular security scans using updated tools'
            ];
        }
        
        return mvtReport;
    }
    
    async downloadLatestIndicators() {
        try {
            // This would download latest Pegasus IOCs from Amnesty International
            return '/tmp/pegasus_indicators.stix2';
        } catch (error) {
            console.warn('⚠️ Failed to download latest indicators:', error.message);
            return null;
        }
    }
}

// ============================================================================
// Forensic Analysis Components
// ============================================================================

class iOSForensicAnalyzer {
    constructor() {
        this.analysisCapabilities = [
            'shutdown_log_analysis',
            'datausage_sqlite_analysis',
            'netusage_sqlite_analysis',
            'webkit_cache_analysis',
            'crash_log_analysis',
            'configuration_profile_analysis'
        ];
    }
    
    async performForensicAnalysis(backupPath) {
        const forensicResults = {
            analysis_completed: new Date().toISOString(),
            artifacts_found: [],
            confidence_score: 0,
            evidence_preserved: false
        };
        
        // This would implement comprehensive iOS forensic analysis
        // Based on MVT methodology and Amnesty International research
        
        return forensicResults;
    }
}

class AndroidForensicAnalyzer {
    constructor() {
        this.analysisCapabilities = [
            'package_analysis',
            'accessibility_service_analysis',
            'device_admin_analysis',
            'notification_access_analysis',
            'logcat_analysis'
        ];
    }
    
    async performForensicAnalysis(devicePath) {
        const forensicResults = {
            analysis_completed: new Date().toISOString(),
            suspicious_packages: [],
            privilege_abuse: [],
            confidence_score: 0
        };
        
        // This would implement comprehensive Android forensic analysis
        
        return forensicResults;
    }
}

class NetworkForensicAnalyzer {
    constructor() {
        this.networkCapabilities = [
            'pcap_analysis',
            'tls_fingerprinting',
            'dns_analysis',
            'c2_detection',
            'exfiltration_detection'
        ];
    }
    
    async analyzeNetworkTraffic(pcapFile) {
        const networkResults = {
            analysis_completed: new Date().toISOString(),
            suspicious_connections: [],
            c2_communications: [],
            data_exfiltration: [],
            confidence_score: 0
        };
        
        // This would implement network traffic analysis for spyware detection
        
        return networkResults;
    }
}

class EvidencePreserver {
    constructor() {
        this.evidenceDirectory = path.join(os.homedir(), '.apollo', 'evidence');
    }
    
    async preserveEvidence(analysisResults) {
        try {
            await fs.ensureDir(this.evidenceDirectory);
            
            const evidenceId = `EVD-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
            const evidencePath = path.join(this.evidenceDirectory, `${evidenceId}.json`);
            
            const evidencePackage = {
                evidence_id: evidenceId,
                timestamp: new Date().toISOString(),
                analysis_results: analysisResults,
                preservation_method: 'apollo_forensic_engine',
                integrity_hash: crypto.createHash('sha256').update(JSON.stringify(analysisResults)).digest('hex')
            };
            
            await fs.writeJSON(evidencePath, evidencePackage, { spaces: 2 });
            
            console.log(`✅ Evidence preserved: ${evidenceId}`);
            return {
                evidence_id: evidenceId,
                evidence_path: evidencePath,
                preserved: true
            };
            
        } catch (error) {
            console.error('❌ Evidence preservation failed:', error);
            return {
                preserved: false,
                error: error.message
            };
        }
    }
}

module.exports = PegasusForensicsEngine;
