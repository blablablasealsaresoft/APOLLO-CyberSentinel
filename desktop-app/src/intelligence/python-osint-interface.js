/**
 * ============================================================================
 * APOLLO SENTINEL™ - PYTHON OSINT INTERFACE
 * Real-time integration with comprehensive Python OSINT sources
 * ============================================================================
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

class PythonOSINTInterface {
    constructor() {
        this.pythonScript = path.join(__dirname, 'realistic-osint-sources.py');
        this.isInitialized = false;
        this.lastStatsCache = null;
        this.lastStatsCacheTime = 0;
        this.cacheDuration = 5 * 60 * 1000; // 5 minutes cache
        
        console.log('🐍 Initializing Python OSINT Interface...');
        this.verifyPythonScript();
    }
    
    verifyPythonScript() {
        try {
            if (fs.existsSync(this.pythonScript)) {
                console.log('✅ Python OSINT script found and ready');
                this.isInitialized = true;
            } else {
                console.error('❌ Python OSINT script not found:', this.pythonScript);
                this.isInitialized = false;
            }
        } catch (error) {
            console.error('❌ Error verifying Python OSINT script:', error);
            this.isInitialized = false;
        }
    }
    
    async executePythonCommand(command, args = []) {
        return new Promise((resolve, reject) => {
            if (!this.isInitialized) {
                reject(new Error('Python OSINT interface not initialized'));
                return;
            }
            
            // Use python3 or python depending on system
            const pythonCmd = os.platform() === 'win32' ? 'python' : 'python3';
            const pythonArgs = [this.pythonScript, command, ...args];
            
            console.log(`🐍 Executing: ${pythonCmd} ${pythonArgs.join(' ')}`);
            
            const pythonProcess = spawn(pythonCmd, pythonArgs, {
                cwd: path.dirname(this.pythonScript),
                env: { 
                    ...process.env,
                    // Ensure user's API keys are available to Python
                    ALIENVAULT_OTX_API_KEY: process.env.ALIENVAULT_OTX_API_KEY || '762c4e5345c0c5b61c5896bc0e4de2a7fc52fc930b2209e5478c5367d646a777',
                    GITHUB_API_TOKEN: process.env.GITHUB_API_TOKEN || 'your_github_token_here',
                    ETHERSCAN_API_KEY: process.env.ETHERSCAN_API_KEY || 'VXVJX5N1UM44KUYMJDAVZBKJ3I5ATWDB6E',
                    NEWSAPI_KEY: process.env.NEWSAPI_KEY || '43f407a4aceb41c4a588224bfbf7f528',
                    HUNTER_IO_API_KEY: process.env.HUNTER_IO_API_KEY || '98df4bbbac21d3f2dfae2e657e09520b82b94bb0',
                    SHODAN_API_KEY: process.env.SHODAN_API_KEY || '',
                    VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',
                    ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY || '',
                    TRUTHFINDER_ACCOUNT_ID: process.env.TRUTHFINDER_ACCOUNT_ID || '26676',
                    TRUTHFINDER_MEMBER_ID: process.env.TRUTHFINDER_MEMBER_ID || '212900365'
                }
            });
            
            let outputData = '';
            let errorData = '';
            
            pythonProcess.stdout.on('data', (data) => {
                outputData += data.toString();
            });
            
            pythonProcess.stderr.on('data', (data) => {
                errorData += data.toString();
                console.warn('🐍 Python stderr:', data.toString());
            });
            
            pythonProcess.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(outputData);
                        console.log(`✅ Python OSINT command '${command}' completed successfully`);
                        resolve(result);
                    } catch (parseError) {
                        console.error('❌ Failed to parse Python output:', parseError);
                        reject(new Error(`Failed to parse Python output: ${parseError.message}`));
                    }
                } else {
                    console.error(`❌ Python process exited with code ${code}`);
                    console.error('Error output:', errorData);
                    reject(new Error(`Python process failed with code ${code}: ${errorData}`));
                }
            });
            
            pythonProcess.on('error', (error) => {
                console.error('❌ Failed to start Python process:', error);
                reject(error);
            });
        });
    }
    
    async getRealSourceStatistics() {
        try {
            // Use cache if available and recent
            const now = Date.now();
            if (this.lastStatsCache && (now - this.lastStatsCacheTime) < this.cacheDuration) {
                console.log('📊 Using cached OSINT source statistics');
                return this.lastStatsCache;
            }
            
            console.log('📊 Fetching real OSINT source statistics...');
            const stats = await this.executePythonCommand('stats');
            
            // Cache the results
            this.lastStatsCache = stats;
            this.lastStatsCacheTime = now;
            
            console.log(`✅ Retrieved statistics for ${stats.total_sources} OSINT sources`);
            return stats;
        } catch (error) {
            console.error('❌ Failed to get OSINT source statistics:', error);
            return {
                error: error.message,
                total_sources: 0,
                configured_sources: 0,
                free_sources: 0
            };
        }
    }
    
    async queryThreatIntelligence(indicator, indicatorType = 'domain') {
        try {
            console.log(`🔍 Querying threat intelligence for ${indicatorType}: ${indicator}`);
            const results = await this.executePythonCommand('threat', [
                '--indicator', indicator,
                '--type', indicatorType
            ]);
            
            console.log(`✅ Threat intelligence query completed for ${indicator}`);
            return results;
        } catch (error) {
            console.error(`❌ Threat intelligence query failed for ${indicator}:`, error);
            return {
                error: error.message,
                indicator: indicator,
                type: indicatorType,
                sources_queried: 0,
                results: {}
            };
        }
    }
    
    async queryDomainIntelligence(domain) {
        try {
            console.log(`🌐 Querying domain intelligence for: ${domain}`);
            const results = await this.executePythonCommand('domain', [
                '--indicator', domain
            ]);
            
            console.log(`✅ Domain intelligence query completed for ${domain}`);
            return results;
        } catch (error) {
            console.error(`❌ Domain intelligence query failed for ${domain}:`, error);
            return {
                error: error.message,
                domain: domain,
                sources_queried: 0,
                results: {}
            };
        }
    }
    
    async queryIPIntelligence(ip) {
        try {
            console.log(`🌍 Querying IP intelligence for: ${ip}`);
            const results = await this.executePythonCommand('ip', [
                '--indicator', ip
            ]);
            
            console.log(`✅ IP intelligence query completed for ${ip}`);
            return results;
        } catch (error) {
            console.error(`❌ IP intelligence query failed for ${ip}:`, error);
            return {
                error: error.message,
                ip: ip,
                sources_queried: 0,
                results: {}
            };
        }
    }
    
    async getComprehensiveThreatIntelligence() {
        try {
            console.log('🔥 Gathering comprehensive threat intelligence from all sources...');
            
            // Get statistics first
            const stats = await this.getRealSourceStatistics();
            
            // Query multiple threat intelligence indicators
            const threatIndicators = [
                { indicator: 'malware.com', type: 'domain' },
                { indicator: 'suspicious-site.org', type: 'domain' },
                { indicator: '192.168.1.1', type: 'ip' },
                { indicator: 'phishing-url.net', type: 'domain' }
            ];
            
            const threatResults = [];
            
            for (const { indicator, type } of threatIndicators) {
                try {
                    const result = await this.queryThreatIntelligence(indicator, type);
                    threatResults.push(result);
                } catch (error) {
                    console.warn(`⚠️ Failed to query ${indicator}:`, error.message);
                }
            }
            
            return {
                source: 'Comprehensive Python OSINT Intelligence',
                timestamp: new Date().toISOString(),
                statistics: stats,
                threat_queries: threatResults,
                total_indicators_analyzed: threatResults.length,
                sources_available: stats.total_sources,
                premium_sources_configured: stats.configured_sources
            };
            
        } catch (error) {
            console.error('❌ Comprehensive threat intelligence gathering failed:', error);
            return {
                error: error.message,
                source: 'Python OSINT Interface',
                timestamp: new Date().toISOString()
            };
        }
    }
    
    // Convert Python OSINT results to Apollo format for frontend compatibility
    async getRealThreats() {
        try {
            console.log('🎯 Converting Python OSINT data to Apollo threat format...');
            
            const comprehensive = await this.getComprehensiveThreatIntelligence();
            const threats = [];
            
            if (comprehensive.threat_queries) {
                for (const query of comprehensive.threat_queries) {
                    if (query.results) {
                        // Process AlienVault OTX results
                        if (query.results.alienvault_otx && !query.results.alienvault_otx.error) {
                            const otxData = query.results.alienvault_otx;
                            threats.push({
                                id: `otx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                                name: `Threat detected for ${otxData.indicator}`,
                                type: 'malware',
                                country: 'Unknown', // Will be enriched by geolocation
                                severity: otxData.reputation > 5 ? 'critical' : otxData.reputation > 2 ? 'high' : 'medium',
                                created: new Date().toISOString(),
                                description: `AlienVault OTX detected ${otxData.pulse_count} threat pulses for ${otxData.indicator}`,
                                source: 'AlienVault OTX (User API)',
                                confidence: 0.95,
                                raw_data: otxData
                            });
                        }
                        
                        // Process ThreatCrowd results
                        if (query.results.threatcrowd && !query.results.threatcrowd.error) {
                            const tcData = query.results.threatcrowd;
                            if (tcData.response_code === 1) { // Valid response
                                threats.push({
                                    id: `tc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                                    name: `ThreatCrowd intelligence for ${tcData.indicator}`,
                                    type: 'intelligence',
                                    country: 'Unknown',
                                    severity: 'medium',
                                    created: new Date().toISOString(),
                                    description: `ThreatCrowd found ${tcData.hashes?.length || 0} hashes, ${tcData.subdomains?.length || 0} subdomains`,
                                    source: 'ThreatCrowd',
                                    confidence: 0.85,
                                    raw_data: tcData
                                });
                            }
                        }
                    }
                }
            }
            
            console.log(`✅ Converted ${threats.length} Python OSINT results to Apollo format`);
            return threats;
            
        } catch (error) {
            console.error('❌ Failed to convert Python OSINT data:', error);
            return [];
        }
    }
    
    async getOSINTStats() {
        try {
            const stats = await this.getRealSourceStatistics();
            return {
                totalSources: stats.total_sources,
                configuredSources: stats.configured_sources,
                freeSources: stats.free_sources,
                premiumSources: stats.authentication_required,
                categories: Object.keys(stats.categories || {}),
                reliability: stats.reliability_distribution,
                queriesRun: stats.configured_sources,
                threatsFound: 0, // Will be updated by actual queries
                lastUpdate: new Date().toISOString()
            };
        } catch (error) {
            console.error('❌ Failed to get OSINT stats:', error);
            return {
                totalSources: 0,
                configuredSources: 0,
                error: error.message
            };
        }
    }
}

module.exports = PythonOSINTInterface;
