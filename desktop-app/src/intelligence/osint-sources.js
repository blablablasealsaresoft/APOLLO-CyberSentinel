const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');
const PythonOSINTInterface = require('./python-osint-interface');

class OSINTThreatIntelligence {
    constructor() {
        this.apiKeys = this.loadApiKeys();
        this.threatSources = this.initializeThreatSources();
        this.cache = new Map();
        this.cacheTimeout = 300000; // 5 minutes
        this.stats = {
            queriesRun: 0,
            threatsFound: 0,
            iocsCollected: 0,
            lastUpdate: new Date()
        };
        
        // Initialize Python OSINT interface
        this.pythonOSINT = new PythonOSINTInterface();
        console.log('🔗 Integrated Python OSINT comprehensive intelligence system');
    }

    loadApiKeys() {
        return {
            ALIENVAULT_OTX_API_KEY: process.env.ALIENVAULT_OTX_API_KEY || "your_alienvault_api_key",
            DNSDUMPSTER_API_KEY: process.env.DNSDUMPSTER_API_KEY || "your_dnsdumpster_api_key",
            REDDIT_API_KEY: process.env.REDDIT_API_KEY || "your_reddit_api_key",
            GITHUB_API_TOKEN: "your_github_token_here",
            YOUTUBE_API_KEY: process.env.YOUTUBE_API_KEY || "your_youtube_api_key",
            COINGECKO_API_KEY: process.env.COINGECKO_API_KEY || "your_coingecko_api_key",
            ETHERSCAN_API_KEY: process.env.ETHERSCAN_API_KEY || "your_etherscan_api_key",
            NEWSAPI_KEY: process.env.NEWSAPI_KEY || "your_newsapi_key",
            HUNTER_IO_API_KEY: process.env.HUNTER_IO_API_KEY || "your_hunter_api_key",
            TRUTHFINDER_ACCOUNT_ID: "26676",
            TRUTHFINDER_MEMBER_ID: "212900365",
            VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || "your_virustotal_api_key",
            VIRUSTOTAL_API_KEY_2: process.env.VIRUSTOTAL_API_KEY_2 || "your_virustotal_api_key_2",
            SHODAN_API_KEY: process.env.SHODAN_API_KEY || "your_shodan_api_key"
        };
    }

    initializeThreatSources() {
        return {
            // Premium threat intelligence sources
            premiumSources: [
                {
                    name: "AlienVault OTX",
                    endpoint: "https://otx.alienvault.com/api/v1",
                    apiKey: this.apiKeys.ALIENVAULT_OTX_API_KEY,
                    reliability: 0.95,
                    types: ["threats", "malware", "iocs", "pulses"]
                },
                {
                    name: "VirusTotal",
                    endpoint: "https://www.virustotal.com/vtapi/v2",
                    apiKey: this.apiKeys.VIRUSTOTAL_API_KEY,
                    reliability: 0.60, // Reduced due to deprecated API endpoints
                    types: ["malware", "files", "urls", "domains"]
                },
                {
                    name: "Shodan",
                    endpoint: "https://api.shodan.io",
                    apiKey: this.apiKeys.SHODAN_API_KEY,
                    reliability: 0.94,
                    types: ["hosts", "services", "vulnerabilities"]
                }
            ],

            // Free threat intelligence sources
            freeSources: [
                {
                    name: "Malware Bazaar",
                    endpoint: "https://mb-api.abuse.ch/api/v1",
                    reliability: 0.92,
                    types: ["malware", "samples", "families"]
                },
                {
                    name: "URLhaus",
                    endpoint: "https://urlhaus-api.abuse.ch/v1",
                    reliability: 0.90,
                    types: ["malicious_urls", "payloads"]
                },
                {
                    name: "ThreatFox",
                    endpoint: "https://threatfox-api.abuse.ch/api/v1",
                    reliability: 0.88,
                    types: ["iocs", "threat_indicators"]
                },
                {
                    name: "Feodo Tracker",
                    endpoint: "https://feodotracker.abuse.ch/api/v1",
                    reliability: 0.90,
                    types: ["botnet", "c2", "malware"]
                }
            ]
        };
    }

    async queryThreatIntelligence(indicator, type = 'hash') {
        console.log(`🔍 Querying threat intelligence for ${type}: ${indicator}`);
        this.stats.queriesRun++;

        // Check cache first
        const cacheKey = `${type}_${indicator}`;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < this.cacheTimeout) {
                console.log('📋 Returning cached result');
                return cached.data;
            }
        }

        const results = {
            indicator,
            type,
            timestamp: new Date(),
            sources: [],
            threat_level: 'unknown',
            malicious: false,
            details: {}
        };

        try {
            // Query VirusTotal
            if (type === 'hash' || type === 'url' || type === 'domain') {
                const vtResult = await this.queryVirusTotal(indicator, type);
                if (vtResult) {
                    results.sources.push(vtResult);
                    if (vtResult.malicious) {
                        results.malicious = true;
                        results.threat_level = 'high';
                        this.stats.threatsFound++;
                    }
                }
            }

            // Query AlienVault OTX
            const otxResult = await this.queryAlienVaultOTX(indicator, type);
            if (otxResult) {
                results.sources.push(otxResult);
                if (otxResult.malicious) {
                    results.malicious = true;
                    results.threat_level = 'high';
                    this.stats.threatsFound++;
                }
            }

            // Query free sources
            const freeResults = await this.queryFreeSources(indicator, type);
            results.sources = results.sources.concat(freeResults);

            // Determine overall threat level
            results.threat_level = this.calculateThreatLevel(results.sources);

            // Cache the result
            this.cache.set(cacheKey, {
                data: results,
                timestamp: Date.now()
            });

            this.stats.iocsCollected += results.sources.length;
            console.log(`✅ Threat intelligence query complete: ${results.sources.length} sources`);

            return results;

        } catch (error) {
            console.error(`❌ Threat intelligence query failed:`, error.message);
            return results;
        }
    }

    async queryVirusTotal(indicator, type) {
        try {
            let endpoint;
            const apiKey = this.apiKeys.VIRUSTOTAL_API_KEY;

            switch (type) {
                case 'hash':
                    endpoint = `https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${indicator}`;
                    break;
                case 'url':
                    endpoint = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${indicator}`;
                    break;
                case 'domain':
                    endpoint = `https://www.virustotal.com/vtapi/v2/domain/report?apikey=${apiKey}&domain=${indicator}`;
                    break;
                default:
                    return null;
            }

            const response = await axios.get(endpoint, { timeout: 10000 });

            if (response.data.response_code === 1) {
                const positives = response.data.positives || 0;
                const total = response.data.total || 0;

                return {
                    source: "VirusTotal",
                    malicious: positives > 0,
                    score: total > 0 ? positives / total : 0,
                    details: {
                        positives,
                        total,
                        scan_date: response.data.scan_date,
                        permalink: response.data.permalink
                    }
                };
            }
        } catch (error) {
            console.warn('VirusTotal query failed:', error.message);
        }
        return null;
    }

    async queryAlienVaultOTX(indicator, type) {
        try {
            const apiKey = this.apiKeys.ALIENVAULT_OTX_API_KEY;
            let endpoint;

            switch (type) {
                case 'hash':
                    endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${indicator}/general`;
                    break;
                case 'ip':
                    endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`;
                    break;
                case 'domain':
                    endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`;
                    break;
                case 'url':
                    endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${indicator}/general`;
                    break;
                default:
                    return null;
            }

            const response = await axios.get(endpoint, {
                headers: { 'X-OTX-API-KEY': apiKey },
                timeout: 10000
            });

            if (response.data) {
                const pulseInfo = response.data.pulse_info || {};
                const pulses = pulseInfo.pulses || [];

                return {
                    source: "AlienVault OTX",
                    malicious: pulses.length > 0,
                    score: Math.min(pulses.length / 10, 1), // Normalize to 0-1
                    details: {
                        pulse_count: pulses.length,
                        pulses: pulses.slice(0, 5).map(p => ({
                            name: p.name,
                            author: p.author_name,
                            created: p.created
                        }))
                    }
                };
            }
        } catch (error) {
            console.warn('AlienVault OTX query failed:', error.message);
        }
        return null;
    }

    async queryFreeSources(indicator, type) {
        const results = [];

        // Query URLhaus for malicious URLs
        if (type === 'url' || type === 'domain') {
            try {
                const response = await axios.post('https://urlhaus-api.abuse.ch/v1/url/',
                    `url=${encodeURIComponent(indicator)}`, {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    timeout: 5000
                });

                if (response.data.query_status === 'ok') {
                    results.push({
                        source: "URLhaus",
                        malicious: true,
                        score: 1.0,
                        details: {
                            threat: response.data.threat,
                            tags: response.data.tags,
                            date_added: response.data.date_added
                        }
                    });
                }
            } catch (error) {
                // URLhaus query failed, continue with other sources
            }
        }

        // Query ThreatFox for IOCs
        try {
            const response = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
                query: 'search_ioc',
                search_term: indicator
            }, { timeout: 5000 });

            if (response.data.query_status === 'ok' && response.data.data.length > 0) {
                results.push({
                    source: "ThreatFox",
                    malicious: true,
                    score: 0.9,
                    details: {
                        iocs: response.data.data.slice(0, 3).map(ioc => ({
                            malware: ioc.malware,
                            confidence: ioc.confidence_level,
                            first_seen: ioc.first_seen
                        }))
                    }
                });
            }
        } catch (error) {
            // ThreatFox query failed, continue
        }

        return results;
    }

    calculateThreatLevel(sources) {
        if (sources.length === 0) return 'unknown';

        const maliciousSources = sources.filter(s => s.malicious);
        if (maliciousSources.length === 0) return 'clean';

        const avgScore = maliciousSources.reduce((sum, s) => sum + s.score, 0) / maliciousSources.length;

        if (avgScore >= 0.7) return 'critical';
        if (avgScore >= 0.4) return 'high';
        if (avgScore >= 0.2) return 'medium';
        return 'low';
    }

    async analyzeCryptoTransaction(txHash, blockchain = 'ethereum') {
        console.log(`💰 Analyzing crypto transaction: ${txHash}`);

        try {
            if (blockchain === 'ethereum') {
                const endpoint = `https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=${txHash}&apikey=${this.apiKeys.ETHERSCAN_API_KEY}`;
                const response = await axios.get(endpoint, { timeout: 10000 });

                if (response.data.result) {
                    const tx = response.data.result;

                    // Check against known malicious addresses
                    const threatCheck = await this.queryThreatIntelligence(tx.to, 'address');

                    return {
                        hash: txHash,
                        from: tx.from,
                        to: tx.to,
                        value: parseInt(tx.value, 16),
                        gasPrice: parseInt(tx.gasPrice, 16),
                        threat_level: threatCheck.threat_level,
                        malicious: threatCheck.malicious,
                        analysis: {
                            high_value: parseInt(tx.value, 16) > 1000000000000000000, // > 1 ETH
                            unusual_gas: parseInt(tx.gasPrice, 16) > 100000000000, // > 100 Gwei
                            threat_sources: threatCheck.sources
                        }
                    };
                }
            }
        } catch (error) {
            console.error('Crypto transaction analysis failed:', error.message);
        }

        return { hash: txHash, error: 'Analysis failed' };
    }

    async checkPhishingURL(url) {
        console.log(`🎣 Checking URL for phishing: ${url}`);

        const results = {
            url,
            timestamp: new Date(),
            phishing: false,
            risk_level: 'unknown',
            sources: []
        };

        try {
            // Check against URLhaus
            const urlhausResult = await this.queryFreeSources(url, 'url');
            if (urlhausResult.length > 0) {
                results.sources = results.sources.concat(urlhausResult);
                results.phishing = true;
                results.risk_level = 'high';
            }

            // Check against VirusTotal
            const vtResult = await this.queryVirusTotal(url, 'url');
            if (vtResult && vtResult.malicious) {
                results.sources.push(vtResult);
                results.phishing = true;
                results.risk_level = 'high';
            }

            // Basic heuristic checks
            const heuristicScore = this.checkPhishingHeuristics(url);
            if (heuristicScore > 0.5) {
                results.sources.push({
                    source: "Heuristic Analysis",
                    malicious: true,
                    score: heuristicScore,
                    details: { heuristic_flags: this.getPhishingFlags(url) }
                });
                results.phishing = true;
                results.risk_level = heuristicScore > 0.8 ? 'high' : 'medium';
            }

        } catch (error) {
            console.error('Phishing URL check failed:', error.message);
        }

        return results;
    }

    checkPhishingHeuristics(url) {
        let score = 0;
        const flags = [];

        // Check for suspicious domains
        const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'shorturl.at'];
        if (suspiciousDomains.some(domain => url.includes(domain))) {
            score += 0.3;
            flags.push('shortened_url');
        }

        // Check for crypto-related phishing patterns
        const cryptoPhishingPatterns = [
            /metamask.*wallet/i,
            /binance.*login/i,
            /coinbase.*secure/i,
            /crypto.*wallet.*verify/i,
            /defi.*connect/i
        ];

        cryptoPhishingPatterns.forEach(pattern => {
            if (pattern.test(url)) {
                score += 0.4;
                flags.push('crypto_phishing_pattern');
            }
        });

        // Check for URL obfuscation
        if (url.includes('%') || url.includes('xn--')) {
            score += 0.2;
            flags.push('url_obfuscation');
        }

        return Math.min(score, 1.0);
    }

    getPhishingFlags(url) {
        const flags = [];

        if (url.includes('bit.ly') || url.includes('tinyurl')) flags.push('URL_SHORTENER');
        if (/metamask/i.test(url) && !/metamask\.io/i.test(url)) flags.push('FAKE_METAMASK');
        if (/binance/i.test(url) && !/binance\.com/i.test(url)) flags.push('FAKE_BINANCE');
        if (url.includes('%') || url.includes('xn--')) flags.push('OBFUSCATED_URL');

        return flags;
    }

    getStats() {
        return {
            ...this.stats,
            cacheSize: this.cache.size,
            activeSources: this.threatSources.premiumSources.length + this.threatSources.freeSources.length
        };
    }

    async refreshThreatFeeds() {
        console.log('🔄 Refreshing threat intelligence feeds...');

        try {
            // Clear old cache entries
            const now = Date.now();
            for (const [key, value] of this.cache.entries()) {
                if (now - value.timestamp > this.cacheTimeout) {
                    this.cache.delete(key);
                }
            }

            // Update stats
            this.stats.lastUpdate = new Date();

            console.log('✅ Threat feeds refreshed');
            return true;
        } catch (error) {
            console.error('❌ Failed to refresh threat feeds:', error.message);
            return false;
        }
    }

    // Get real threat data using Python OSINT comprehensive system
    async getRealThreats() {
        try {
            console.log('🔍 Querying COMPREHENSIVE Python OSINT system with all your API keys...');
            
            // First try to get threats from the Python comprehensive system
            let pythonThreats = [];
            try {
                pythonThreats = await this.pythonOSINT.getRealThreats();
                console.log(`🐍 Retrieved ${pythonThreats.length} threats from Python OSINT system`);
                
                // Update stats from Python system
                const pythonStats = await this.pythonOSINT.getOSINTStats();
                this.stats.threatsFound += pythonThreats.length;
                this.stats.queriesRun += pythonStats.queriesRun || 0;
                this.stats.iocsCollected += pythonThreats.length;
                
            } catch (pythonError) {
                console.warn('⚠️ Python OSINT system unavailable, falling back to Node.js sources');
            }
            
            // Get additional threats from Node.js sources (as backup)
            const nodeThreats = await this.getNodeJSThreats();
            
            // Combine both sources
            const allThreats = [...pythonThreats, ...nodeThreats];
            
            console.log(`✅ TOTAL: Retrieved ${allThreats.length} REAL threats from comprehensive OSINT sources`);
            this.stats.threatsFound = allThreats.length;
            this.stats.lastUpdate = new Date();
            
            return allThreats;
        } catch (error) {
            console.error('❌ Error getting comprehensive threats:', error);
            return [];
        }
    }
    
    // Get comprehensive OSINT statistics including Python system
    async getOSINTStats() {
        try {
            // Get Python system stats
            const pythonStats = await this.pythonOSINT.getOSINTStats();
            
            // Combine with Node.js stats
            return {
                ...this.stats,
                pythonSources: pythonStats.totalSources || 0,
                pythonConfigured: pythonStats.configuredSources || 0,
                pythonFree: pythonStats.freeSources || 0,
                pythonPremium: pythonStats.premiumSources || 0,
                totalSystemSources: (pythonStats.totalSources || 0) + this.threatSources.premiumSources.length + this.threatSources.freeSources.length,
                activeSources: this.threatSources.premiumSources.length + this.threatSources.freeSources.length,
                cacheSize: this.cache.size,
                pythonCategories: pythonStats.categories || [],
                reliability: pythonStats.reliability || {},
                lastPythonUpdate: pythonStats.lastUpdate
            };
        } catch (error) {
            console.error('❌ Failed to get comprehensive OSINT stats:', error);
            return {
                ...this.stats,
                pythonSources: 0,
                totalSystemSources: this.threatSources.premiumSources.length + this.threatSources.freeSources.length,
                activeSources: this.threatSources.premiumSources.length + this.threatSources.freeSources.length,
                cacheSize: this.cache.size,
                error: error.message
            };
        }
    }
    
    // Legacy Node.js threat gathering (as backup)
    async getNodeJSThreats() {
        try {
            const threats = [];

            console.log('🔍 Querying legacy Node.js OSINT sources as backup...');

            // 1. Query AlienVault OTX with your API key
            try {
                const otxResponse = await axios.get(`${this.threatSources.premiumSources[0].endpoint}/pulses/subscribed?limit=5`, {
                    headers: { 'X-OTX-API-KEY': this.apiKeys.ALIENVAULT_OTX_API_KEY }
                });

                if (otxResponse.data && otxResponse.data.results) {
                    otxResponse.data.results.forEach((pulse, index) => {
                        const targetCountries = pulse.targeted_countries && pulse.targeted_countries.length > 0 
                            ? pulse.targeted_countries[0] : 'Global';
                        
                        threats.push({
                            name: pulse.name || 'Threat Intelligence Pulse',
                            type: this.categorizePulse(pulse.tags),
                            country: targetCountries,
                            severity: this.mapSeverity(pulse.tags),
                            confidence: 0.90,
                            description: pulse.description || 'Active threat campaign detected',
                            source: 'AlienVault OTX (Node.js Backup)',
                            tags: pulse.tags || [],
                            created: pulse.created,
                            id: `nodejs_otx_${pulse.id}`
                        });
                    });
                    console.log(`✅ Retrieved ${threats.length} threats from AlienVault OTX (Node.js backup)`);
                }
            } catch (otxError) {
                console.warn('⚠️ AlienVault OTX (Node.js) query failed:', otxError.message);
            }

            // 2. Query free sources as backup
            try {
                const mbResponse = await axios.post('https://mb-api.abuse.ch/api/v1/', {
                    query: 'get_recent',
                    selector: 'time'
                });

                if (mbResponse.data && mbResponse.data.data) {
                    mbResponse.data.data.slice(0, 2).forEach((malware, index) => {
                        threats.push({
                            name: `${malware.file_name || 'Malware'} detected`,
                            type: 'malware',
                            country: malware.origin_country || 'Unknown',
                            severity: 'high',
                            confidence: 0.88,
                            description: `Malware family: ${malware.signature || 'Unknown'}`,
                            source: 'Malware Bazaar (Node.js Backup)',
                            file_type: malware.file_type,
                            sha256: malware.sha256_hash,
                            id: `nodejs_mb_${malware.sha256_hash?.substring(0, 8)}`
                        });
                    });
                    console.log(`✅ Retrieved recent malware from Malware Bazaar (Node.js backup)`);
                }
            } catch (mbError) {
                console.warn('⚠️ Malware Bazaar (Node.js) query failed:', mbError.message);
            }

            console.log(`✅ Node.js backup: Retrieved ${threats.length} threats`);
            return threats;
        } catch (error) {
            console.error('❌ Error getting Node.js backup threats:', error);
            return [];
        }
    }
    
    // Enhanced domain intelligence using Python system
    async queryDomainIntelligence(domain) {
        try {
            console.log(`🌐 Querying comprehensive domain intelligence for: ${domain}`);
            
            // Use Python system for comprehensive domain analysis
            let pythonResults = null;
            try {
                pythonResults = await this.pythonOSINT.queryDomainIntelligence(domain);
                console.log(`🐍 Retrieved domain intelligence from Python system`);
            } catch (pythonError) {
                console.warn('⚠️ Python domain analysis unavailable, using Node.js fallback');
            }
            
            // Get basic Node.js analysis as backup
            const nodeResults = await this.queryThreatIntelligence(domain, 'domain');
            
            return {
                domain: domain,
                timestamp: new Date().toISOString(),
                python_analysis: pythonResults,
                node_analysis: nodeResults,
                comprehensive: pythonResults !== null
            };
            
        } catch (error) {
            console.error(`❌ Domain intelligence query failed for ${domain}:`, error);
            return { domain: domain, error: error.message };
        }
    }
    
    // Enhanced crypto transaction analysis using Python system
    async analyzeCryptoTransaction(txHash, blockchain = 'ethereum') {
        console.log(`💰 Analyzing crypto transaction with comprehensive OSINT: ${txHash}`);

        try {
            // Use Python system for multi-chain analysis if available
            let pythonAnalysis = null;
            try {
                // Extract address from transaction if possible
                const ethResponse = await axios.get(`https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=${txHash}&apikey=${this.apiKeys.ETHERSCAN_API_KEY}`);
                
                if (ethResponse.data.result && ethResponse.data.result.to) {
                    pythonAnalysis = await this.pythonOSINT.executePythonCommand('ip', ['--indicator', ethResponse.data.result.to]);
                }
            } catch (pythonError) {
                console.warn('⚠️ Python crypto analysis unavailable');
            }
            
            // Legacy Node.js analysis
            if (blockchain === 'ethereum') {
                const endpoint = `https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=${txHash}&apikey=${this.apiKeys.ETHERSCAN_API_KEY}`;
                const response = await axios.get(endpoint, { timeout: 10000 });

                if (response.data.result) {
                    const tx = response.data.result;

                    // Check against known malicious addresses
                    const threatCheck = await this.queryThreatIntelligence(tx.to, 'address');

                    return {
                        hash: txHash,
                        from: tx.from,
                        to: tx.to,
                        value: parseInt(tx.value, 16),
                        gasPrice: parseInt(tx.gasPrice, 16),
                        threat_level: threatCheck.threat_level,
                        malicious: threatCheck.malicious,
                        python_analysis: pythonAnalysis,
                        analysis: {
                            high_value: parseInt(tx.value, 16) > 1000000000000000000, // > 1 ETH
                            unusual_gas: parseInt(tx.gasPrice, 16) > 100000000000, // > 100 Gwei
                            threat_sources: threatCheck.sources,
                            comprehensive_osint: pythonAnalysis !== null
                        }
                    };
                }
            }
        } catch (error) {
            console.error('Crypto transaction analysis failed:', error.message);
        }

        return { hash: txHash, error: 'Analysis failed' };
    }

    // Helper function to categorize OTX pulses
    categorizePulse(tags) {
        if (!tags || tags.length === 0) return 'threat_intel';
        
        const tagString = tags.join(' ').toLowerCase();
        if (tagString.includes('ransomware') || tagString.includes('crypto')) return 'ransomware';
        if (tagString.includes('phishing') || tagString.includes('email')) return 'phishing';
        if (tagString.includes('ddos') || tagString.includes('botnet')) return 'ddos';
        if (tagString.includes('apt') || tagString.includes('nation')) return 'apt';
        if (tagString.includes('malware') || tagString.includes('trojan')) return 'malware';
        if (tagString.includes('exploit') || tagString.includes('vulnerability')) return 'exploit';
        
        return 'threat_intel';
    }

    // Helper function to map severity from tags
    mapSeverity(tags) {
        if (!tags || tags.length === 0) return 'medium';
        
        const tagString = tags.join(' ').toLowerCase();
        if (tagString.includes('critical') || tagString.includes('high') || tagString.includes('apt')) return 'critical';
        if (tagString.includes('medium') || tagString.includes('malware')) return 'high';
        
        return 'medium';
    }
}

module.exports = OSINTThreatIntelligence;