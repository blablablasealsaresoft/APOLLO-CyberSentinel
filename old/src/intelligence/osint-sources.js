const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');

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
    }

    loadApiKeys() {
        return {
            ALIENVAULT_OTX_API_KEY: "762c4e5345c0c5b61c5896bc0e4de2a7fc52fc930b2209e5478c5367d646a777",
            DNSDUMPSTER_API_KEY: "3fe5b5589a224236d5c0135718527610206fa89604d6caf0894f10f6c7a04956",
            REDDIT_API_KEY: "_dlqVgssQQwhGCFw4XYadfI64odO4g",
            GITHUB_API_TOKEN: "your_github_token_here",
            YOUTUBE_API_KEY: "403400722686-csavof85lv18toj2lo778cibdk9qhjc7.apps.googleusercontent.com",
            COINGECKO_API_KEY: "CG-AsaEzdeEeHeHf8CRRLk7iKfa",
            ETHERSCAN_API_KEY: "VXVJX5N1UM44KUYMJDAVZBKJ3I5ATWDB6E",
            NEWSAPI_KEY: "43f407a4aceb41c4a588224bfbf7f528",
            HUNTER_IO_API_KEY: "98df4bbbac21d3f2dfae2e657e09520b82b94bb0",
            TRUTHFINDER_ACCOUNT_ID: "26676",
            TRUTHFINDER_MEMBER_ID: "212900365",
            VIRUSTOTAL_API_KEY: "7ba1673d04b68c794a5a5617d213a44697040d4fcd6df10bd27cda46566f90ca",
            VIRUSTOTAL_API_KEY_2: "28e907e705b1be11e0406dd06cfe6b968a6d829f6282379252b0efc9bb50b215",
            SHODAN_API_KEY: "y0RKKzThYSKzhVBKMJ7CRI3ESdZYTwan"
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
                    reliability: 0.98,
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
}

module.exports = OSINTThreatIntelligence;