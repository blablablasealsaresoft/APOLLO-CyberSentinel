const Anthropic = require('@anthropic-ai/sdk');
const PythonOSINTInterface = require('../intelligence/python-osint-interface');

class ApolloAIOracle {
    constructor() {
        this.model = "claude-opus-4-1-20250805"; // Latest Claude Opus model
        this.apiKey = null; // Will be loaded from secure config
        this.anthropic = null; // Anthropic client instance
        this.threatContextDatabase = new Map();
        this.analysisHistory = [];
        this.maxHistorySize = 1000;
        
        // Integrate comprehensive Python OSINT intelligence
        this.pythonOSINT = new PythonOSINTInterface();
        console.log('🧠 AI Oracle integrated with comprehensive Python OSINT intelligence (37 sources)');

        this.systemPrompt = `You are Apollo, a military-grade cybersecurity AI assistant specializing in:
- Nation-state threat analysis (North Korea, Russia, China, Iran)
- Advanced Persistent Threat (APT) detection and classification
- Cryptocurrency and DeFi security analysis
- Smart contract vulnerability assessment
- Phishing and social engineering detection
- Zero-day exploit identification
- Malware family classification and behavior analysis

You provide expert-level analysis with specific technical details, IOCs, and actionable recommendations.
Always include confidence scores and cite relevant threat intelligence sources when available.`;

        this.init();
    }

    init() {
        this.loadConfiguration();
        this.initializeThreatContext();
        console.log('🤖 Apollo AI Oracle initialized');
    }
    
    async gatherComprehensiveOSINTIntelligence(indicator) {
        try {
            console.log(`🔍 AI Oracle gathering comprehensive OSINT for: ${indicator}`);
            
            // Determine indicator type
            let indicatorType = 'domain';
            if (/^[a-fA-F0-9]{32,64}$/.test(indicator)) indicatorType = 'hash';
            else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) indicatorType = 'ip';
            else if (indicator.startsWith('http')) indicatorType = 'url';
            else if (/^0x[a-fA-F0-9]{40}$/.test(indicator)) indicatorType = 'address';
            
            let osintData = null;
            
            if (indicatorType === 'domain') {
                osintData = await this.pythonOSINT.queryDomainIntelligence(indicator);
            } else if (indicatorType === 'ip') {
                osintData = await this.pythonOSINT.queryIPIntelligence(indicator);
            } else {
                osintData = await this.pythonOSINT.queryThreatIntelligence(indicator, indicatorType);
            }
            
            const stats = await this.pythonOSINT.getOSINTStats();
            
            return {
                indicator: indicator,
                type: indicatorType,
                sourcesQueried: osintData?.sources_queried || 0,
                totalSources: stats?.totalSources || 0,
                osintData: osintData,
                summary: this.summarizeOSINTForAI(osintData, stats)
            };
            
        } catch (error) {
            console.warn(`⚠️ AI Oracle OSINT gathering failed: ${error.message}`);
            return {
                indicator: indicator,
                sourcesQueried: 0,
                summary: 'OSINT intelligence unavailable',
                error: error.message
            };
        }
    }
    
    summarizeOSINTForAI(osintData, stats) {
        if (!osintData || osintData.error) {
            return 'No OSINT intelligence available.';
        }
        
        let summary = `OSINT Intelligence Summary (${stats?.totalSources || 0} sources available):\n`;
        
        if (osintData.results) {
            const results = osintData.results;
            
            if (results.alienvault_otx && !results.alienvault_otx.error) {
                summary += `- AlienVault OTX: ${results.alienvault_otx.pulse_count || 0} threat pulses, reputation ${results.alienvault_otx.reputation || 0}\n`;
            }
            
            if (results.hunter_io && !results.hunter_io.error) {
                summary += `- Hunter.io: Organization "${results.hunter_io.organization || 'Unknown'}", ${results.hunter_io.emails_found || 0} emails\n`;
            }
            
            if (results.certificates && !results.certificates.error) {
                summary += `- SSL Certificates: ${results.certificates.certificates_found || 0} certificates, ${results.certificates.unique_subdomains || 0} subdomains\n`;
            }
            
            if (results.geolocation && !results.geolocation.error) {
                summary += `- Geolocation: ${results.geolocation.country || 'Unknown'}, ${results.geolocation.city || 'Unknown'}, ISP: ${results.geolocation.isp || 'Unknown'}\n`;
            }
            
            if (results.threatcrowd && !results.threatcrowd.error) {
                summary += `- ThreatCrowd: ${results.threatcrowd.hashes?.length || 0} hashes, ${results.threatcrowd.subdomains?.length || 0} subdomains\n`;
            }
        }
        
        return summary;
    }
    
    buildAnalysisPromptWithOSINT(indicator, threatContext, context, osintIntelligence) {
        return `
COMPREHENSIVE CYBERSECURITY THREAT ANALYSIS REQUEST

Indicator: ${indicator}
Type: ${osintIntelligence.type}
Context: ${JSON.stringify(context)}

COMPREHENSIVE OSINT INTELLIGENCE:
${osintIntelligence.summary}

THREAT CONTEXT DATABASE:
${threatContext}

ANALYSIS REQUIREMENTS:
Based on the comprehensive OSINT data from ${osintIntelligence.sourcesQueried} sources out of ${osintIntelligence.totalSources} available, provide:

1. THREAT LEVEL: (clean, low, medium, high, critical)
2. CONFIDENCE SCORE: (0.0 to 1.0) based on OSINT evidence quality
3. TECHNICAL ANALYSIS: Incorporating all OSINT findings
4. ATTRIBUTION: Threat actor/campaign identification if possible
5. RECOMMENDATIONS: Specific defensive actions
6. IOCS: Additional indicators of compromise from OSINT
7. TTPS: Tactics, techniques, and procedures observed

Focus on actionable intelligence and cite specific OSINT sources in your analysis.
        `;
    }

    loadConfiguration() {
        // In production, this would load from secure config
        try {
            const config = {
                anthropicApiKey: process.env.ANTHROPIC_API_KEY || null,
                model: process.env.AI_MODEL || "claude-3-5-sonnet-20241022"
            };

            this.apiKey = config.anthropicApiKey;
            this.model = config.model;

            // Initialize Anthropic client
            if (this.apiKey) {
                this.anthropic = new Anthropic({
                    apiKey: this.apiKey,
                });
                console.log('🔑 Anthropic Claude AI Oracle initialized');
            } else {
                console.warn('⚠️ No Anthropic API key found - using fallback mode');
            }

            console.log('🔑 AI Oracle configuration loaded');
        } catch (error) {
            console.warn('⚠️ AI Oracle configuration failed, using fallback mode');
        }
    }

    initializeThreatContext() {
        // Pre-load threat intelligence context
        this.threatContextDatabase.set('pegasus', {
            description: 'NSO Group Pegasus spyware - zero-click iOS/Android exploitation',
            indicators: ['com.apple.WebKit.Networking', 'NSPredicate injection', 'JBIG2 exploit'],
            attribution: 'NSO Group (Israel)',
            targets: 'Journalists, activists, politicians, dissidents'
        });

        this.threatContextDatabase.set('lazarus', {
            description: 'North Korean Lazarus Group - cryptocurrency theft and espionage',
            indicators: ['AppleJeus', 'RATANKBA', 'Manuscrypt', 'BADCALL'],
            attribution: 'DPRK Bureau 121',
            targets: 'Cryptocurrency exchanges, financial institutions, defense contractors'
        });

        this.threatContextDatabase.set('apt28', {
            description: 'Russian military intelligence (GRU) cyber unit',
            indicators: ['Fancy Bear', 'GAMEFISH', 'Sofacy', 'Pawn Storm'],
            attribution: 'GRU Unit 26165',
            targets: 'Government agencies, military, NATO members, elections'
        });

        this.threatContextDatabase.set('apt1', {
            description: 'Chinese PLA Unit 61398 cyber espionage group',
            indicators: ['WEBC2-UGX', 'SEASALT', 'BACKDOOR.BARKIOFORK'],
            attribution: 'PLA Unit 61398',
            targets: 'Intellectual property theft, government secrets, critical infrastructure'
        });
    }

    async analyzeThreat(indicator, context = {}) {
        if (!this.anthropic) {
            return this.fallbackAnalysis(indicator, context);
        }

        try {
            console.log(`🧠 Claude AI Oracle analyzing threat with comprehensive OSINT: ${indicator}`);

            // Gather comprehensive OSINT intelligence first
            const osintIntelligence = await this.gatherComprehensiveOSINTIntelligence(indicator);
            
            const threatContext = this.buildThreatContext(indicator, context);
            const prompt = this.buildAnalysisPromptWithOSINT(indicator, threatContext, context, osintIntelligence);

            // Use custom prompt if provided in context
            const finalPrompt = context.customPrompt || prompt;

            const response = await this.anthropic.messages.create({
                model: this.model,
                max_tokens: 1024,
                messages: [
                    {
                        role: "user",
                        content: `${this.systemPrompt}\n\n${finalPrompt}`
                    }
                ],
                temperature: 0.1 // Low temperature for factual analysis
            });

            const analysis = this.parseClaudeResponse(response);
            this.storeAnalysisHistory(indicator, analysis);

            return analysis;

        } catch (error) {
            console.error('❌ Claude AI Oracle analysis failed:', error.message);
            return this.fallbackAnalysis(indicator, context);
        }
    }

    buildThreatContext(indicator, context) {
        let threatContext = '';

        // Check if indicator matches known threat patterns
        for (const [threatName, threatInfo] of this.threatContextDatabase.entries()) {
            if (threatInfo.indicators.some(ioc =>
                indicator.toLowerCase().includes(ioc.toLowerCase()) ||
                ioc.toLowerCase().includes(indicator.toLowerCase())
            )) {
                threatContext += `\nKnown threat match: ${threatName.toUpperCase()}\n`;
                threatContext += `- Description: ${threatInfo.description}\n`;
                threatContext += `- Attribution: ${threatInfo.attribution}\n`;
                threatContext += `- Typical targets: ${threatInfo.targets}\n`;
            }
        }

        // Add OSINT context if available
        if (context.osintResults) {
            threatContext += '\nOSINT Intelligence:\n';
            context.osintResults.forEach(result => {
                threatContext += `- ${result.source}: ${result.malicious ? 'MALICIOUS' : 'CLEAN'} (confidence: ${(result.score * 100).toFixed(0)}%)\n`;
            });
        }

        return threatContext;
    }

    buildAnalysisPrompt(indicator, threatContext, context) {
        let prompt = `Analyze this cybersecurity indicator for threats:\n\n`;
        prompt += `Indicator: ${indicator}\n`;
        prompt += `Type: ${context.type || 'unknown'}\n\n`;

        if (threatContext) {
            prompt += `Threat Intelligence Context:\n${threatContext}\n\n`;
        }

        prompt += `Please provide:\n`;
        prompt += `1. Threat Assessment (CLEAN/SUSPICIOUS/MALICIOUS)\n`;
        prompt += `2. Confidence Score (0-100%)\n`;
        prompt += `3. Threat Family/Group (if applicable)\n`;
        prompt += `4. Technical Analysis\n`;
        prompt += `5. Recommended Actions\n`;
        prompt += `6. IOCs to monitor\n\n`;

        prompt += `Focus on nation-state threats, APT groups, cryptocurrency attacks, and zero-day exploits.`;

        return prompt;
    }

    parseClaudeResponse(apiResponse) {
        try {
            const content = apiResponse.content[0].text;

            // Extract structured information from Claude's response
            const analysis = {
                raw_response: content,
                threat_level: this.extractThreatLevel(content),
                confidence: this.extractConfidence(content),
                threat_family: this.extractThreatFamily(content),
                technical_analysis: this.extractTechnicalAnalysis(content),
                recommendations: this.extractRecommendations(content),
                iocs: this.extractIOCs(content),
                timestamp: new Date(),
                source: 'Claude AI Oracle',
                model: this.model
            };

            return analysis;

        } catch (error) {
            console.error('Failed to parse Claude response:', error);
            return { error: 'Analysis parsing failed', raw_response: apiResponse };
        }
    }

    // Legacy method for backward compatibility
    parseAnalysisResponse(apiResponse) {
        return this.parseClaudeResponse(apiResponse);
    }

    extractThreatLevel(content) {
        const levelRegex = /(CLEAN|SUSPICIOUS|MALICIOUS)/i;
        const match = content.match(levelRegex);
        return match ? match[1].toUpperCase() : 'UNKNOWN';
    }

    extractConfidence(content) {
        const confidenceRegex = /(\d+)%/;
        const match = content.match(confidenceRegex);
        return match ? parseInt(match[1]) : 0;
    }

    extractThreatFamily(content) {
        const families = ['Lazarus', 'APT28', 'APT1', 'Pegasus', 'Fancy Bear', 'Sofacy'];
        for (const family of families) {
            if (content.toLowerCase().includes(family.toLowerCase())) {
                return family;
            }
        }
        return null;
    }

    extractTechnicalAnalysis(content) {
        const sections = content.split('\n');
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].toLowerCase().includes('technical') && sections[i].toLowerCase().includes('analysis')) {
                return sections.slice(i, i + 3).join('\n').trim();
            }
        }
        return 'No technical analysis extracted';
    }

    extractRecommendations(content) {
        const sections = content.split('\n');
        const recommendations = [];

        for (let i = 0; i < sections.length; i++) {
            if (sections[i].toLowerCase().includes('recommend')) {
                for (let j = i + 1; j < sections.length && j < i + 5; j++) {
                    if (sections[j].trim().startsWith('-') || sections[j].trim().match(/^\d+\./)) {
                        recommendations.push(sections[j].trim());
                    }
                }
            }
        }

        return recommendations;
    }

    extractIOCs(content) {
        const iocPatterns = [
            /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, // IP addresses
            /\b[a-f0-9]{32,64}\b/gi, // Hashes
            /\b[a-z0-9.-]+\.[a-z]{2,}\b/gi // Domains
        ];

        const iocs = [];
        iocPatterns.forEach(pattern => {
            const matches = content.match(pattern);
            if (matches) {
                iocs.push(...matches);
            }
        });

        return [...new Set(iocs)]; // Remove duplicates
    }

    fallbackAnalysis(indicator, context) {
        console.log('🔧 Using fallback analysis (no AI model available)');

        // Simple heuristic-based analysis
        let threatLevel = 'CLEAN';
        let confidence = 50;
        let recommendations = ['Monitor for suspicious activity'];

        // Check against known bad patterns
        const suspiciousPatterns = [
            /pegasus/i,
            /lazarus/i,
            /apt/i,
            /malware/i,
            /trojan/i,
            /backdoor/i,
            /ransomware/i
        ];

        if (suspiciousPatterns.some(pattern => pattern.test(indicator))) {
            threatLevel = 'SUSPICIOUS';
            confidence = 75;
            recommendations = [
                'Quarantine immediately',
                'Perform deep forensic analysis',
                'Alert security team'
            ];
        }

        return {
            threat_level: threatLevel,
            confidence: confidence,
            threat_family: null,
            technical_analysis: 'Heuristic-based analysis performed',
            recommendations: recommendations,
            iocs: [],
            timestamp: new Date(),
            source: 'Fallback Analysis'
        };
    }

    storeAnalysisHistory(indicator, analysis) {
        this.analysisHistory.push({
            indicator,
            analysis,
            timestamp: new Date()
        });

        // Maintain history size limit
        if (this.analysisHistory.length > this.maxHistorySize) {
            this.analysisHistory.shift();
        }
    }

    async analyzeSmartContract(contractAddress, bytecode = null) {
        const context = {
            type: 'smart_contract',
            address: contractAddress,
            bytecode: bytecode
        };

        const prompt = `Analyze this Ethereum smart contract for security vulnerabilities:
Contract Address: ${contractAddress}
${bytecode ? `Bytecode: ${bytecode.substring(0, 200)}...` : ''}

Check for:
- Reentrancy vulnerabilities
- Integer overflow/underflow
- Unauthorized access controls
- Hidden fees or unlimited approvals
- Ponzi/pyramid scheme patterns
- Rugpull indicators
- Honeypot mechanisms

Provide detailed security assessment and risk rating.`;

        return await this.analyzeThreat(contractAddress, { ...context, customPrompt: prompt });
    }

    async analyzePhishingURL(url) {
        const context = {
            type: 'phishing_url',
            url: url
        };

        const prompt = `Analyze this URL for phishing and malicious content:
URL: ${url}

Check for:
- Fake cryptocurrency exchange sites
- Wallet phishing attempts
- Domain spoofing techniques
- Social engineering indicators
- Malicious redirects
- Typosquatting
- Certificate fraud

Assess the phishing risk and provide protection recommendations.`;

        return await this.analyzeThreat(url, { ...context, customPrompt: prompt });
    }

    getAnalysisHistory(limit = 10) {
        return this.analysisHistory.slice(-limit);
    }

    getStats() {
        return {
            total_analyses: this.analysisHistory.length,
            threat_context_entries: this.threatContextDatabase.size,
            ai_model: this.model,
            ai_provider: 'Anthropic Claude',
            oracle_status: this.anthropic ? 'active' : 'fallback'
        };
    }
}

module.exports = ApolloAIOracle;