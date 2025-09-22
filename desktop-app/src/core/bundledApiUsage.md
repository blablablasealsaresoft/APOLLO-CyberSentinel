# Bundled API Keys Usage Guide

## Overview
APOLLO CyberSentinel now comes with pre-configured API keys bundled directly into the application. This provides immediate functionality without requiring users to obtain their own API keys.

## Implementation

### 1. Automatic Initialization
The bundled keys are automatically initialized when the app starts in `main.js`:

```javascript
// Keys are loaded and set in process.env automatically
const { initializeBundledKeys } = require('./src/core/bundledApiKeys');
initializeBundledKeys();
```

### 2. Usage in Existing Code
Your existing code continues to work without changes:

```javascript
// This will now use the bundled key automatically
const anthropicKey = process.env.ANTHROPIC_API_KEY;
const virusTotalKey = process.env.VIRUSTOTAL_API_KEY;
```

### 3. Direct Access (Alternative)
You can also access keys directly if needed:

```javascript
const { getBundledApiKey } = require('./src/core/bundledApiKeys');

const anthropicKey = getBundledApiKey('ANTHROPIC_API_KEY');
const shodanKey = getBundledApiKey('SHODAN_API_KEY');
```

## Available API Keys

### AI & Analysis
- `ANTHROPIC_API_KEY` - Claude AI for threat analysis
- `AI_MODEL` - Configured model version

### OSINT Threat Intelligence
- `ALIENVAULT_OTX_API_KEY` - AlienVault OTX threat feeds
- `VIRUSTOTAL_API_KEY` - VirusTotal malware analysis
- `SHODAN_API_KEY` - Shodan device/service discovery

### Additional OSINT Sources
- `DNSDUMPSTER_API_KEY` - DNS reconnaissance
- `REDDIT_API_KEY` - Social media intelligence
- `GITHUB_API_TOKEN` - Code repository monitoring
- `YOUTUBE_API_KEY` - Video content analysis
- `NEWSAPI_KEY` - News and media monitoring

### Crypto & Blockchain
- `COINGECKO_API_KEY` - Cryptocurrency data
- `ETHERSCAN_API_KEY` - Ethereum blockchain analysis
- `WALLETCONNECT_PROJECT_ID` - Wallet connectivity

### Investigation Tools
- `HUNTER_IO_API_KEY` - Email verification
- `TRUTHFINDER_ACCOUNT_ID` - People search
- `TRUTHFINDER_MEMBER_ID` - Account credentials

## Security Features

### Key Protection
- Keys are compiled into the binary
- Not stored in plain text files
- Protected from casual extraction

### Validation
```javascript
const { validateBundledKeys } = require('./src/core/bundledApiKeys');
const validation = validateBundledKeys();

if (validation.valid) {
    console.log('All critical keys available');
} else {
    console.log('Missing keys:', validation.missing);
}
```

## Migration from .env

### Before (Required user setup)
```javascript
// User had to create .env file with:
// ANTHROPIC_API_KEY=their_key_here
// VIRUSTOTAL_API_KEY=their_key_here

const key = process.env.ANTHROPIC_API_KEY; // Could be undefined
```

### After (Works immediately)
```javascript
// Keys are automatically available
const key = process.env.ANTHROPIC_API_KEY; // Always available
```

## Benefits

### For Users
- ✅ Zero configuration required
- ✅ Works immediately after installation
- ✅ No API key costs for users
- ✅ Professional out-of-box experience

### For Development
- ✅ Consistent API access across installations
- ✅ No user support issues with API setup
- ✅ Controlled usage and costs
- ✅ Better user experience metrics

## Build Process

When building the application:

1. Keys are embedded in the compiled binary
2. .env files are still ignored by git
3. Production builds use bundled keys
4. Development can still use .env for testing

## Usage Examples

### Threat Intelligence Service
```javascript
class ThreatIntelligenceService {
    constructor() {
        // These keys are automatically available
        this.virusTotalKey = process.env.VIRUSTOTAL_API_KEY;
        this.shodanKey = process.env.SHODAN_API_KEY;
        this.otxKey = process.env.ALIENVAULT_OTX_API_KEY;
    }

    async analyzeThreat(indicator) {
        // Use bundled keys for immediate analysis
        const vtResult = await this.queryVirusTotal(indicator);
        const shodanResult = await this.queryShodan(indicator);
        return { vtResult, shodanResult };
    }
}
```

### AI Analysis
```javascript
class AIAnalysisEngine {
    constructor() {
        this.anthropicKey = process.env.ANTHROPIC_API_KEY;
        this.model = process.env.AI_MODEL;
    }

    async analyzeWithClaude(data) {
        // Bundled Anthropic key enables immediate AI analysis
        return await this.callClaudeAPI(data);
    }
}
```

This implementation provides seamless functionality while maintaining security and user experience.