# 🔌 Apollo Security - API Reference

## Overview
Apollo Security provides a comprehensive API for threat analysis, OSINT intelligence, and AI-powered security assessment. This reference covers all available endpoints and integration methods.

## 📡 IPC API (Electron Main Process)

### Protection Status
```javascript
// Get current protection status
const status = await window.apolloAPI.getProtectionStatus();
console.log(status);
// Returns:
// {
//   active: true,
//   stats: { threatsDetected: 0, threatsBlocked: 0, ... },
//   engines: { threatEngine: "active", walletShield: "active", ... }
// }
```

### Threat Analysis
```javascript
// Analyze smart contract
const contractResult = await window.apolloAPI.analyzeSmartContract(
  "0x1234567890123456789012345678901234567890",
  bytecode // optional
);

// Check phishing URL
const phishingResult = await window.apolloAPI.checkPhishingURL(
  "https://suspicious-domain.com"
);

// AI-powered threat analysis
const aiAnalysis = await window.apolloAPI.analyzeWithAI(
  "suspicious-file.exe",
  { type: "file", source: "email_attachment" }
);
```

### OSINT Intelligence
```javascript
// Get OSINT statistics
const osintStats = await window.apolloAPI.getOSINTStats();
console.log(osintStats);
// Returns:
// {
//   total_queries: 156,
//   threat_sources: 5,
//   last_update: "2025-01-19T..."
// }
```

## 🧠 AI Oracle API

### Claude Integration
```javascript
const ApolloAIOracle = require('./src/ai/oracle-integration');

const oracle = new ApolloAIOracle();

// Analyze threat with context
const analysis = await oracle.analyzeThreat("malicious-indicator", {
  type: "url",
  source: "email",
  osintResults: [/* OSINT data */]
});

// Smart contract security analysis
const contractAnalysis = await oracle.analyzeSmartContract(
  "0xContractAddress",
  bytecode
);

// Phishing URL analysis
const phishingAnalysis = await oracle.analyzePhishingURL(
  "https://suspicious-site.com"
);
```

### Analysis Response Format
```javascript
{
  "threat_level": "MALICIOUS",
  "confidence": 85,
  "threat_family": "Lazarus",
  "technical_analysis": "Advanced persistent threat...",
  "recommendations": [
    "Quarantine immediately",
    "Perform deep forensic analysis"
  ],
  "iocs": ["192.168.1.100", "malicious.exe"],
  "timestamp": "2025-01-19T...",
  "source": "Claude AI Oracle",
  "model": "claude-opus-4-1-20250805"
}
```

## 🔍 OSINT Intelligence API

### Threat Intelligence Sources
```javascript
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');

const osint = new OSINTThreatIntelligence();

// Analyze URL for threats
const urlAnalysis = await osint.analyzeURL("https://suspicious.com");

// Check file hash reputation
const fileAnalysis = await osint.analyzeFileHash("sha256:abc123...");

// Cryptocurrency transaction analysis
const cryptoAnalysis = await osint.analyzeCryptoTransaction(
  "0x1234567890123456789012345678901234567890123456789012345678901234"
);
```

### OSINT Response Format
```javascript
{
  "indicator": "https://malicious.com",
  "malicious": true,
  "score": 0.95,
  "sources": [
    {
      "source": "VirusTotal",
      "malicious": true,
      "score": 0.9,
      "last_analysis": "2025-01-19T..."
    },
    {
      "source": "URLhaus",
      "malicious": true,
      "score": 1.0,
      "tags": ["phishing", "cryptocurrency"]
    }
  ],
  "timestamp": "2025-01-19T..."
}
```

## 🛡️ Protection Engine API

### Real-time Monitoring
```javascript
// Enable/disable protection modules
await window.apolloAPI.toggleProtection();

// Run deep system scan
const scanResult = await window.apolloAPI.runDeepScan();

// Emergency system isolation
const isolationResult = await window.apolloAPI.emergencyIsolation();
```

### Event Listeners
```javascript
// Listen for threat alerts
window.apolloAPI.onThreatAlert((alert) => {
  console.log('Threat detected:', alert);
  // Handle threat alert UI
});

// Listen for crypto alerts
window.apolloAPI.onCryptoAlert((alert) => {
  console.log('Crypto threat:', alert);
  // Handle crypto threat UI
});

// Listen for APT alerts
window.apolloAPI.onAPTAlert((alert) => {
  console.log('APT detected:', alert);
  // Handle APT alert UI
});
```

## ⚙️ Configuration API

### Settings Management
```javascript
// Load current configuration
const config = await window.apolloAPI.loadConfig();

// Save configuration changes
const saveResult = await window.apolloAPI.saveConfig({
  realTimeProtection: true,
  cryptoMonitoring: true,
  aptDetection: true,
  aiOracle: {
    enabled: true,
    provider: "anthropic",
    model: "claude-opus-4-1-20250805"
  }
});
```

### Environment Variables
```bash
# Required API keys
ANTHROPIC_API_KEY=sk-ant-api03-...
VIRUSTOTAL_API_KEY=abc123...
ALIENVAULT_OTX_API_KEY=def456...
SHODAN_API_KEY=ghi789...

# Optional configuration
AI_MODEL=claude-opus-4-1-20250805
NODE_ENV=production
DEBUG_MODE=false
```

## 📊 Statistics & Metrics API

### Real-time Metrics
```javascript
// Get protection statistics
const stats = await window.apolloAPI.getProtectionStatus();
console.log(stats.stats);
// Returns:
// {
//   threatsDetected: 0,
//   threatsBlocked: 0,
//   scansCompleted: 1247,
//   cryptoTransactionsProtected: 156,
//   aptDetections: 0,
//   osintQueries: 93,
//   phishingBlocked: 5,
//   malwareDetected: 2
// }

// Get AI Oracle statistics
const aiStats = await oracle.getStats();
console.log(aiStats);
// Returns:
// {
//   total_analyses: 42,
//   threat_context_entries: 4,
//   ai_model: "claude-opus-4-1-20250805",
//   ai_provider: "Anthropic Claude",
//   oracle_status: "active"
// }
```

## 🚨 Emergency Response API

### System Isolation
```javascript
// Activate emergency isolation
const isolation = await window.apolloAPI.emergencyIsolation();
if (isolation.success) {
  console.log('System isolated from network');
}

// Quarantine detected threats
const quarantine = await window.apolloAPI.quarantineThreats();

// Capture forensic evidence
const evidence = await window.apolloAPI.captureEvidence();
```

## 🔐 Security Considerations

### API Rate Limits
```javascript
// OSINT source rate limits
const rateLimits = {
  virusTotal: 4, // requests per minute
  alienVault: 1000, // requests per hour
  shodan: 100, // requests per month
  urlhaus: 1000 // requests per day
};

// AI Oracle rate limits (Anthropic)
const claudeLimits = {
  tier1: 5, // requests per minute
  tier2: 50, // requests per minute
  tier3: 1000 // requests per minute
};
```

### Error Handling
```javascript
try {
  const analysis = await oracle.analyzeThreat(indicator, context);

  if (analysis.error) {
    switch (analysis.error) {
      case 'API_KEY_MISSING':
        console.error('Configure ANTHROPIC_API_KEY');
        break;
      case 'RATE_LIMIT_EXCEEDED':
        console.error('Rate limit exceeded, retry later');
        break;
      case 'NETWORK_ERROR':
        console.error('Network connectivity issue');
        break;
      default:
        console.error('Unknown error:', analysis.error);
    }
  }

} catch (error) {
  console.error('API call failed:', error.message);
}
```

### Authentication & Security
```javascript
// API keys should be stored securely
const secureConfig = {
  // Use environment variables
  anthropicKey: process.env.ANTHROPIC_API_KEY,

  // Or encrypted configuration files
  configFile: await loadEncryptedConfig(),

  // Never hardcode keys in source
  // ❌ apiKey: "sk-ant-api03-..." // DON'T DO THIS
};
```

## 📱 CLI API

### Command Line Interface
```bash
# Test integrations
apollo --test-claude
apollo --test-osint
apollo --test-network

# Analysis commands
apollo --analyze-url https://suspicious.com
apollo --analyze-contract 0x1234...
apollo --analyze-file /path/to/file

# System commands
apollo --status
apollo --scan
apollo --isolate
apollo --update
```

### Response Formats
```bash
# JSON output for programmatic use
apollo --analyze-url https://suspicious.com --output json

# Human-readable output
apollo --analyze-url https://suspicious.com --output human

# Detailed analysis
apollo --analyze-url https://suspicious.com --verbose
```

## 🔧 Integration Examples

### Node.js Integration
```javascript
const { spawn } = require('child_process');

// Use Apollo CLI from Node.js
function analyzeURL(url) {
  return new Promise((resolve, reject) => {
    const apollo = spawn('apollo', ['--analyze-url', url, '--output', 'json']);

    let output = '';
    apollo.stdout.on('data', (data) => {
      output += data.toString();
    });

    apollo.on('close', (code) => {
      if (code === 0) {
        resolve(JSON.parse(output));
      } else {
        reject(new Error(`Apollo CLI exited with code ${code}`));
      }
    });
  });
}
```

### Python Integration
```python
import subprocess
import json

def analyze_contract(contract_address):
    """Analyze smart contract using Apollo CLI"""
    try:
        result = subprocess.run([
            'apollo',
            '--analyze-contract',
            contract_address,
            '--output',
            'json'
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            raise Exception(f"Apollo analysis failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        raise Exception("Apollo analysis timed out")
```

### REST API Wrapper
```javascript
// Express.js wrapper for Apollo functionality
const express = require('express');
const { spawn } = require('child_process');

const app = express();
app.use(express.json());

// URL analysis endpoint
app.post('/api/analyze/url', async (req, res) => {
  try {
    const { url } = req.body;
    const result = await analyzeURL(url);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Smart contract analysis endpoint
app.post('/api/analyze/contract', async (req, res) => {
  try {
    const { address, bytecode } = req.body;
    // Implement contract analysis
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Apollo API server running on port 3000');
});
```

This API reference provides comprehensive documentation for integrating with Apollo Security's threat analysis capabilities.