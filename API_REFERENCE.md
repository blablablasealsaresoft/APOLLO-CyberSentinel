# 🔌 APOLLO CyberSentinel - API Reference v2.0

## Overview
APOLLO CyberSentinel provides a comprehensive API for enhanced threat analysis, OSINT intelligence, and AI-powered security assessment with context-aware detection capabilities. This reference covers all available endpoints and integration methods.

## 🛡️ Enhanced Security APIs

### Process Analysis & Whitelisting
```javascript
// Analyze process with context awareness
const processAnalysis = await window.apolloAPI.analyzeProcess({
  processName: "powershell.exe",
  commandLine: "-EncodedCommand base64string...",
  parentProcess: "explorer.exe",
  pid: 1234
});

console.log(processAnalysis);
// Returns:
// {
//   suspicionLevel: 0.75,
//   confidenceScore: 75,
//   requiresConfirmation: true,
//   threatType: "LIVING_OFF_THE_LAND",
//   technique: "T1059.001",
//   reason: "Suspicious argument: -EncodedCommand",
//   parentProcess: "explorer.exe",
//   isWhitelisted: false
// }
```

### User Confirmation System
```javascript
// Request user confirmation for medium-confidence threats
const userDecision = await window.apolloAPI.requestUserConfirmation({
  threat: {
    type: "APT_DETECTION",
    severity: "high",
    details: {
      tool: "powershell.exe",
      technique: "T1059.001",
      confidenceScore: 75
    },
    pid: 1234,
    reason: "Potentially encoded command detected"
  },
  source: "Advanced Process Monitor"
});

console.log(userDecision);
// Returns: { approved: false, addToWhitelist: true }
```

### Process Whitelisting Management
```javascript
// Add process chain to whitelist
await window.apolloAPI.addToWhitelist("code.exe>powershell.exe");

// Check if process is whitelisted
const isWhitelisted = await window.apolloAPI.isProcessWhitelisted(
  "explorer.exe",
  "powershell.exe"
);

// Get current whitelist
const whitelist = await window.apolloAPI.getProcessWhitelist();
console.log(whitelist);
// Returns: ["explorer.exe>powershell.exe", "code.exe>powershell.exe", ...]
```

## 📡 Core Protection APIs

### Protection Status
```javascript
// Get enhanced protection status
const status = await window.apolloAPI.getProtectionStatus();
console.log(status);
// Returns:
// {
//   active: true,
//   version: "2.0.0",
//   stats: {
//     threatsDetected: 5,
//     threatsBlocked: 3,
//     falsePositivesReduced: 12,
//     confirmationsRequested: 2
//   },
//   engines: {
//     threatEngine: "active",
//     walletShield: "active",
//     contextAnalyzer: "active",
//     processGuard: "active"
//   },
//   features: {
//     contextAwareDetection: true,
//     processWhitelisting: true,
//     userConfirmation: true,
//     criticalProcessProtection: true
//   }
// }
```

### APT Detection
```javascript
// Get APT detection results
const aptStatus = await window.apolloAPI.getAPTDetectionStatus();
console.log(aptStatus);
// Returns:
// {
//   activeThreats: [
//     {
//       group: "apt29_cozy_bear",
//       technique: "T1059.001",
//       confidence: 85,
//       process: "powershell.exe",
//       status: "contained"
//     }
//   ],
//   detectionRules: 47,
//   lastUpdate: "2025-01-15T10:30:00Z"
// }
```

### Threat Analysis
```javascript
// Analyze smart contract with enhanced AI
const contractResult = await window.apolloAPI.analyzeSmartContract(
  "0x1234567890123456789012345678901234567890",
  bytecode, // optional
  { aiAnalysis: true, confidenceThreshold: 0.7 }
);

// Check phishing URL with context
const phishingResult = await window.apolloAPI.checkPhishingURL(
  "https://suspicious-site.com",
  {
    contextAnalysis: true,
    parentApplication: "browser.exe",
    userTriggered: true
  }
);

// Enhanced transaction monitoring
const transactionRisk = await window.apolloAPI.analyzeTransaction({
  to: "0xabcd...",
  value: "1000000000000000000",
  data: "0x...",
  contextualInfo: {
    userIntent: "token_swap",
    dappOrigin: "uniswap.org"
  }
});
```

## 🔍 Enhanced OSINT Integration

### Intelligence Sources with AI Analysis
```javascript
// Query intelligence sources with AI enhancement
const intelResult = await window.apolloAPI.queryIntelligence({
  indicator: "malicious-domain.com",
  type: "domain",
  sources: ["virustotal", "alienVault", "threatFox"],
  aiAnalysis: true,
  contextualScoring: true
});

console.log(intelResult);
// Returns:
// {
//   indicator: "malicious-domain.com",
//   riskScore: 95,
//   confidence: 92,
//   sources: {
//     virustotal: { detected: true, score: 85 },
//     alienVault: { pulses: 3, score: 90 },
//     threatFox: { malware_families: ["emotet"] }
//   },
//   aiAnalysis: {
//     assessment: "High confidence malicious domain",
//     reasoning: "Multiple sources confirm malware distribution",
//     recommendedAction: "block"
//   }
// }
```

### Threat Intelligence Feeds
```javascript
// Subscribe to enhanced threat feeds
await window.apolloAPI.subscribeThreatFeed({
  categories: ["apt", "crypto", "phishing"],
  confidence_threshold: 0.8,
  callback: (threat) => {
    console.log("New threat detected:", threat);
  }
});

// Get threat feed statistics
const feedStats = await window.apolloAPI.getThreatFeedStats();
console.log(feedStats);
// Returns:
// {
//   totalIndicators: 15000,
//   aptIndicators: 2500,
//   cryptoThreats: 8000,
//   phishingURLs: 4500,
//   lastUpdate: "2025-01-15T09:45:00Z",
//   accuracy: 0.95
// }
```

## 🧠 AI Oracle Integration

### Claude AI Analysis
```javascript
// Advanced AI threat analysis
const aiAnalysis = await window.apolloAPI.analyzeWithClaude({
  type: "process_behavior",
  data: {
    processName: "suspicious.exe",
    commandLine: "encoded_command_here",
    networkConnections: ["192.168.1.100:4444"],
    fileOperations: ["/tmp/payload.bin"]
  },
  model: "claude-opus-4-1-20250805",
  analysisDepth: "deep"
});

console.log(aiAnalysis);
// Returns:
// {
//   assessment: "HIGH_RISK",
//   confidence: 0.92,
//   reasoning: "Process exhibits clear APT characteristics...",
//   techniques: ["T1059.001", "T1071.001"],
//   recommendedActions: ["isolate", "investigate", "terminate"],
//   aptGroup: "apt29_cozy_bear"
// }
```

### Behavioral Analysis
```javascript
// Real-time behavioral analysis
const behaviorResult = await window.apolloAPI.analyzeBehavior({
  timeWindow: 300, // 5 minutes
  processFilter: ["powershell.exe", "cmd.exe"],
  networkMonitoring: true,
  fileSystemEvents: true
});

console.log(behaviorResult);
// Returns:
// {
//   suspicious_patterns: [
//     {
//       pattern: "encoded_powershell_execution",
//       confidence: 0.85,
//       processes: ["powershell.exe"],
//       technique: "T1059.001"
//     }
//   ],
//   baseline_deviation: 0.7,
//   risk_score: 82
// }
```

## 🔧 Configuration APIs

### Enhanced Security Settings
```javascript
// Configure context-aware detection
await window.apolloAPI.updateSecuritySettings({
  contextAnalysis: {
    enabled: true,
    confidenceThreshold: 0.7,
    requireConfirmationBelow: 0.8
  },
  processWhitelisting: {
    enabled: true,
    autoLearn: true,
    strictMode: false
  },
  criticalProcessProtection: {
    enabled: true,
    protectedProcesses: [
      "winlogon.exe", "csrss.exe", "lsass.exe"
    ]
  },
  userInteraction: {
    confirmMediumThreats: true,
    showConfidenceScores: true,
    allowWhitelistAddition: true
  }
});

// Get current configuration
const config = await window.apolloAPI.getSecurityConfiguration();
```

### API Key Management
```javascript
// Securely update API keys
await window.apolloAPI.updateAPIKeys({
  anthropic: "your_anthropic_key",
  virusTotal: "your_vt_key",
  alienVault: "your_otx_key"
});

// Test API connectivity
const connectivity = await window.apolloAPI.testAPIConnectivity();
console.log(connectivity);
// Returns:
// {
//   anthropic: { status: "connected", latency: 150 },
//   virusTotal: { status: "connected", rate_limit: 4 },
//   alienVault: { status: "connected", quota: 1000 }
// }
```

## 📊 Enhanced Statistics & Monitoring

### Detailed Statistics
```javascript
// Get comprehensive statistics
const detailedStats = await window.apolloAPI.getDetailedStatistics();
console.log(detailedStats);
// Returns:
// {
//   detection: {
//     totalThreats: 25,
//     aptDetections: 3,
//     falsePositives: 2,
//     userConfirmations: 5,
//     whitelistHits: 12
//   },
//   performance: {
//     averageAnalysisTime: 485, // ms
//     cpuUsage: 1.8, // %
//     memoryUsage: 145 // MB
//   },
//   confidence: {
//     averageScore: 0.84,
//     highConfidenceDetections: 18,
//     mediumConfidenceDetections: 7
//   }
// }
```

### Real-time Monitoring
```javascript
// Subscribe to real-time events
window.apolloAPI.onThreatDetected((threat) => {
  console.log("Threat detected:", threat);
  // {
  //   type: "APT_DETECTION",
  //   confidence: 0.89,
  //   process: "malicious.exe",
  //   action: "terminated",
  //   timestamp: "2025-01-15T10:30:00Z"
  // }
});

window.apolloAPI.onUserConfirmationRequired((request) => {
  console.log("User confirmation needed:", request);
  // Display confirmation dialog
});

window.apolloAPI.onWhitelistUpdated((update) => {
  console.log("Whitelist updated:", update);
});
```

## 🚨 Event System

### Enhanced Event Types
```javascript
// Subscribe to enhanced security events
const events = [
  'threat-detected',           // Enhanced threat detection
  'context-analysis-complete', // Context analysis finished
  'user-confirmation-required',// Medium-confidence threat needs approval
  'process-whitelisted',       // Process added to whitelist
  'critical-process-protected',// Critical process protection triggered
  'apt-signature-matched',     // APT group signature detected
  'confidence-score-calculated'// Threat confidence assessment
];

events.forEach(eventType => {
  window.apolloAPI.on(eventType, (data) => {
    console.log(`Event ${eventType}:`, data);
  });
});
```

## 🔒 Security Considerations

### API Security
- All API calls are validated and sanitized
- Sensitive data is encrypted in transit
- API keys are stored securely using OS keychain
- Rate limiting prevents abuse
- Audit logging for all security-related operations

### Error Handling
```javascript
try {
  const result = await window.apolloAPI.analyzeProcess(processData);
} catch (error) {
  console.error("API Error:", error);
  // Error types:
  // - "INVALID_INPUT": Invalid parameters
  // - "API_UNAVAILABLE": External service down
  // - "RATE_LIMITED": Too many requests
  // - "INSUFFICIENT_PERMISSIONS": Access denied
  // - "ANALYSIS_TIMEOUT": Operation timed out
}
```

## 📚 Integration Examples

### Complete Threat Analysis Workflow
```javascript
async function comprehensiveThreatAnalysis(processInfo) {
  try {
    // Step 1: Context analysis
    const contextResult = await window.apolloAPI.analyzeProcess(processInfo);

    // Step 2: Check whitelist
    if (contextResult.isWhitelisted) {
      return { action: "allow", reason: "whitelisted" };
    }

    // Step 3: AI analysis for high-confidence threats
    if (contextResult.suspicionLevel > 0.8) {
      const aiResult = await window.apolloAPI.analyzeWithClaude({
        type: "process_behavior",
        data: processInfo
      });

      return {
        action: "block",
        confidence: aiResult.confidence,
        reasoning: aiResult.reasoning
      };
    }

    // Step 4: User confirmation for medium threats
    if (contextResult.requiresConfirmation) {
      const userDecision = await window.apolloAPI.requestUserConfirmation({
        threat: contextResult,
        source: "Enhanced Detection Engine"
      });

      if (userDecision.addToWhitelist) {
        await window.apolloAPI.addToWhitelist(
          `${processInfo.parentProcess}>${processInfo.processName}`
        );
      }

      return {
        action: userDecision.approved ? "allow" : "block",
        reason: "user_decision"
      };
    }

    return { action: "allow", reason: "low_confidence" };

  } catch (error) {
    console.error("Threat analysis failed:", error);
    return { action: "block", reason: "analysis_error" };
  }
}
```

## 📖 API Versioning

### Current Version: 2.0.0
- Enhanced context-aware detection
- Process whitelisting system
- User confirmation workflows
- Critical process protection
- Improved confidence scoring

### Backwards Compatibility
All v1.x API endpoints remain functional with enhanced responses including confidence scores and context information.

---

🛡️ **For complete API documentation and examples, visit the [APOLLO CyberSentinel Documentation](docs/)**