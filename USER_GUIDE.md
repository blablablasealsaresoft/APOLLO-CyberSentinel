# 📚 Apollo Security - Complete User Guide

## 🎯 Table of Contents
1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Protection Features](#protection-features)
4. [AI Oracle & Threat Analysis](#ai-oracle--threat-analysis)
5. [OSINT Intelligence](#osint-intelligence)
6. [Emergency Features](#emergency-features)
7. [Settings & Configuration](#settings--configuration)
8. [Troubleshooting](#troubleshooting)

---

## 🚀 Getting Started

### First Launch
After installation, Apollo will automatically:
1. **Start background protection** - Real-time monitoring begins immediately
2. **Display system tray icon** - 🚀 indicates active protection
3. **Open dashboard** - Military-grade interface for threat monitoring
4. **Initialize AI Oracle** - Claude AI threat analysis system
5. **Connect OSINT sources** - Live threat intelligence feeds

### System Requirements
- **Windows**: 10/11 (64-bit) with Administrator privileges
- **macOS**: 10.15+ (Intel/Apple Silicon) with security permissions
- **Linux**: Ubuntu 18.04+, Fedora 30+, or equivalent with systemd
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 500MB free space for installation and threat database
- **Network**: Internet connection for threat intelligence updates

---

## 🖥️ Dashboard Overview

### Main Interface
```
┌─────────────────────────────────────────────────────────────┐
│ 🚀 Apollo                    Military-Grade Protection Active │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  📊 Threat Level: LOW      📈 Statistics                    │
│  Active Threats: 0         Total Scans: 1,247             │
│  Blocked Today: 0          Threats Blocked: 0             │
│  Last Scan: Just now       Crypto Tx Protected: 156       │
│                                                             │
│  🛡️ Protection Modules                                      │
│  ✅ Threat Engine    ✅ Crypto Shield                       │
│  ✅ APT Detector     ✅ Behavior Monitor                    │
│                                                             │
│  🔍 Real-time Activity                                      │
│  ✅ Apollo protection activated - all systems secured       │
│  🛡️ Threat database updated - 15,247 new signatures        │
│  🔍 System scan completed - no threats detected            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Status Indicators
- **🟢 GREEN**: All systems operational, no threats detected
- **🟡 YELLOW**: Potential threats under investigation
- **🔴 RED**: Active threats detected, immediate action required
- **🚀 Tray Icon**: Apollo running in background protection mode

---

## 🛡️ Protection Features

### 1. Real-time Threat Engine
**What it protects against:**
- **Pegasus spyware** - NSO Group zero-click exploits
- **Process injection** - Code injection and DLL hijacking
- **Network anomalies** - C2 communication detection
- **File system monitoring** - Suspicious file operations
- **Registry manipulation** - Persistence mechanism detection

**How it works:**
- Continuous background monitoring of system behavior
- AI-powered behavioral analysis for unknown threats
- Real-time blocking of malicious processes and network connections
- Automatic quarantine of suspicious files

### 2. APT Detector (Nation-State Protection)
**Target threats:**
- **North Korean APT** (Lazarus, Kimsuky, APT38)
- **Russian APT** (APT28, APT29, Fancy Bear)
- **Chinese APT** (APT1, APT40, PLA Unit 61398)
- **Iranian APT** (APT33, APT34, OilRig)
- **Commercial spyware** (Pegasus, Predator, Cellebrite)

**Detection methods:**
- Signature-based detection for known APT tools
- Behavioral analysis for living-off-the-land techniques
- Network traffic analysis for APT communication patterns
- Memory forensics for advanced payload detection

### 3. Crypto Guardian (WalletShield)
**Protection capabilities:**
- **Smart contract analysis** - Detects malicious contracts before interaction
- **Transaction monitoring** - Real-time safety assessment
- **Phishing detection** - Blocks fake wallet websites
- **Clipboard protection** - Prevents wallet address hijacking
- **DeFi security** - Analyzes yield farming and staking protocols

**Supported blockchains:**
- Ethereum (ETH) and ERC-20 tokens
- Bitcoin (BTC) and Bitcoin forks
- Binance Smart Chain (BSC)
- Polygon (MATIC)
- Avalanche (AVAX)

---

## 🧠 AI Oracle & Threat Analysis

### Claude AI Integration
Apollo uses **Anthropic Claude Opus** for advanced threat analysis:

**Model:** `claude-opus-4-1-20250805`
**Capabilities:**
- Nation-state threat classification and attribution
- Smart contract vulnerability assessment
- Phishing pattern recognition and analysis
- Zero-day exploit identification
- APT group behavior analysis

### Using AI Analysis Features

#### Smart Contract Analysis
1. Click **"Analyze Contract"** in Crypto Guardian section
2. Enter contract address (e.g., `0x1234...`)
3. Apollo performs multi-layered analysis:
   - Static code analysis for known vulnerabilities
   - AI-powered pattern recognition
   - OSINT lookup for known malicious contracts
   - Risk assessment with confidence score

#### Phishing URL Detection
1. Click **"Check Phishing"** button
2. Enter suspicious URL
3. AI Oracle analyzes:
   - Domain reputation and registration patterns
   - URL structure and obfuscation techniques
   - Content analysis for phishing indicators
   - Cross-reference with known phishing databases

#### Manual Threat Analysis
Access advanced AI analysis through:
- **Right-click context menu** on suspicious files
- **Command palette** (Ctrl+Shift+P) → "Analyze with AI"
- **Terminal interface** for technical users

---

## 🔍 OSINT Intelligence

### Live Threat Intelligence Sources
Apollo integrates with multiple OSINT sources for real-time threat detection:

#### Primary Sources
- **VirusTotal** - Malware detection and file reputation
- **AlienVault OTX** - Threat intelligence pulses and IOCs
- **URLhaus** - Malicious URL database
- **ThreatFox** - Indicator of Compromise (IOC) database
- **Shodan** - Network infrastructure analysis
- **Etherscan** - Blockchain transaction analysis

#### Intelligence Dashboard
Monitor OSINT activity in real-time:
```
🔍 Intelligence Sources
┌─────────────────┬─────────┬──────────┐
│ Source          │ Status  │ Queries  │
├─────────────────┼─────────┼──────────┤
│ VirusTotal      │ ACTIVE  │ 47       │
│ AlienVault OTX  │ ACTIVE  │ 23       │
│ URLhaus         │ ACTIVE  │ 15       │
│ ThreatFox       │ ACTIVE  │ 8        │
└─────────────────┴─────────┴──────────┘

OSINT Statistics:
• OSINT Queries: 93
• Phishing Blocked: 5
• Malware Detected: 2
• IOCs Collected: 127
```

---

## 🚨 Emergency Features

### System Isolation
**When to use:** Active nation-state attack detected
**What it does:**
- Immediately cuts all network connections
- Blocks all internet traffic (inbound/outbound)
- Preserves system state for forensic analysis
- Maintains local functionality for investigation

**How to activate:**
- Dashboard: Click **"System Isolation"** emergency button
- Keyboard shortcut: `Ctrl+Alt+I`
- System tray: Right-click → Emergency → Isolate System

### Threat Quarantine
**Automatic triggers:**
- High-confidence malware detection
- APT tool identification
- Suspicious process injection
- Crypto wallet hijacking attempt

**Manual quarantine:**
- Right-click suspicious files → "Quarantine with Apollo"
- Dashboard → Emergency Controls → "Quarantine Threats"

### Forensic Evidence Capture
**What gets captured:**
- Network traffic logs and packet captures
- Process execution history and memory dumps
- Registry changes and file system modifications
- Screenshot evidence of malicious activity
- Timeline of security events

**Storage location:** `~/.apollo/evidence/` (encrypted)

---

## ⚙️ Settings & Configuration

### Protection Settings
```
Real-time Protection: ✅ ENABLED
├── File system monitoring
├── Network traffic analysis
├── Process behavior tracking
└── Registry modification detection

Crypto Monitoring: ✅ ENABLED
├── Transaction analysis
├── Smart contract checking
├── Phishing detection
└── Clipboard protection

APT Detection: ✅ ENABLED
├── Nation-state signatures
├── Behavioral analysis
├── Network indicators
└── Memory scanning
```

### Advanced Configuration

#### API Keys Management
Access through: Settings → Advanced → API Configuration
```
🔑 Anthropic Claude: CONFIGURED ✅
🔍 VirusTotal: ACTIVE ✅
📡 AlienVault OTX: ACTIVE ✅
🌐 Shodan: ACTIVE ✅
⛓️ Etherscan: ACTIVE ✅
```

#### Notification Settings
- **Critical threats**: Always notify (recommended)
- **Medium threats**: Desktop notification
- **Low threats**: Log only
- **OSINT updates**: Weekly summary

#### Performance Tuning
- **CPU usage limit**: 25% (adjustable 10-50%)
- **Memory limit**: 1GB (adjustable 512MB-4GB)
- **Scan frequency**: Every 30 minutes (adjustable)
- **Network timeout**: 30 seconds

---

## 🔧 Troubleshooting

### Common Issues

#### "AI Oracle not responding"
**Cause:** Anthropic API key missing or invalid
**Solution:**
1. Check `.env` file for `ANTHROPIC_API_KEY`
2. Verify API key is valid and has credits
3. Test with: `npm run test:claude`

#### "OSINT sources unavailable"
**Cause:** Network connectivity or API rate limits
**Solution:**
1. Check internet connection
2. Verify firewall allows Apollo traffic
3. Wait for rate limit reset (usually 1 hour)

#### "High CPU usage"
**Cause:** Intensive scanning or malware activity
**Solution:**
1. Check Settings → Performance → CPU Limit
2. Run manual scan: Dashboard → "Deep Scan"
3. If persistent, check for actual threats

#### "Protection not starting"
**Cause:** Insufficient privileges or system interference
**Solution:**
1. **Windows**: Run as Administrator, check Windows Defender exclusions
2. **macOS**: Grant Full Disk Access in Security & Privacy
3. **Linux**: Ensure user has sudo privileges, check systemd service

### Performance Optimization

#### For Low-End Systems
```javascript
// Recommended settings for 4GB RAM systems
{
  "scanning": {
    "realTimeDepth": "basic",
    "cpuLimit": 15,
    "memoryLimit": "512MB"
  },
  "features": {
    "behaviorAnalysis": "simplified",
    "networkMonitoring": "essential",
    "aiOracle": "on-demand"
  }
}
```

#### For High-Performance Systems
```javascript
// Recommended settings for 16GB+ RAM systems
{
  "scanning": {
    "realTimeDepth": "maximum",
    "cpuLimit": 40,
    "memoryLimit": "2GB"
  },
  "features": {
    "behaviorAnalysis": "advanced",
    "networkMonitoring": "comprehensive",
    "aiOracle": "continuous"
  }
}
```

### Getting Help

#### Log Files
- **Application logs**: `~/.apollo/logs/apollo.log`
- **Threat detection**: `~/.apollo/logs/threats.log`
- **Network activity**: `~/.apollo/logs/network.log`
- **AI Oracle**: `~/.apollo/logs/ai-oracle.log`

#### Support Channels
- **Documentation**: https://docs.apollo-shield.org
- **Community Forum**: https://community.apollo-shield.org
- **Bug Reports**: https://github.com/apollo-shield/issues
- **Emergency Support**: security@apollo-shield.org

#### Self-Diagnostics
Run built-in diagnostic tools:
```bash
# Full system diagnostic
npm run diagnostic

# Network connectivity test
npm run test:network

# AI Oracle functionality test
npm run test:claude

# OSINT sources test
npm run test:osint
```

---

## 📊 Understanding Protection Metrics

### Dashboard Statistics Explained

#### Threat Level Indicators
- **LOW** (Green): Normal operation, no threats detected
- **MEDIUM** (Yellow): Potential threats under investigation
- **HIGH** (Orange): Confirmed threats detected and blocked
- **CRITICAL** (Red): Active attack in progress, emergency response activated

#### Key Metrics
- **Active Threats**: Currently detected and monitored threats
- **Blocked Today**: Threats prevented in last 24 hours
- **Total Scans**: Cumulative security scans performed
- **Crypto Tx Protected**: Cryptocurrency transactions analyzed
- **APT Detections**: Nation-state threat attempts identified
- **OSINT Queries**: Intelligence lookups performed
- **Phishing Blocked**: Malicious websites prevented
- **IOCs Collected**: Indicators of Compromise gathered

### When to Take Action

#### Immediate Action Required (RED)
- **Nation-state attack detected**: Activate system isolation
- **Crypto wallet compromise**: Disconnect from internet, move funds
- **Pegasus infection**: Full system forensics and reinstall
- **Data exfiltration**: Network isolation and incident response

#### Monitor Closely (YELLOW/ORANGE)
- **Suspicious network activity**: Review activity logs
- **Unknown file behavior**: Submit for AI analysis
- **Phishing attempts**: Update security awareness
- **API rate limiting**: Adjust query frequency

---

This comprehensive user guide covers all aspects of Apollo Security operation. For additional technical details, refer to the deployment documentation and API reference guides.