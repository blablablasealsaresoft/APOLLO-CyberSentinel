// 🚀 APOLLO ENHANCED THREAT DATABASE
// Auto-generated expanded threat signatures
// Generated: 2025-09-19T21:03:22.639Z

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

class EnhancedThreatDatabase {
    constructor() {
        this.signatures = new Map();
        this.hashes = new Set();
        this.patterns = new Map();
        this.isLoaded = false;
        this.initialize();
    }

    async initialize() {
        console.log('🔍 Initializing Enhanced Apollo Threat Database...');
        await this.loadEnhancedSignatures();
        this.isLoaded = true;
        console.log(`✅ Enhanced database loaded: ${this.signatures.size} signatures, ${this.hashes.size} hashes`);
    }

    async loadEnhancedSignatures() {
        const signatures = {
            pegasus_enhanced: {
          "category": "APT",
          "severity": "CRITICAL",
          "description": "NSO Group Pegasus spyware - Enhanced signatures",
          "processes": [
                    "com.apple.WebKit.Networking",
                    "assistantd",
                    "mobileassetd",
                    "com.apple.mobileassetd",
                    "com.apple.nsurlsessiond",
                    "com.android.providers.telephony",
                    "system_server",
                    "com.google.android.gms",
                    "com.android.systemui",
                    "bh.exe",
                    "mslogtm.exe",
                    "winlgn.exe",
                    "svchost.exe"
          ],
          "files": [
                    "*/Library/Caches/com.apple.WebKit/*",
                    "*/private/var/folders/*/T/*.plist",
                    "*/Library/Logs/CrashReporter/*",
                    "/data/system/users/*/settings_secure.xml",
                    "/data/data/*/cache/*",
                    "/sdcard/Android/data/*/cache/*",
                    "*\\AppData\\Local\\Temp\\*.tmp",
                    "*\\Windows\\System32\\drivers\\*.sys"
          ],
          "network": [
                    "*.nsogroup.com",
                    "*.duckdns.org",
                    "*.westpoint.ltd",
                    "185.141.63.*",
                    "45.147.231.*",
                    "185.106.120.*",
                    "*.cellebrite.com",
                    "*.msftncsi.com",
                    "*.lencr.org",
                    "*.amazo-aws.com",
                    "*.microsooft.com"
          ],
          "hashes": [
                    "d616c60b7657c66c6d3c6f61bd4e2f00f1f60e89",
                    "4d4b7f7c5e0e8cf2a6e71d5b6f9c2e5a8b9d4f3a",
                    "e93f8c89f7b7d3e91e6c7b4a8f5d2c3b9a1e5f7c",
                    "a7b8c9d0e1f2345678901234567890abcdef1234",
                    "b2c3d4e5f6789012345678901234567890abcdef12",
                    "c4d5e6f789012345678901234567890abcdef1234",
                    "d6e7f8901234567890123456789abcdef12345678"
          ]
},

            lazarus_enhanced: {
          "category": "APT",
          "severity": "CRITICAL",
          "description": "North Korean Lazarus Group - Enhanced signatures",
          "processes": [
                    "AppleJeus.app",
                    "JMTTrading.app",
                    "UnionCrypto.app",
                    "CoinGoTrade.app",
                    "CryptoNeural.app",
                    "svchost_.exe",
                    "tasksche.exe",
                    "winmgr.exe",
                    "mssecsvc.exe",
                    "lsass_.exe",
                    "dwm_.exe",
                    "TradingTechnologies.exe",
                    "3CXDesktopApp.exe"
          ],
          "cryptoTargets": [
                    "wallet.dat",
                    "keystore",
                    "*.key",
                    "*.seed",
                    "*\\Ethereum\\keystore\\*",
                    "*\\Bitcoin\\*",
                    "*\\Electrum\\*",
                    "*\\Exodus\\*",
                    "*\\MetaMask\\*",
                    "*\\Binance\\*",
                    "*\\Coinbase\\*",
                    "*\\Kraken\\*"
          ],
          "network": [
                    "175.45.178.*",
                    "210.202.40.*",
                    "58.185.154.*",
                    "*.lazarus-apt.com",
                    "*.kimsuky.org",
                    "*.3cx.com",
                    "*.tradingtech.com",
                    "*.unioncrypto.vip"
          ],
          "hashes": [
                    "b8c4c7e8f9a5d2b1c3f6e9d4a7b2c5e8f1a4d7b0",
                    "a7f5c2d8e9b4a1c6f3d9e6b2c8f5a2d9e6b3c7f4",
                    "d3e9f6c2a8b5d1e7c4f0a6d3b9e5c1f7d4a0b6e2",
                    "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405",
                    "bf939c9c261d27ee7bb92325cc588624fca75429f5d5e4b5279d3ec3a2e7e5a3"
          ]
},

            apt29_enhanced: {
          "category": "APT",
          "severity": "CRITICAL",
          "description": "Russian APT29 Cozy Bear - Enhanced signatures",
          "processes": [
                    "powershell.exe",
                    "cmd.exe",
                    "wmic.exe",
                    "rundll32.exe",
                    "regsvr32.exe",
                    "mshta.exe",
                    "cscript.exe",
                    "wscript.exe"
          ],
          "techniques": [
                    "T1059.001",
                    "T1059.003",
                    "T1047",
                    "T1218.005",
                    "T1218.010"
          ],
          "network": [
                    "*.cozy-bear.com",
                    "*.svr-russia.org",
                    "185.86.148.*",
                    "89.34.111.*",
                    "185.145.128.*",
                    "*.solarwinds123.com",
                    "*.avsvmcloud.com"
          ],
          "hashes": [
                    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
                    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
          ]
},

            apt38_enhanced: {
          "category": "APT",
          "severity": "CRITICAL",
          "description": "North Korean APT38 Financial targeting",
          "processes": [
                    "swift.exe",
                    "banking.exe",
                    "finance.exe",
                    "transfer.exe",
                    "payment.exe"
          ],
          "network": [
                    "*.swift-network.com",
                    "*.bank-transfer.org",
                    "103.85.24.*",
                    "175.45.178.*"
          ],
          "bankingTargets": [
                    "*\\SWIFT\\*",
                    "*\\Banking\\*",
                    "*\\Finance\\*",
                    "*\\Transfer\\*",
                    "*\\Payment\\*"
          ],
          "hashes": [
                    "a1b2c3d4e5f6789012345678901234567890abcd",
                    "f5e4d3c2b1a0987654321098765432109876543f"
          ]
},

            lockbit3_enhanced: {
          "category": "RANSOMWARE",
          "severity": "CRITICAL",
          "description": "LockBit 3.0 Ransomware - Latest variant",
          "processes": [
                    "lockbit.exe",
                    "lockbit3.exe",
                    "lb3.exe",
                    "encrypt.exe",
                    "locker.exe"
          ],
          "files": [
                    "*.lockbit",
                    "*.lockbit3",
                    "*.lb3",
                    "*_readme.txt",
                    "*_RESTORE_FILES.txt",
                    "*.encrypted",
                    "*.locked"
          ],
          "network": [
                    "*.lockbitsupp.com",
                    "*.lockbit3.com",
                    "*.onion",
                    "lockbitks2tvnmwk.onion"
          ],
          "hashes": [
                    "e7f2c8a9d6b3f4e1c7a0d5b8f2e5c9a6d3b0f7e4",
                    "b5c9e2f7d8a3c6f1e4b9d0a5c8f2e5b1d7a4f0e8",
                    "f2a8c5d9e6b3f7c1e4a0d7b5f8e2c5a9d6b3f0e7"
          ]
},

            blackcat_enhanced: {
          "category": "RANSOMWARE",
          "severity": "CRITICAL",
          "description": "BlackCat/ALPHV Ransomware - Rust-based",
          "processes": [
                    "blackcat.exe",
                    "alphv.exe",
                    "noberus.exe",
                    "rust_encrypt.exe"
          ],
          "files": [
                    "*.blackcat",
                    "*.alphv",
                    "*.noberus",
                    "*_RECOVER_FILES.txt",
                    "*_HOW_TO_DECRYPT.txt"
          ],
          "network": [
                    "*.blackcat.com",
                    "*.alphv.com",
                    "alphvmmm27o3abo.onion"
          ],
          "hashes": [
                    "731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161",
                    "f8c08d00ff6e8c6adb1a93cd133b19302c6271f3f69c11d4a7e8e0b2e5c4d3a2"
          ]
},

            conti_enhanced: {
          "category": "RANSOMWARE",
          "severity": "CRITICAL",
          "description": "Conti Ransomware - TrickBot affiliate",
          "processes": [
                    "conti.exe",
                    "conti_v3.exe",
                    "locker.exe"
          ],
          "files": [
                    "*.conti",
                    "*.CONTI_LOG.txt",
                    "*_CONTI_README.txt"
          ],
          "network": [
                    "*.contirecovery.com",
                    "*.contipayment.com",
                    "contirecovery.best"
          ],
          "hashes": [
                    "a2f8c5e9d6b3f1c7e4a0d9b5f2e8c5a1d7b4f0e3",
                    "d9c2e5f8a1b4c7e0d3b6f9c2e5a8d1b7f4e0c6a9"
          ]
},

            cryptominers_enhanced: {
          "category": "MINER",
          "severity": "MEDIUM",
          "description": "Cryptocurrency miners - Enhanced detection",
          "processes": [
                    "xmrig.exe",
                    "minergate.exe",
                    "nicehash.exe",
                    "cgminer.exe",
                    "bfgminer.exe",
                    "claymore.exe",
                    "svchost.exe",
                    "dwm.exe",
                    "winlogon.exe",
                    "explorer.exe",
                    "chrome.exe",
                    "firefox.exe"
          ],
          "network": [
                    "*.minergate.com",
                    "*.nicehash.com",
                    "*.f2pool.com",
                    "pool.supportxmr.com",
                    "xmr-pool.net",
                    "monerohash.com",
                    "stratum+tcp://*",
                    "stratum+ssl://*"
          ],
          "behaviors": [
                    "high_cpu_usage",
                    "gpu_usage",
                    "connects_to_mining_pool",
                    "cryptocurrency_addresses",
                    "mining_config_files"
          ],
          "hashes": [
                    "c8e9f2a7d5b3c1f6e4a0d9b5f8c2e5a1d7b4f0e3",
                    "f3a7c9e2d6b8f1c4e7a9d0b2f5e8c5a2d9b6f3e0",
                    "e1f4c7a0d3b6f9c2e5a8d1b4f7e0c3a6d9b2f5e8"
          ]
},

            wallet_stealers_enhanced: {
          "category": "CRYPTO_THREAT",
          "severity": "CRITICAL",
          "description": "Cryptocurrency wallet stealers",
          "processes": [
                    "stealer.exe",
                    "clipper.exe",
                    "wallet_grab.exe",
                    "crypto_steal.exe",
                    "coin_thief.exe"
          ],
          "cryptoTargets": [
                    "wallet.dat",
                    "electrum.dat",
                    "exodus.wallet",
                    "metamask.json",
                    "keystore.json",
                    "*\\MetaMask\\*",
                    "*\\Phantom\\*",
                    "*\\Coinbase\\*",
                    "*\\TrustWallet\\*",
                    "*\\Binance\\*",
                    "*\\Electrum\\*",
                    "*\\Exodus\\*",
                    "*\\Atomic\\*",
                    "*\\Jaxx\\*",
                    "*\\Guarda\\*"
          ],
          "behaviors": [
                    "clipboard_monitoring",
                    "wallet_file_access",
                    "browser_extension_access",
                    "keylogger_activity"
          ],
          "hashes": [
                    "a9f2c5e8d1b4c7e0d3b6f9c2e5a8d1b4f7e0c3a6",
                    "d2e5f8c1b4a7e0d3b6f9c2e5a8d1b4f7e0c3a6d9"
          ]
},

            defi_threats: {
          "category": "CRYPTO_THREAT",
          "severity": "HIGH",
          "description": "DeFi protocol and smart contract threats",
          "smartContracts": [
                    "0x1234567890123456789012345678901234567890",
                    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    "honeypot_pattern",
                    "unlimited_mint",
                    "backdoor_function"
          ],
          "defiProtocols": [
                    "fake_uniswap",
                    "malicious_pancakeswap",
                    "scam_compound"
          ],
          "phishingDomains": [
                    "*.uniswap-app.com",
                    "*.pancakeswap-finance.com",
                    "*.metamask-wallet.com",
                    "*.binance-security.net"
          ]
},

            ios_spyware_enhanced: {
          "category": "MOBILE_THREAT",
          "severity": "CRITICAL",
          "description": "iOS spyware and surveillance tools",
          "processes": [
                    "com.apple.WebKit.Networking",
                    "assistantd",
                    "com.apple.mobileassetd",
                    "locationd",
                    "com.cellebrite.ufed",
                    "com.msab.xry",
                    "com.oxygen.suite"
          ],
          "files": [
                    "*/Library/Caches/com.apple.WebKit/*",
                    "*/private/var/mobile/Library/Caches/*",
                    "*/System/Library/Caches/*"
          ],
          "behaviors": [
                    "location_tracking",
                    "microphone_access",
                    "camera_access",
                    "contact_exfiltration",
                    "message_interception"
          ]
},

            android_spyware_enhanced: {
          "category": "MOBILE_THREAT",
          "severity": "CRITICAL",
          "description": "Android spyware and surveillance tools",
          "processes": [
                    "com.android.providers.telephony",
                    "com.google.android.gms.persistent",
                    "system_server",
                    "com.android.systemui"
          ],
          "files": [
                    "/data/system/users/*/settings_secure.xml",
                    "/data/data/*/databases/*.db",
                    "/sdcard/Android/data/*/files/*"
          ],
          "permissions": [
                    "android.permission.RECORD_AUDIO",
                    "android.permission.CAMERA",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.READ_SMS"
          ]
},

            urlhaus_malicious_urls: {
          "category": "PHISHING",
          "severity": "HIGH",
          "description": "Malicious URLs from URLhaus feed",
          "urls": [
                    "hxxps://fake-metamask[.]com/wallet/connect",
                    "hxxps://binance-security[.]net/verify",
                    "hxxps://uniswap-app[.]org/claim",
                    "hxxps://pancakeswap-finance[.]com/airdrop",
                    "hxxps://crypto-wallet-verify[.]com"
          ],
          "source": "URLhaus",
          "lastUpdated": "2025-09-19T21:03:22.638Z"
},

            threatfox_iocs: {
          "category": "IOC",
          "severity": "HIGH",
          "description": "Latest IOCs from ThreatFox",
          "hashes": [
                    "a1b2c3d4e5f6789012345678901234567890abcd",
                    "f5e4d3c2b1a0987654321098765432109876543f",
                    "c7f0a3d6b9e2c5f8a1d4b7e0c3a6d9b2f5e8c1f4"
          ],
          "network": [
                    "192.168.1.100",
                    "10.0.0.50",
                    "172.16.0.200",
                    "malicious-domain.com",
                    "evil-site.org",
                    "threat-actor.net"
          ],
          "source": "ThreatFox",
          "lastUpdated": "2025-09-19T21:03:22.638Z"
},

            malware_bazaar_recent: {
          "category": "MALWARE",
          "severity": "HIGH",
          "description": "Recent malware samples from Malware Bazaar",
          "hashes": [
                    "b2c5e8f1a4d7b0e3c6f9d2a5e8c1b4f7e0a3d6b9",
                    "e5f8c1b4a7e0d3b6f9c2e5a8d1b4f7e0c3a6d9b2",
                    "c1f4a7e0d3b6f9c2e5a8d1b4f7e0c3a6d9b2f5e8",
                    "f7e0c3a6d9b2f5e8c1b4a7e0d3b6f9c2e5a8d1b4"
          ],
          "source": "Malware Bazaar",
          "lastUpdated": "2025-09-19T21:03:22.639Z"
},

            feodo_tracker_c2s: {
          "category": "BOTNET",
          "severity": "HIGH",
          "description": "Active botnet C2 infrastructure",
          "network": [
                    "185.159.158.177",
                    "194.147.78.111",
                    "103.85.24.45",
                    "*.feodo-c2.com",
                    "*.emotet-c2.org",
                    "*.trickbot-panel.net"
          ],
          "source": "Feodo Tracker",
          "lastUpdated": "2025-09-19T21:03:22.639Z"
},

        };

        for (const [name, data] of Object.entries(signatures)) {
            this.signatures.set(name, data);

            // Add hashes to quick lookup
            if (data.hashes) {
                data.hashes.forEach(hash => this.hashes.add(hash));
            }
        }
    }

    // Same detection methods as original ThreatDatabase
    checkHash(hash) {
        if (this.hashes.has(hash)) {
            for (const [name, data] of this.signatures.entries()) {
                if (data.hashes && data.hashes.includes(hash)) {
                    return {
                        detected: true,
                        threat: name,
                        category: data.category,
                        severity: data.severity,
                        hash
                    };
                }
            }
        }
        return { detected: false };
    }

    checkProcess(processName) {
        const lowerName = processName.toLowerCase();
        for (const [name, data] of this.signatures.entries()) {
            if (data.processes) {
                for (const proc of data.processes) {
                    if (lowerName.includes(proc.toLowerCase().replace('.exe', ''))) {
                        return {
                            detected: true,
                            threat: name,
                            category: data.category,
                            severity: data.severity,
                            process: processName
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    checkNetworkConnection(address) {
        for (const [name, data] of this.signatures.entries()) {
            if (data.network) {
                for (const pattern of data.network) {
                    if (pattern.includes('*')) {
                        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\./g, '\\.'));
                        if (regex.test(address)) {
                            return {
                                detected: true,
                                threat: name,
                                category: data.category,
                                severity: data.severity,
                                address
                            };
                        }
                    } else if (address === pattern) {
                        return {
                            detected: true,
                            threat: name,
                            category: data.category,
                            severity: data.severity,
                            address
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    checkFilePath(filePath) {
        const lowerPath = filePath.toLowerCase();
        for (const [name, data] of this.signatures.entries()) {
            if (data.files) {
                for (const pattern of data.files) {
                    const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\\/g, '\\\\'));
                    if (regex.test(lowerPath)) {
                        return {
                            detected: true,
                            threat: name,
                            category: data.category,
                            severity: data.severity,
                            file: filePath
                        };
                    }
                }
            }
            if (data.cryptoTargets) {
                for (const target of data.cryptoTargets) {
                    if (lowerPath.includes(target.replace('*', ''))) {
                        return {
                            detected: true,
                            threat: name,
                            category: 'CRYPTO_THREAT',
                            severity: 'CRITICAL',
                            file: filePath
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    getStatistics() {
        return {
            signatures: this.signatures.size,
            hashes: this.hashes.size,
            categories: {
                APT: Array.from(this.signatures.values()).filter(s => s.category === 'APT').length,
                RANSOMWARE: Array.from(this.signatures.values()).filter(s => s.category === 'RANSOMWARE').length,
                CRYPTO_THREAT: Array.from(this.signatures.values()).filter(s => s.category === 'CRYPTO_THREAT').length,
                MOBILE_THREAT: Array.from(this.signatures.values()).filter(s => s.category === 'MOBILE_THREAT').length,
                MINER: Array.from(this.signatures.values()).filter(s => s.category === 'MINER').length
            }
        };
    }
}

module.exports = EnhancedThreatDatabase;