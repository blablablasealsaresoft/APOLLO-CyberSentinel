# 🔐 APOLLO Code Signing Certificates

## 🎯 CRITICAL SECURITY REQUIREMENT

Code signing is **MANDATORY** for cybersecurity software. This ensures:
- ✅ **Authenticity**: Users know the software is from you
- ✅ **Integrity**: Software hasn't been tampered with
- ✅ **Trust**: Windows Defender and antivirus won't flag it
- ✅ **Professional**: Required for enterprise deployment

## 📋 REQUIRED CERTIFICATES

### **Windows Code Signing Certificate**
- **File**: `apollo-code-sign.p12`
- **Type**: Authenticode Code Signing Certificate
- **Provider**: DigiCert, Sectigo, or similar trusted CA
- **Cost**: ~$200-400/year
- **Required for**: Windows .exe and .msi files

### **macOS Code Signing Certificate**
- **File**: `apollo-developer-id.p12`
- **Type**: Apple Developer ID Application
- **Provider**: Apple Developer Program
- **Cost**: $99/year
- **Required for**: macOS .app and .dmg files

## 🚀 HOW TO OBTAIN CERTIFICATES

### **1. Windows Certificate (Recommended: DigiCert)**
```bash
# 1. Go to DigiCert.com
# 2. Purchase "Code Signing Certificate"
# 3. Verify your organization (takes 1-3 business days)
# 4. Download .p12 file
# 5. Place in this directory as "apollo-code-sign.p12"
```

### **2. macOS Certificate (Apple Developer)**
```bash
# 1. Join Apple Developer Program ($99/year)
# 2. Create Developer ID Application certificate
# 3. Download from Xcode or Developer Portal
# 4. Export as .p12 file
# 5. Place in this directory as "apollo-developer-id.p12"
```

## 🔧 ENVIRONMENT SETUP

Create `.env` file in desktop-app directory:
```bash
# Code Signing Passwords
CERTIFICATE_PASSWORD=your_p12_password_here
APPLE_ID_PASSWORD=your_apple_id_password_here
```

## 🛡️ SECURITY NOTES

- **NEVER commit certificates to git**
- **Keep passwords in environment variables only**
- **Certificates expire annually - track renewal dates**
- **Backup certificates securely**

## 📊 CURRENT STATUS

- [ ] Windows Certificate (apollo-code-sign.p12)
- [ ] macOS Certificate (apollo-developer-id.p12)
- [ ] Environment variables configured
- [ ] Test signing successful

## 🚀 NEXT STEPS FOR BETA DEPLOYMENT

1. **Obtain certificates** (1-3 business days)
2. **Configure environment variables**
3. **Test build with signing**
4. **Deploy signed beta to testers**

**⚡ PRIORITY: Get certificates ASAP for beta launch!**
