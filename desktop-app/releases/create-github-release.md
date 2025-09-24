# GitHub Release Creation Guide

## Step 1: Create Release on GitHub

1. Go to: https://github.com/blablablasealsaresoft/APOLLO-CyberSentinel/releases
2. Click "Create a new release"
3. Set tag: `v1.0.0-beta`
4. Set title: `Apollo CyberSentinel v1.0.0 Beta`
5. Set description:

```markdown
# Apollo CyberSentinel v1.0.0 Beta Release

🛡️ **Military-grade cybersecurity protection now in open beta testing!**

## What's New in Beta

- Complete nation-state threat detection system
- APT group protection (Pegasus, Lazarus, etc.)
- Cryptocurrency wallet security
- Real-time behavioral analysis
- Advanced forensic capabilities
- Pre-configured threat intelligence APIs

## Downloads

- **Windows**: `Apollo-Setup-1.0.0-x64.exe` (Portable executable)
- **Linux**: `Apollo-1.0.0-x64.tar.gz` (Extract and run)
- **macOS**: Coming soon (requires macOS build environment)

## Installation

### Windows
1. Download and run `Apollo-Setup-1.0.0-x64.exe`
2. No installation required - runs directly
3. For optimal protection, run as administrator

### Linux
1. Download `Apollo-1.0.0-x64.tar.gz`
2. Extract: `tar -xzf Apollo-1.0.0-x64.tar.gz`
3. Run: `./apollo`

## Beta Testing Notes

⚠️ **This is an unsigned beta build for testing purposes**

- Some antivirus software may flag unsigned builds
- API keys pre-configured for immediate testing
- Report issues via GitHub Issues
- Community feedback welcomed

## System Requirements

- Windows 10/11 or modern Linux distribution
- 4GB RAM (8GB recommended)
- 2GB free disk space
- Internet connection (optional)

## Features

✅ Nation-state threat protection  
✅ APT group detection  
✅ Cryptocurrency wallet security  
✅ Real-time behavioral analysis  
✅ Network monitoring  
✅ Biometric authentication  
✅ Advanced forensics  

## Support

- 📖 Documentation: Built into the application
- 🐛 Issues: Use GitHub Issues tab
- 💬 Community: Beta testing feedback welcome

---

**Next Release**: Production version with code signing and installer packages
```

6. Check "This is a pre-release"
7. Upload files from the releases directory

## Step 2: Upload Release Assets

Upload these files as release assets:
- `Apollo-Setup-1.0.0-x64.exe`
- `Apollo-1.0.0-x64.tar.gz`
- `README.md`

## Step 3: Test Download Links

After creating the release, test these URLs:
- https://github.com/blablablasealsaresoft/APOLLO-CyberSentinel/releases/latest/download/Apollo-Setup-1.0.0-x64.exe
- https://github.com/blablablasealsaresoft/APOLLO-CyberSentinel/releases/latest/download/Apollo-1.0.0-x64.tar.gz

## Step 4: Verify installer.html

Go to your installer.html page and test the download buttons to ensure they work with the actual release files.

## File Sizes for Reference

- Apollo-Setup-1.0.0-x64.exe: ~177MB
- Apollo-1.0.0-x64.tar.gz: ~100MB (compressed)

## Security Notes

- Files are unsigned for beta testing
- Production releases will include proper code signing
- Some antivirus software may quarantine unsigned executables
- This is normal for beta software
