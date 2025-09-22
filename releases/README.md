# APOLLO CyberSentinel Releases

This directory contains release build scripts and documentation for creating distribution packages.

## Release Files

### Windows
- `apollo-cybersentinel-windows-x64.exe` - Full Windows installer with system integration
- `apollo-cybersentinel-portable.exe` - Portable Windows executable (no installation required)

### Linux
- `apollo-cybersentinel-linux-x64.AppImage` - Universal Linux application package

### macOS
- `apollo-cybersentinel-macos-x64.dmg` - Native macOS installer for Intel and Apple Silicon

## Build Instructions

1. **Windows Build**:
   ```bash
   # Using Electron Builder or similar
   npm run build:windows
   npm run dist:windows
   ```

2. **Linux Build**:
   ```bash
   # Using AppImage tools
   npm run build:linux
   npm run dist:appimage
   ```

3. **macOS Build**:
   ```bash
   # Using Electron Builder on macOS
   npm run build:macos
   npm run dist:dmg
   ```

## Release Process

1. Update version in package.json
2. Build all platform packages
3. Test on target platforms
4. Create GitHub release with all binaries
5. Update download links in landing page and installer

## Security

All release files are:
- Cryptographically signed
- Virus scanned
- Verified for integrity
- Include SHA256 checksums

## Support

For build issues or release questions, see the main repository documentation.