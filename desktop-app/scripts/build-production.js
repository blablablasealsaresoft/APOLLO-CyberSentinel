const builder = require('electron-builder');
const fs = require('fs-extra');
const path = require('path');
const { execSync } = require('child_process');

async function buildProduction() {
    console.log('🚀 Apollo Production Build Starting...');

    try {
        // Clean previous builds
        console.log('🧹 Cleaning previous builds...');
        await fs.remove(path.join(__dirname, '..', 'dist'));
        await fs.ensureDir(path.join(__dirname, '..', 'dist'));

        // Install dependencies
        console.log('📦 Installing dependencies...');
        execSync('npm install', { stdio: 'inherit', cwd: path.join(__dirname, '..') });

        // Run tests (optional, can be uncommented)
        // console.log('🧪 Running tests...');
        // execSync('npm test', { stdio: 'inherit', cwd: path.join(__dirname, '..') });

        // Build for all platforms
        console.log('🔨 Building Apollo for all platforms...');

        const config = {
            config: {
                appId: 'com.apollo.shield',
                productName: 'Apollo',
                copyright: '© 2025 Apollo Security',
                directories: {
                    output: 'dist',
                    buildResources: 'build'
                },
                files: [
                    'main.js',
                    'preload.js',
                    'src/**/*',
                    'ui/**/*',
                    'assets/**/*',
                    'node_modules/**/*',
                    '!node_modules/**/test/**',
                    '!node_modules/**/*.md',
                    '!node_modules/**/*.map',
                    '!**/*.{iml,o,hprof,orig,pyc,pyo,rbc,swp,csproj,sln,xproj}'
                ],
                extraResources: [
                    {
                        from: 'data',
                        to: 'data',
                        filter: ['**/*']
                    }
                ],
                asar: true,
                compression: 'maximum',
                nodeGypRebuild: false,
                npmRebuild: true,

                // Windows configuration
                win: {
                    target: [
                        {
                            target: 'nsis',
                            arch: ['x64', 'ia32']
                        },
                        {
                            target: 'portable',
                            arch: ['x64']
                        }
                    ],
                    icon: 'assets/apollo-icon.ico',
                    requestedExecutionLevel: 'requireAdministrator',
                    certificateFile: process.env.WINDOWS_CERTIFICATE,
                    certificatePassword: process.env.WINDOWS_CERTIFICATE_PASSWORD,
                    verifyUpdateCodeSignature: true,
                    publisherName: 'Apollo Security',
                    legalTrademarks: 'Apollo Security',
                    artifactName: 'Apollo-Setup-${version}-${arch}.${ext}'
                },

                // macOS configuration
                mac: {
                    target: [
                        {
                            target: 'dmg',
                            arch: ['x64', 'arm64']
                        },
                        {
                            target: 'zip',
                            arch: ['x64', 'arm64']
                        }
                    ],
                    icon: 'assets/apollo-icon.icns',
                    category: 'public.app-category.security',
                    hardenedRuntime: true,
                    gatekeeperAssess: false,
                    entitlements: 'build/entitlements.mac.plist',
                    entitlementsInherit: 'build/entitlements.mac.plist',
                    darkModeSupport: true,
                    artifactName: 'Apollo-${version}-${arch}.${ext}'
                },

                // Linux configuration
                linux: {
                    target: [
                        {
                            target: 'AppImage',
                            arch: ['x64']
                        },
                        {
                            target: 'deb',
                            arch: ['x64']
                        },
                        {
                            target: 'rpm',
                            arch: ['x64']
                        },
                        {
                            target: 'snap',
                            arch: ['x64']
                        }
                    ],
                    icon: 'assets/apollo-icon.png',
                    category: 'Security',
                    synopsis: 'Military-grade protection against nation-state threats',
                    description: 'Apollo provides comprehensive protection against advanced persistent threats, Pegasus spyware, and cryptocurrency threats.',
                    desktop: {
                        Name: 'Apollo',
                        Comment: 'Military-grade security',
                        Categories: 'Security;System;'
                    },
                    artifactName: 'Apollo-${version}-${arch}.${ext}'
                },

                // NSIS installer configuration
                nsis: {
                    oneClick: false,
                    perMachine: true,
                    allowToChangeInstallationDirectory: true,
                    installerIcon: 'assets/apollo-icon.ico',
                    uninstallerIcon: 'assets/apollo-icon.ico',
                    installerHeaderIcon: 'assets/apollo-icon.ico',
                    createDesktopShortcut: true,
                    createStartMenuShortcut: true,
                    shortcutName: 'Apollo Security',
                    license: 'LICENSE.txt',
                    runAfterFinish: true,
                    deleteAppDataOnUninstall: false,
                    include: 'build/installer.nsh',
                    script: 'build/installer-script.nsh'
                },

                // DMG configuration
                dmg: {
                    icon: 'assets/apollo-icon.icns',
                    background: 'assets/dmg-background.png',
                    title: 'Apollo ${version}',
                    window: {
                        width: 540,
                        height: 380
                    },
                    contents: [
                        {
                            x: 130,
                            y: 220
                        },
                        {
                            x: 410,
                            y: 220,
                            type: 'link',
                            path: '/Applications'
                        }
                    ]
                },

                // Auto-update configuration
                publish: [
                    {
                        provider: 'github',
                        owner: 'apollo-shield',
                        repo: 'desktop-app',
                        releaseType: 'release'
                    }
                ]
            }
        };

        // Build for current platform first (faster for testing)
        if (process.env.BUILD_TARGET === 'current') {
            console.log('📱 Building for current platform only...');
            await builder.build(config);
        } else {
            // Build for all platforms
            console.log('🌍 Building for all platforms...');

            // Windows build
            if (process.platform === 'win32' || process.env.BUILD_ALL) {
                console.log('🪟 Building for Windows...');
                await builder.build({
                    ...config,
                    targets: builder.Platform.WINDOWS.createTarget()
                });
            }

            // macOS build
            if (process.platform === 'darwin' || process.env.BUILD_ALL) {
                console.log('🍎 Building for macOS...');
                await builder.build({
                    ...config,
                    targets: builder.Platform.MAC.createTarget()
                });
            }

            // Linux build
            if (process.platform === 'linux' || process.env.BUILD_ALL) {
                console.log('🐧 Building for Linux...');
                await builder.build({
                    ...config,
                    targets: builder.Platform.LINUX.createTarget()
                });
            }
        }

        // Generate checksums
        console.log('🔐 Generating checksums...');
        await generateChecksums();

        // Create release notes
        console.log('📝 Creating release notes...');
        await createReleaseNotes();

        console.log('✅ Apollo Production Build Complete!');
        console.log('\n📦 Built packages are in the dist/ directory');
        console.log('🚀 Ready for distribution!');

        // Display build summary
        const distFiles = await fs.readdir(path.join(__dirname, '..', 'dist'));
        console.log('\n📊 Build Summary:');
        console.log('═══════════════════════════════════════');
        for (const file of distFiles) {
            if (!file.includes('.blockmap') && !file.includes('.yml')) {
                const stats = await fs.stat(path.join(__dirname, '..', 'dist', file));
                const sizeMB = (stats.size / (1024 * 1024)).toFixed(2);
                console.log(`  📦 ${file} (${sizeMB} MB)`);
            }
        }

    } catch (error) {
        console.error('❌ Build failed:', error);
        process.exit(1);
    }
}

async function generateChecksums() {
    const crypto = require('crypto');
    const distDir = path.join(__dirname, '..', 'dist');
    const files = await fs.readdir(distDir);
    const checksums = {};

    for (const file of files) {
        if (!file.includes('.blockmap') && !file.includes('.yml')) {
            const filePath = path.join(distDir, file);
            const fileBuffer = await fs.readFile(filePath);
            const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            checksums[file] = hash;
        }
    }

    await fs.writeFile(
        path.join(distDir, 'checksums-sha256.txt'),
        Object.entries(checksums).map(([file, hash]) => `${hash}  ${file}`).join('\n')
    );

    await fs.writeJSON(path.join(distDir, 'checksums.json'), checksums, { spaces: 2 });
}

async function createReleaseNotes() {
    const releaseNotes = `# Apollo v1.0.0 - Production Release

## 🚀 Features

### Military-Grade Protection
- Real-time detection of Pegasus spyware and nation-state threats
- Advanced Persistent Threat (APT) detection for North Korea, Russia, China
- Cryptocurrency wallet protection and smart contract analysis
- Emergency system isolation for critical threats

### System Integration
- Runs as system service with elevated privileges
- Network-level blocking of malicious connections
- Process termination with memory forensics
- File quarantine with hash-based blocking

### Cross-Platform Support
- Windows 10/11 (x64, x86)
- macOS 10.15+ (Intel, Apple Silicon)
- Linux (Ubuntu 20.04+, CentOS 8+, Fedora 35+)

## 🔐 Security Features
- Real malware signature database (15,000+ signatures)
- Behavioral analysis engine
- Zero-day threat detection
- Kernel-level protection hooks

## 📦 Installation

### Windows
\`\`\`powershell
# Run as Administrator
.\\Apollo-Setup-1.0.0-x64.exe
\`\`\`

### macOS
\`\`\`bash
# Open DMG and drag to Applications
open Apollo-1.0.0-arm64.dmg
\`\`\`

### Linux
\`\`\`bash
# AppImage (portable)
chmod +x Apollo-1.0.0-x64.AppImage
./Apollo-1.0.0-x64.AppImage

# Debian/Ubuntu
sudo dpkg -i Apollo-1.0.0-x64.deb

# RedHat/Fedora
sudo rpm -i Apollo-1.0.0-x64.rpm
\`\`\`

## ⚠️ Important Notes
- Administrator/root privileges required for full protection
- First launch may take longer due to initial setup
- Service installation happens automatically on first run

## 🆘 Support
- Documentation: https://docs.apollo-shield.org
- Issues: https://github.com/apollo-shield/desktop-app/issues
- Discord: https://discord.gg/apollo-shield

## 🔒 Verification
Verify your download using the provided SHA256 checksums in \`checksums-sha256.txt\`

---
*Apollo - Military-grade protection for the digital battlefield*
`;

    await fs.writeFile(path.join(__dirname, '..', 'dist', 'RELEASE_NOTES.md'), releaseNotes);
}

// Run the build
buildProduction();