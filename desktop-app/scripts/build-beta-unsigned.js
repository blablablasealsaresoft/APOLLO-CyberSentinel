#!/usr/bin/env node
/**
 * 🚀 APOLLO Beta Build Script (Unsigned for Development)
 * 
 * IMPORTANT: This is ONLY for development testing!
 * Production builds MUST use proper code signing certificates.
 */

const { build } = require('electron-builder');
const path = require('path');
const fs = require('fs');

console.log('🚀 APOLLO Beta Build (UNSIGNED - DEV ONLY)');
console.log('⚠️  WARNING: This build is NOT code-signed!');
console.log('🔐 Production builds require proper certificates!');
console.log('');

async function buildUnsignedBeta() {
    try {
        console.log('🧹 Cleaning previous builds...');
        
        // Temporarily modify package.json to disable signing
        const packagePath = path.join(__dirname, '..', 'package.json');
        const packageContent = fs.readFileSync(packagePath, 'utf8');
        const packageJson = JSON.parse(packageContent);
        
        // Backup original signing config
        const originalSign = packageJson.build.win.sign;
        
        // Temporarily disable signing for dev build
        packageJson.build.win.sign = false;
        
        // Write temporary config
        fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
        
        console.log('📦 Building unsigned beta for Windows...');
        
        await build({
            targets: { platform: 'win32', arch: 'x64' },
            config: {
                directories: {
                    output: 'dist-beta-unsigned'
                },
                artifactName: 'Apollo-Beta-UNSIGNED-${version}-${arch}.${ext}'
            }
        });
        
        // Restore original signing config
        packageJson.build.win.sign = originalSign;
        fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
        
        console.log('');
        console.log('✅ UNSIGNED BETA BUILD COMPLETE!');
        console.log('📁 Location: dist-beta-unsigned/');
        console.log('');
        console.log('🔐 NEXT STEPS FOR PRODUCTION:');
        console.log('   1. Obtain code signing certificate');
        console.log('   2. Configure environment variables');
        console.log('   3. Run: npm run build');
        console.log('');
        console.log('⚠️  DO NOT DISTRIBUTE UNSIGNED BUILDS TO USERS!');
        
    } catch (error) {
        console.error('❌ Build failed:', error.message);
        process.exit(1);
    }
}

buildUnsignedBeta();
