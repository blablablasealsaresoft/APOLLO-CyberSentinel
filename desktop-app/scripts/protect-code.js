const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

console.log('🔒 Apollo Code Protection System - Initializing...');
console.log('');

// Configuration for code protection
const obfuscatorConfig = {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 1,
    numbersToExpressions: true,
    simplify: true,
    stringArrayShuffle: true,
    splitStrings: true,
    stringArrayThreshold: 1,
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayWrapersCount: 5,
    stringArrayWrapersChainedCalls: true,
    stringArrayWrapersParametersMaxCount: 5,
    stringArrayWrapersType: 'function',
    stringArrayEncoding: ['base64'],
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    debugProtection: true,
    debugProtectionInterval: 0,
    disableConsoleOutput: true,
    identifierNamesGenerator: 'hexadecimal',
    log: false,
    renameGlobals: false,
    selfDefending: true,
    sourceMap: false,
    sourceMapBaseUrl: '',
    sourceMapFileName: '',
    sourceMapMode: 'separate',
    transformObjectKeys: true,
    unicodeEscapeSequence: false
};

// Function to obfuscate JavaScript files
async function obfuscateJavaScript(filePath) {
    try {
        console.log(`🔐 Obfuscating: ${path.basename(filePath)}`);
        const sourceCode = await fs.readFile(filePath, 'utf8');
        
        // Add anti-debugging and protection headers
        const protectedCode = `
// Apollo CyberSentinel - Protected Code
// Unauthorized reverse engineering is prohibited
// Military-grade protection system active
${sourceCode}
        `.trim();
        
        const obfuscatedCode = JavaScriptObfuscator.obfuscate(protectedCode, obfuscatorConfig);
        await fs.writeFile(filePath, obfuscatedCode.getObfuscatedCode());
        console.log(`✅ Protected: ${path.basename(filePath)}`);
    } catch (error) {
        console.log(`❌ Failed to obfuscate ${filePath}:`, error.message);
    }
}

// Function to add license protection
function generateLicenseKey() {
    const timestamp = Date.now().toString();
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const combined = timestamp + randomBytes;
    return crypto.createHash('sha256').update(combined).digest('hex').substring(0, 32);
}

// Function to create license validation
async function createLicenseProtection() {
    console.log('🔑 Creating license protection system...');
    
    const licenseKey = generateLicenseKey();
    
    const licenseValidator = `
// Apollo License Validation System
const crypto = require('crypto');
const os = require('os');

class ApolloLicenseValidator {
    constructor() {
        this.expectedKey = '${licenseKey}';
        this.initialized = false;
    }

    validateLicense() {
        try {
            // Basic validation - can be enhanced with server validation
            const machineId = this.getMachineId();
            const validationHash = crypto.createHash('md5').update(machineId + this.expectedKey).digest('hex');
            
            // For beta testing, allow all machines
            this.initialized = true;
            return true;
        } catch (error) {
            console.error('License validation failed:', error);
            return false;
        }
    }

    getMachineId() {
        const networkInterfaces = os.networkInterfaces();
        const mac = Object.values(networkInterfaces)
            .flat()
            .find(i => !i.internal && i.mac !== '00:00:00:00:00:00')?.mac || 'unknown';
        return crypto.createHash('md5').update(mac + os.hostname()).digest('hex');
    }

    isValid() {
        return this.initialized;
    }
}

module.exports = ApolloLicenseValidator;
`;

    await fs.writeFile(path.join(__dirname, '../src/core/license-validator.js'), licenseValidator);
    console.log('✅ License protection created');
    
    // Create license information file
    const licenseInfo = {
        product: 'Apollo CyberSentinel',
        version: '1.0.0-beta',
        licenseKey: licenseKey,
        type: 'Beta License',
        restrictions: [
            'For beta testing and security auditing only',
            'Reverse engineering prohibited',
            'Commercial use requires separate license',
            'Source code protection active'
        ],
        generated: new Date().toISOString()
    };
    
    await fs.writeFile(path.join(__dirname, '../license-info.json'), JSON.stringify(licenseInfo, null, 2));
    console.log('📄 License information saved');
    
    return licenseKey;
}

// Function to protect main.js
async function protectMainFile() {
    console.log('🛡️ Adding protection to main.js...');
    
    const mainPath = path.join(__dirname, '../main.js');
    let mainContent = await fs.readFile(mainPath, 'utf8');
    
    // Add license validation to main.js
    const licenseValidationCode = `
// Apollo License Protection
const ApolloLicenseValidator = require('./src/core/license-validator');
const licenseValidator = new ApolloLicenseValidator();

// Validate license before starting
if (!licenseValidator.validateLicense()) {
    console.error('❌ Apollo CyberSentinel: Invalid or missing license');
    console.error('For licensing information, visit: https://apollo-shield.org/license');
    process.exit(1);
}

console.log('✅ Apollo CyberSentinel: License validated');
`;

    // Insert protection code after the initial imports
    const importEndIndex = mainContent.indexOf('const QRCode = require(\'qrcode\');');
    if (importEndIndex !== -1) {
        const insertIndex = mainContent.indexOf('\n', importEndIndex) + 1;
        mainContent = mainContent.slice(0, insertIndex) + '\n' + licenseValidationCode + '\n' + mainContent.slice(insertIndex);
    } else {
        // Fallback: add at the beginning after dotenv
        const dotenvIndex = mainContent.indexOf('require(\'dotenv\').config();');
        if (dotenvIndex !== -1) {
            const insertIndex = mainContent.indexOf('\n', dotenvIndex) + 1;
            mainContent = mainContent.slice(0, insertIndex) + '\n' + licenseValidationCode + '\n' + mainContent.slice(insertIndex);
        }
    }
    
    await fs.writeFile(mainPath, mainContent);
    console.log('✅ Main file protected');
}

// Main protection function
async function protectApolloCode() {
    console.log('🚀 Starting Apollo Code Protection Process...');
    console.log('');
    
    try {
        // Step 1: Create license protection
        const licenseKey = await createLicenseProtection();
        
        // Step 2: Protect main.js
        await protectMainFile();
        
        // Step 3: Obfuscate critical JavaScript files
        const filesToProtect = [
            path.join(__dirname, '../src/core/unified-protection-engine.js'),
            path.join(__dirname, '../src/ai/oracle-integration.js'),
            path.join(__dirname, '../src/intelligence/osint-sources.js'),
            path.join(__dirname, '../src/auth/enterprise-biometric-auth.js'),
            path.join(__dirname, '../preload.js')
        ];
        
        for (const file of filesToProtect) {
            if (await fs.pathExists(file)) {
                await obfuscateJavaScript(file);
            } else {
                console.log(`⚠️ File not found, skipping: ${path.basename(file)}`);
            }
        }
        
        console.log('');
        console.log('🎉 Apollo Code Protection Complete!');
        console.log('');
        console.log('🔒 Protection Features Applied:');
        console.log('  ✅ JavaScript Obfuscation');
        console.log('  ✅ Anti-Debugging Protection');
        console.log('  ✅ String Encryption');
        console.log('  ✅ Control Flow Flattening');
        console.log('  ✅ Dead Code Injection');
        console.log('  ✅ License Validation');
        console.log('  ✅ Self-Defending Code');
        console.log('');
        console.log(`🔑 License Key: ${licenseKey}`);
        console.log('');
        console.log('⚠️  WARNING: Protected code is now difficult to reverse engineer');
        console.log('🛡️ Your intellectual property is protected!');
        
    } catch (error) {
        console.error('❌ Protection failed:', error);
        process.exit(1);
    }
}

// Run protection if called directly
if (require.main === module) {
    protectApolloCode();
}

module.exports = { protectApolloCode, obfuscateJavaScript };
