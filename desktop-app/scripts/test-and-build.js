const { execSync } = require('child_process');
const fs = require('fs-extra');
const path = require('path');

async function testAndBuild() {
    console.log('🚀 Apollo Test & Build Pipeline Starting...');

    try {
        // Step 1: Environment Setup
        console.log('\n1️⃣ Setting up build environment...');
        process.chdir(path.join(__dirname, '..'));

        // Check Node.js version
        const nodeVersion = process.version;
        console.log(`Node.js version: ${nodeVersion}`);
        if (parseInt(nodeVersion.slice(1)) < 18) {
            throw new Error('Node.js 18+ required');
        }

        // Step 2: Install Dependencies
        console.log('\n2️⃣ Installing dependencies...');
        execSync('npm install', { stdio: 'inherit' });

        // Step 3: Lint Code
        console.log('\n3️⃣ Running code linting...');
        try {
            execSync('npm run lint', { stdio: 'inherit' });
        } catch (error) {
            console.warn('⚠️ Linting issues found, continuing...');
        }

        // Step 4: Run Basic Tests
        console.log('\n4️⃣ Running basic functionality tests...');
        await runBasicTests();

        // Step 5: Test Threat Detection
        console.log('\n5️⃣ Testing threat detection...');
        await testThreatDetection();

        // Step 6: Test System Integration
        console.log('\n6️⃣ Testing system integration...');
        await testSystemIntegration();

        // Step 7: Create Data Directory
        console.log('\n7️⃣ Creating data directory...');
        await createDataDirectory();

        // Step 8: Build for Current Platform
        console.log('\n8️⃣ Building Apollo executable...');
        process.env.BUILD_TARGET = 'current';
        execSync('node scripts/build-production.js', { stdio: 'inherit' });

        // Step 9: Post-Build Tests
        console.log('\n9️⃣ Running post-build tests...');
        await testBuiltExecutable();

        console.log('\n✅ Apollo Test & Build Pipeline Complete!');
        console.log('\n📦 Built executable ready for deployment');

    } catch (error) {
        console.error('\n❌ Build pipeline failed:', error);
        process.exit(1);
    }
}

async function runBasicTests() {
    console.log('  🧪 Testing core modules...');

    try {
        // Test threat database loading
        const ThreatDatabase = require('../src/signatures/threat-database');
        const db = new ThreatDatabase();
        console.log('  ✅ Threat database loaded');

        // Test system privileges
        const SystemPrivileges = require('../src/native/system-privileges');
        const privileges = new SystemPrivileges();
        console.log('  ✅ System privileges module loaded');

        // Test threat engines
        const ThreatEngine = require('../src/threat-engine/core');
        const engine = new ThreatEngine();
        console.log('  ✅ Threat engine loaded');

        const WalletShield = require('../src/crypto-guardian/wallet-shield');
        const wallet = new WalletShield();
        console.log('  ✅ Crypto guardian loaded');

        const APTDetector = require('../src/apt-detection/realtime-monitor');
        const apt = new APTDetector();
        console.log('  ✅ APT detector loaded');

    } catch (error) {
        throw new Error(`Core module test failed: ${error.message}`);
    }
}

async function testThreatDetection() {
    console.log('  🔍 Testing threat detection capabilities...');

    const ThreatDatabase = require('../src/signatures/threat-database');
    const db = new ThreatDatabase();

    // Test hash detection
    const testHash = 'd616c60b7657c66c6d3c6f61bd4e2f00f1f60e89'; // Pegasus hash
    const hashResult = db.checkHash(testHash);
    if (!hashResult.detected) {
        throw new Error('Hash detection test failed');
    }
    console.log('  ✅ Malware hash detection working');

    // Test process detection
    const processResult = db.checkProcess('com.apple.WebKit.Networking');
    if (!processResult.detected) {
        throw new Error('Process detection test failed');
    }
    console.log('  ✅ Malicious process detection working');

    // Test network detection
    const networkResult = db.checkNetworkConnection('185.141.63.120');
    if (!networkResult.detected) {
        throw new Error('Network detection test failed');
    }
    console.log('  ✅ Network threat detection working');
}

async function testSystemIntegration() {
    console.log('  🔧 Testing system integration...');

    const SystemPrivileges = require('../src/native/system-privileges');
    const privileges = new SystemPrivileges();

    // Test privilege checking
    const hasPrivileges = await privileges.checkPrivileges();
    console.log(`  📋 Running with privileges: ${hasPrivileges ? 'YES' : 'NO'}`);

    // Test threat blocker
    const ThreatBlocker = require('../src/native/threat-blocker');
    const blocker = new ThreatBlocker();
    console.log('  ✅ Threat blocker initialized');

    // Test basic status
    const status = blocker.getStatus();
    if (!status.hasOwnProperty('active')) {
        throw new Error('Threat blocker status test failed');
    }
    console.log('  ✅ System integration working');
}

async function createDataDirectory() {
    const dataDir = path.join(__dirname, '..', 'data');
    await fs.ensureDir(dataDir);

    // Create sample configuration
    const config = {
        version: '1.0.0',
        created: new Date().toISOString(),
        signatures: {
            version: '2025.01.19',
            count: 15247
        }
    };

    await fs.writeJSON(path.join(dataDir, 'config.json'), config, { spaces: 2 });
    console.log('  ✅ Data directory created');
}

async function testBuiltExecutable() {
    console.log('  🚀 Testing built executable...');

    const platform = process.platform;
    const distDir = path.join(__dirname, '..', 'dist');

    try {
        const files = await fs.readdir(distDir);
        let executableFound = false;

        if (platform === 'win32') {
            executableFound = files.some(f => f.endsWith('.exe'));
        } else if (platform === 'darwin') {
            executableFound = files.some(f => f.endsWith('.dmg'));
        } else {
            executableFound = files.some(f => f.endsWith('.AppImage'));
        }

        if (!executableFound) {
            throw new Error(`No executable found for platform: ${platform}`);
        }

        console.log('  ✅ Executable built successfully');

        // Check file sizes
        for (const file of files) {
            if (!file.includes('.blockmap') && !file.includes('.yml')) {
                const stats = await fs.stat(path.join(distDir, file));
                const sizeMB = (stats.size / (1024 * 1024)).toFixed(2);
                console.log(`  📦 ${file}: ${sizeMB} MB`);
            }
        }

    } catch (error) {
        throw new Error(`Executable test failed: ${error.message}`);
    }
}

// Additional helper function for manual testing
async function createTestScenarios() {
    console.log('\n🧪 Creating test scenarios...');

    const testDir = path.join(__dirname, '..', 'test-scenarios');
    await fs.ensureDir(testDir);

    // Create test malware file (harmless for testing)
    const testMalware = `
// Test file for Apollo detection
console.log("This is a test file with Pegasus indicators");
const process_name = "com.apple.WebKit.Networking";
const malicious_ip = "185.141.63.120";
    `;

    await fs.writeFile(path.join(testDir, 'test-malware.js'), testMalware);

    // Create test crypto transaction
    const testTx = {
        to: '0x0000000000000000000000000000000000000000',
        value: '1000000000000000000',
        data: '0xa9059cbb000000000000000000000000742d35cc6b96692cae98ae6b96692cae98ae6b96692cae98ae6b96692cae98ae6b96692cae98ae6b96692cae98ae6b96692cae'
    };

    await fs.writeJSON(path.join(testDir, 'test-transaction.json'), testTx, { spaces: 2 });

    console.log('  ✅ Test scenarios created in test-scenarios/');
}

// Run the test and build pipeline
testAndBuild().catch(console.error);