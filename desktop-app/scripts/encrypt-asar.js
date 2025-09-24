const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

console.log('🔐 ASAR Encryption System - Apollo CyberSentinel');
console.log('');

// Encryption configuration
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key
const IV = crypto.randomBytes(16); // 128-bit IV

class AsarProtector {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.key = ENCRYPTION_KEY;
        this.iv = IV;
    }

    encrypt(data) {
        const cipher = crypto.createCipher(this.algorithm, this.key);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }

    decrypt(encryptedData) {
        const decipher = crypto.createDecipher(this.algorithm, this.key);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    async protectAsarFile(asarPath) {
        try {
            console.log(`🔒 Encrypting ASAR: ${path.basename(asarPath)}`);
            
            if (!await fs.pathExists(asarPath)) {
                console.log(`⚠️ ASAR file not found: ${asarPath}`);
                return false;
            }

            // Read the ASAR file
            const asarData = await fs.readFile(asarPath);
            
            // Create backup
            const backupPath = asarPath + '.backup';
            await fs.copy(asarPath, backupPath);
            console.log(`💾 Backup created: ${path.basename(backupPath)}`);
            
            // Add protection header
            const protectionHeader = {
                protected: true,
                version: '1.0.0',
                algorithm: this.algorithm,
                timestamp: Date.now(),
                checksum: crypto.createHash('sha256').update(asarData).digest('hex')
            };
            
            const headerString = JSON.stringify(protectionHeader);
            const headerLength = Buffer.byteLength(headerString, 'utf8');
            
            // Create protected ASAR with header
            const headerLengthBuffer = Buffer.allocUnsafe(4);
            headerLengthBuffer.writeUInt32LE(headerLength, 0);
            
            const headerBuffer = Buffer.from(headerString, 'utf8');
            const encryptedData = this.encrypt(asarData.toString('base64'));
            const encryptedBuffer = Buffer.from(encryptedData, 'utf8');
            
            const protectedAsar = Buffer.concat([
                headerLengthBuffer,
                headerBuffer,
                encryptedBuffer
            ]);
            
            await fs.writeFile(asarPath, protectedAsar);
            console.log(`✅ ASAR encrypted: ${path.basename(asarPath)}`);
            
            return true;
        } catch (error) {
            console.error(`❌ Failed to encrypt ASAR:`, error.message);
            return false;
        }
    }

    async createDecryptionModule() {
        console.log('🔧 Creating ASAR decryption module...');
        
        const decryptorCode = `
// Apollo ASAR Decryption Module
// Protected Content Loader
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class AsarDecryptor {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.key = Buffer.from('${this.key.toString('hex')}', 'hex');
    }

    decrypt(encryptedData) {
        try {
            const decipher = crypto.createDecipher(this.algorithm, this.key);
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            throw new Error('Failed to decrypt protected content');
        }
    }

    loadProtectedAsar(asarPath) {
        try {
            const data = fs.readFileSync(asarPath);
            
            // Read header length
            const headerLength = data.readUInt32LE(0);
            
            // Read header
            const headerBuffer = data.slice(4, 4 + headerLength);
            const header = JSON.parse(headerBuffer.toString('utf8'));
            
            if (!header.protected) {
                throw new Error('ASAR is not protected');
            }
            
            // Read encrypted content
            const encryptedData = data.slice(4 + headerLength).toString('utf8');
            
            // Decrypt content
            const decryptedBase64 = this.decrypt(encryptedData);
            const originalData = Buffer.from(decryptedBase64, 'base64');
            
            // Verify checksum
            const checksum = crypto.createHash('sha256').update(originalData).digest('hex');
            if (checksum !== header.checksum) {
                throw new Error('ASAR integrity check failed');
            }
            
            return originalData;
        } catch (error) {
            console.error('Failed to load protected ASAR:', error.message);
            return null;
        }
    }
}

module.exports = AsarDecryptor;
`;

        await fs.writeFile(path.join(__dirname, '../src/core/asar-decryptor.js'), decryptorCode);
        console.log('✅ Decryption module created');
    }
}

async function protectAsar() {
    console.log('🚀 Starting ASAR Protection Process...');
    console.log('');
    
    const protector = new AsarProtector();
    
    // Protect main app.asar
    const asarPaths = [
        path.join(__dirname, '../dist/win-unpacked/resources/app.asar'),
        path.join(__dirname, '../dist/linux-unpacked/resources/app.asar'),
        path.join(__dirname, '../dist/mac/Apollo.app/Contents/Resources/app.asar')
    ];
    
    let protected = false;
    
    for (const asarPath of asarPaths) {
        if (await fs.pathExists(asarPath)) {
            const result = await protector.protectAsarFile(asarPath);
            if (result) protected = true;
        }
    }
    
    if (protected) {
        await protector.createDecryptionModule();
        console.log('');
        console.log('🎉 ASAR Protection Complete!');
        console.log('🔐 Your source code is now encrypted in the ASAR archive');
        console.log('⚠️ Reverse engineering is significantly more difficult');
    } else {
        console.log('⚠️ No ASAR files found to protect');
    }
}

// Run if called directly
if (require.main === module) {
    protectAsar();
}

module.exports = { protectAsar, AsarProtector };
