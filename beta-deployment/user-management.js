// Apollo Beta User Management System
// Manages beta testers, licensing, and access control

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

class ApolloBetaUserManager {
    constructor() {
        this.betaUsers = new Map();
        this.accessKeys = new Map();
        this.usageStats = new Map();
        this.feedbackData = new Map();

        // Beta program configuration
        this.config = {
            maxBetaUsers: 100,
            phases: {
                alpha: { maxUsers: 10, duration: '1_week' },
                security_community: { maxUsers: 30, duration: '2_weeks' },
                crypto_users: { maxUsers: 50, duration: '3_weeks' },
                general_beta: { maxUsers: 100, duration: '4_weeks' }
            },
            requirements: {
                alpha: ['internal_team', 'security_professional'],
                security_community: ['cybersecurity_background', 'signed_nda'],
                crypto_users: ['cryptocurrency_usage', 'high_value_target'],
                general_beta: ['application_approved', 'feedback_commitment']
            }
        };

        this.init();
    }

    async init() {
        console.log('🔐 Initializing Apollo Beta User Management...');

        await this.loadExistingUsers();
        await this.initializeSystemKeys();
        await this.setupAccessControl();

        console.log('✅ Beta User Management initialized');
    }

    async loadExistingUsers() {
        try {
            const usersFile = path.join(__dirname, 'data', 'beta-users.json');
            if (await fs.pathExists(usersFile)) {
                const userData = await fs.readJSON(usersFile);
                userData.users.forEach(user => {
                    this.betaUsers.set(user.id, user);
                });
                console.log(`📋 Loaded ${this.betaUsers.size} existing beta users`);
            }
        } catch (error) {
            console.warn('⚠️ Could not load existing users:', error.message);
        }
    }

    async initializeSystemKeys() {
        // Generate master keys for beta program
        this.masterKey = crypto.randomBytes(32).toString('hex');
        this.signingKey = crypto.randomBytes(32).toString('hex');

        console.log('🔑 System keys initialized');
    }

    async setupAccessControl() {
        // Initialize access control mechanisms
        this.accessLevels = {
            alpha: 10,
            beta: 5,
            limited: 1
        };

        console.log('🛡️ Access control configured');
    }

    // User registration and management
    async registerBetaUser(applicationData) {
        const {
            email,
            name,
            organization,
            background,
            useCase,
            phase,
            referralCode,
            agreedToTerms
        } = applicationData;

        // Validate application
        const validation = this.validateApplication(applicationData);
        if (!validation.valid) {
            return {
                success: false,
                error: validation.error,
                code: 'VALIDATION_FAILED'
            };
        }

        // Check if phase has capacity
        const phaseStats = this.getPhaseStatistics(phase);
        if (phaseStats.currentUsers >= phaseStats.maxUsers) {
            return {
                success: false,
                error: `Phase ${phase} is full. Please try a different phase or wait for next opening.`,
                code: 'PHASE_FULL'
            };
        }

        // Generate user ID and access credentials
        const userId = this.generateUserId();
        const accessKey = this.generateAccessKey(userId, phase);
        const licenseKey = this.generateLicenseKey(userId);

        const betaUser = {
            id: userId,
            email,
            name,
            organization,
            background,
            useCase,
            phase,
            status: 'pending_approval',
            createdAt: new Date().toISOString(),
            credentials: {
                accessKey,
                licenseKey,
                downloadTokens: this.generateDownloadTokens(userId)
            },
            permissions: this.getPhasePermissions(phase),
            limits: this.getPhaseLimits(phase),
            agreedToTerms,
            referralCode
        };

        // Store user
        this.betaUsers.set(userId, betaUser);
        await this.saveBetaUsers();

        // Initialize usage tracking
        this.usageStats.set(userId, {
            installDate: null,
            lastActive: null,
            threatsDetected: 0,
            crashReports: 0,
            feedbackSubmissions: 0,
            usageHours: 0
        });

        console.log(`✅ Beta user registered: ${email} (${phase})`);

        return {
            success: true,
            userId,
            accessKey,
            licenseKey,
            downloadUrls: this.generateDownloadUrls(betaUser),
            nextSteps: this.getOnboardingSteps(phase)
        };
    }

    validateApplication(data) {
        const required = ['email', 'name', 'background', 'useCase', 'phase', 'agreedToTerms'];

        for (const field of required) {
            if (!data[field]) {
                return {
                    valid: false,
                    error: `Missing required field: ${field}`
                };
            }
        }

        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(data.email)) {
            return {
                valid: false,
                error: 'Invalid email address'
            };
        }

        // Check if email already registered
        const existingUser = Array.from(this.betaUsers.values())
            .find(user => user.email === data.email);

        if (existingUser) {
            return {
                valid: false,
                error: 'Email already registered for beta program'
            };
        }

        // Validate phase requirements
        const phaseRequirements = this.config.requirements[data.phase];
        if (phaseRequirements) {
            // This would check against specific criteria
            // For now, we'll assume validation passes
        }

        return { valid: true };
    }

    async approveBetaUser(userId, approverNotes = '') {
        const user = this.betaUsers.get(userId);
        if (!user) {
            return { success: false, error: 'User not found' };
        }

        user.status = 'approved';
        user.approvedAt = new Date().toISOString();
        user.approverNotes = approverNotes;

        // Send approval notification
        await this.sendApprovalNotification(user);

        await this.saveBetaUsers();

        console.log(`✅ Beta user approved: ${user.email}`);

        return {
            success: true,
            downloadUrls: this.generateDownloadUrls(user),
            setupInstructions: this.getSetupInstructions(user.phase)
        };
    }

    // Access key validation
    validateAccessKey(accessKey, userId = null) {
        try {
            // Decrypt and validate access key
            const keyData = this.decryptAccessKey(accessKey);

            if (userId && keyData.userId !== userId) {
                return { valid: false, error: 'Key mismatch' };
            }

            const user = this.betaUsers.get(keyData.userId);
            if (!user) {
                return { valid: false, error: 'User not found' };
            }

            if (user.status !== 'approved') {
                return { valid: false, error: 'User not approved' };
            }

            // Check expiration
            if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
                return { valid: false, error: 'Access key expired' };
            }

            return {
                valid: true,
                user: user,
                permissions: user.permissions,
                limits: user.limits
            };

        } catch (error) {
            return { valid: false, error: 'Invalid access key' };
        }
    }

    // License key validation for application
    validateLicenseKey(licenseKey) {
        try {
            const licenseData = this.decryptLicenseKey(licenseKey);
            const user = this.betaUsers.get(licenseData.userId);

            if (!user || user.status !== 'approved') {
                return { valid: false };
            }

            // Update last active
            const stats = this.usageStats.get(licenseData.userId);
            if (stats) {
                stats.lastActive = new Date().toISOString();
            }

            return {
                valid: true,
                userId: licenseData.userId,
                phase: user.phase,
                permissions: user.permissions,
                limits: user.limits
            };

        } catch (error) {
            return { valid: false };
        }
    }

    // Usage tracking
    recordUsage(userId, usageData) {
        const stats = this.usageStats.get(userId);
        if (!stats) return;

        if (usageData.installDate && !stats.installDate) {
            stats.installDate = usageData.installDate;
        }

        if (usageData.threatsDetected) {
            stats.threatsDetected += usageData.threatsDetected;
        }

        if (usageData.sessionDuration) {
            stats.usageHours += usageData.sessionDuration / 3600000; // Convert ms to hours
        }

        if (usageData.crashReport) {
            stats.crashReports++;
        }

        stats.lastActive = new Date().toISOString();

        console.log(`📊 Usage recorded for user ${userId}`);
    }

    // Feedback collection
    async collectFeedback(userId, feedbackData) {
        if (!this.feedbackData.has(userId)) {
            this.feedbackData.set(userId, []);
        }

        const feedback = {
            id: crypto.randomUUID(),
            userId,
            timestamp: new Date().toISOString(),
            type: feedbackData.type,
            rating: feedbackData.rating,
            message: feedbackData.message,
            category: feedbackData.category,
            systemInfo: feedbackData.systemInfo,
            logs: feedbackData.logs
        };

        this.feedbackData.get(userId).push(feedback);

        // Update stats
        const stats = this.usageStats.get(userId);
        if (stats) {
            stats.feedbackSubmissions++;
        }

        console.log(`💬 Feedback collected from user ${userId}: ${feedbackData.type}`);

        return {
            success: true,
            feedbackId: feedback.id,
            message: 'Thank you for your feedback!'
        };
    }

    // Utility methods
    generateUserId() {
        return `beta_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }

    generateAccessKey(userId, phase) {
        const keyData = {
            userId,
            phase,
            createdAt: new Date().toISOString(),
            expiresAt: this.calculateExpiration(phase)
        };

        return this.encryptData(keyData, this.masterKey);
    }

    generateLicenseKey(userId) {
        const licenseData = {
            userId,
            type: 'beta',
            createdAt: new Date().toISOString()
        };

        return this.encryptData(licenseData, this.signingKey);
    }

    generateDownloadTokens(userId) {
        return {
            windows: this.generateDownloadToken(userId, 'windows'),
            macos: this.generateDownloadToken(userId, 'macos'),
            linux: this.generateDownloadToken(userId, 'linux')
        };
    }

    generateDownloadToken(userId, platform) {
        const tokenData = {
            userId,
            platform,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
        };

        return this.encryptData(tokenData, this.masterKey);
    }

    generateDownloadUrls(user) {
        const baseUrl = 'https://beta-releases.apollo-shield.org';
        const tokens = user.credentials.downloadTokens;

        return {
            windows: `${baseUrl}/download/windows?token=${tokens.windows}`,
            macos: `${baseUrl}/download/macos?token=${tokens.macos}`,
            linux: `${baseUrl}/download/linux?token=${tokens.linux}`
        };
    }

    getPhasePermissions(phase) {
        const permissions = {
            alpha: ['full_access', 'debug_mode', 'telemetry_detailed'],
            security_community: ['full_access', 'telemetry_standard'],
            crypto_users: ['crypto_focus', 'telemetry_standard'],
            general_beta: ['standard_access', 'telemetry_basic']
        };

        return permissions[phase] || permissions.general_beta;
    }

    getPhaseLimits(phase) {
        const limits = {
            alpha: { apiCalls: 1000, supportPriority: 'high' },
            security_community: { apiCalls: 500, supportPriority: 'medium' },
            crypto_users: { apiCalls: 300, supportPriority: 'medium' },
            general_beta: { apiCalls: 100, supportPriority: 'normal' }
        };

        return limits[phase] || limits.general_beta;
    }

    getPhaseStatistics(phase) {
        const users = Array.from(this.betaUsers.values())
            .filter(user => user.phase === phase);

        return {
            currentUsers: users.length,
            maxUsers: this.config.phases[phase]?.maxUsers || 0,
            approvedUsers: users.filter(u => u.status === 'approved').length,
            pendingUsers: users.filter(u => u.status === 'pending_approval').length
        };
    }

    getBetaStatistics() {
        const phases = Object.keys(this.config.phases);
        const stats = {
            totalUsers: this.betaUsers.size,
            maxUsers: this.config.maxBetaUsers,
            phases: {}
        };

        phases.forEach(phase => {
            stats.phases[phase] = this.getPhaseStatistics(phase);
        });

        return stats;
    }

    // Encryption/Decryption utilities
    encryptData(data, key) {
        const algorithm = 'aes-256-gcm';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, key);

        const encrypted = Buffer.concat([
            cipher.update(JSON.stringify(data), 'utf8'),
            cipher.final()
        ]);

        const authTag = cipher.getAuthTag();

        return Buffer.concat([iv, authTag, encrypted]).toString('base64');
    }

    decryptData(encryptedData, key) {
        const algorithm = 'aes-256-gcm';
        const buffer = Buffer.from(encryptedData, 'base64');

        const iv = buffer.slice(0, 16);
        const authTag = buffer.slice(16, 32);
        const encrypted = buffer.slice(32);

        const decipher = crypto.createDecipher(algorithm, key);
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]);

        return JSON.parse(decrypted.toString('utf8'));
    }

    decryptAccessKey(accessKey) {
        return this.decryptData(accessKey, this.masterKey);
    }

    decryptLicenseKey(licenseKey) {
        return this.decryptData(licenseKey, this.signingKey);
    }

    calculateExpiration(phase) {
        const durations = {
            alpha: 7 * 24 * 60 * 60 * 1000, // 1 week
            security_community: 14 * 24 * 60 * 60 * 1000, // 2 weeks
            crypto_users: 21 * 24 * 60 * 60 * 1000, // 3 weeks
            general_beta: 28 * 24 * 60 * 60 * 1000 // 4 weeks
        };

        return new Date(Date.now() + durations[phase]).toISOString();
    }

    async saveBetaUsers() {
        try {
            const dataDir = path.join(__dirname, 'data');
            await fs.ensureDir(dataDir);

            const usersFile = path.join(dataDir, 'beta-users.json');
            const userData = {
                lastUpdated: new Date().toISOString(),
                users: Array.from(this.betaUsers.values())
            };

            await fs.writeJSON(usersFile, userData, { spaces: 2 });
        } catch (error) {
            console.error('Failed to save beta users:', error);
        }
    }

    async sendApprovalNotification(user) {
        // This would integrate with email service
        console.log(`📧 Sending approval notification to ${user.email}`);
    }

    getOnboardingSteps(phase) {
        return [
            'Download Apollo from the provided links',
            'Install the application',
            'Enter your license key when prompted',
            'Complete the setup wizard',
            'Join the beta feedback community',
            'Report any issues through the feedback system'
        ];
    }

    getSetupInstructions(phase) {
        return {
            installation: 'Follow the platform-specific installation guide',
            configuration: 'Apollo will auto-configure with your beta settings',
            support: 'Access beta support through the in-app help system',
            feedback: 'Use Ctrl+F to submit feedback anytime'
        };
    }
}

module.exports = ApolloBetaUserManager;