// Apollo Feedback Collection System
// Comprehensive user feedback and issue reporting for beta users

const { EventEmitter } = require('events');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class ApolloFeedbackSystem extends EventEmitter {
    constructor(logger = null) {
        super();

        this.logger = logger;
        this.feedbackDirectory = path.join(os.homedir(), '.apollo', 'feedback');
        this.pendingFeedback = new Map();
        this.feedbackHistory = [];
        this.maxHistorySize = 100;

        // Feedback categories
        this.categories = {
            BUG_REPORT: {
                title: 'Bug Report',
                priority: 'high',
                requiresLogs: true,
                autoCapture: ['system_info', 'error_logs', 'screenshot']
            },
            FEATURE_REQUEST: {
                title: 'Feature Request',
                priority: 'medium',
                requiresLogs: false,
                autoCapture: ['system_info']
            },
            PERFORMANCE_ISSUE: {
                title: 'Performance Issue',
                priority: 'high',
                requiresLogs: true,
                autoCapture: ['system_info', 'performance_metrics', 'memory_usage']
            },
            FALSE_POSITIVE: {
                title: 'False Positive Detection',
                priority: 'high',
                requiresLogs: true,
                autoCapture: ['threat_logs', 'file_info', 'scan_results']
            },
            THREAT_MISSED: {
                title: 'Threat Not Detected',
                priority: 'critical',
                requiresLogs: true,
                autoCapture: ['threat_logs', 'file_info', 'system_info']
            },
            USABILITY: {
                title: 'Usability Feedback',
                priority: 'medium',
                requiresLogs: false,
                autoCapture: ['system_info', 'ui_state']
            },
            GENERAL: {
                title: 'General Feedback',
                priority: 'low',
                requiresLogs: false,
                autoCapture: ['system_info']
            }
        };

        // Feedback endpoints
        this.endpoints = {
            submit: 'https://feedback.apollo-shield.org/v1/submit',
            status: 'https://feedback.apollo-shield.org/v1/status',
            update: 'https://feedback.apollo-shield.org/v1/update'
        };

        this.init();
    }

    async init() {
        try {
            await fs.ensureDir(this.feedbackDirectory);
            await this.loadPendingFeedback();
            await this.loadFeedbackHistory();

            // Set up automatic feedback triggers
            this.setupAutoTriggers();

            this.log('info', 'Apollo Feedback System initialized');

        } catch (error) {
            console.error('Failed to initialize Feedback System:', error);
        }
    }

    setupAutoTriggers() {
        // Auto-trigger feedback collection on critical events
        process.on('uncaughtException', (error) => {
            this.triggerAutoFeedback('BUG_REPORT', {
                title: 'Critical Application Error',
                description: `Uncaught exception: ${error.message}`,
                error: error,
                severity: 'critical'
            });
        });

        // Set up periodic satisfaction surveys
        this.setupSatisfactionSurveys();
    }

    setupSatisfactionSurveys() {
        // Show satisfaction survey after 7 days of usage
        setInterval(() => {
            this.checkForSatisfactionSurvey();
        }, 24 * 60 * 60 * 1000); // Daily check
    }

    async checkForSatisfactionSurvey() {
        const installDate = await this.getInstallDate();
        const daysSinceInstall = (Date.now() - installDate) / (1000 * 60 * 60 * 24);

        if (daysSinceInstall >= 7 && !this.hasSurveyBeenShown()) {
            this.showSatisfactionSurvey();
        }
    }

    // Main feedback submission
    async submitFeedback(feedbackData) {
        try {
            const feedback = await this.prepareFeedback(feedbackData);

            // Try to submit immediately
            const submitted = await this.sendFeedback(feedback);

            if (submitted) {
                await this.storeFeedbackLocally(feedback, 'submitted');
                this.addToHistory(feedback);

                this.log('info', 'Feedback submitted successfully', {
                    feedbackId: feedback.id,
                    category: feedback.category
                });

                return {
                    success: true,
                    feedbackId: feedback.id,
                    message: 'Thank you for your feedback! We\'ll review it promptly.',
                    trackingUrl: `https://feedback.apollo-shield.org/track/${feedback.id}`
                };
            } else {
                // Store for later retry
                await this.storeFeedbackLocally(feedback, 'pending');
                this.pendingFeedback.set(feedback.id, feedback);

                return {
                    success: true,
                    feedbackId: feedback.id,
                    message: 'Feedback saved locally and will be submitted when connection is available.',
                    status: 'pending'
                };
            }

        } catch (error) {
            this.log('error', 'Failed to submit feedback', {
                error: error.message,
                feedbackData: feedbackData
            });

            return {
                success: false,
                error: 'Failed to process feedback. Please try again.',
                details: error.message
            };
        }
    }

    async prepareFeedback(feedbackData) {
        const feedback = {
            id: this.generateFeedbackId(),
            timestamp: new Date().toISOString(),
            userId: this.getUserId(),
            category: feedbackData.category || 'GENERAL',
            title: feedbackData.title,
            description: feedbackData.description,
            rating: feedbackData.rating,
            severity: feedbackData.severity || 'medium',
            reproductionSteps: feedbackData.reproductionSteps,
            expectedBehavior: feedbackData.expectedBehavior,
            actualBehavior: feedbackData.actualBehavior,
            userContact: feedbackData.userContact,
            allowContact: feedbackData.allowContact || false,

            // Auto-captured data
            systemInfo: await this.captureSystemInfo(),
            applicationInfo: this.captureApplicationInfo(),
            attachments: [],

            // Metadata
            version: this.getApplicationVersion(),
            buildId: this.getBuildId(),
            sessionId: this.getSessionId()
        };

        // Auto-capture additional data based on category
        const categoryConfig = this.categories[feedback.category];
        if (categoryConfig && categoryConfig.autoCapture) {
            await this.addAutoCapture(feedback, categoryConfig.autoCapture);
        }

        return feedback;
    }

    async addAutoCapture(feedback, captureTypes) {
        for (const captureType of captureTypes) {
            try {
                switch (captureType) {
                    case 'error_logs':
                        feedback.attachments.push(await this.captureErrorLogs());
                        break;
                    case 'performance_metrics':
                        feedback.attachments.push(await this.capturePerformanceMetrics());
                        break;
                    case 'memory_usage':
                        feedback.attachments.push(this.captureMemoryUsage());
                        break;
                    case 'threat_logs':
                        feedback.attachments.push(await this.captureThreatLogs());
                        break;
                    case 'file_info':
                        if (feedback.filePath) {
                            feedback.attachments.push(await this.captureFileInfo(feedback.filePath));
                        }
                        break;
                    case 'screenshot':
                        if (feedback.includeScreenshot) {
                            feedback.attachments.push(await this.captureScreenshot());
                        }
                        break;
                    case 'ui_state':
                        feedback.attachments.push(this.captureUIState());
                        break;
                    case 'scan_results':
                        feedback.attachments.push(await this.captureScanResults());
                        break;
                }
            } catch (error) {
                this.log('warn', `Failed to capture ${captureType}`, { error: error.message });
            }
        }
    }

    // Auto-capture methods
    async captureSystemInfo() {
        return {
            type: 'system_info',
            data: {
                platform: os.platform(),
                arch: os.arch(),
                release: os.release(),
                cpus: os.cpus().length,
                totalMemory: os.totalmem(),
                freeMemory: os.freemem(),
                uptime: os.uptime(),
                hostname: os.hostname(),
                nodeVersion: process.version,
                processUptime: process.uptime(),
                processMemory: process.memoryUsage(),
                processCPU: process.cpuUsage()
            }
        };
    }

    captureApplicationInfo() {
        return {
            type: 'application_info',
            data: {
                version: this.getApplicationVersion(),
                buildId: this.getBuildId(),
                startTime: this.getApplicationStartTime(),
                features: this.getEnabledFeatures(),
                configuration: this.getSafeConfiguration()
            }
        };
    }

    async captureErrorLogs() {
        try {
            const logsDir = path.join(os.homedir(), '.apollo', 'logs');
            const logFiles = await fs.readdir(logsDir);

            // Get most recent log file
            const recentLog = logFiles
                .filter(file => file.endsWith('.log'))
                .sort()
                .pop();

            if (recentLog) {
                const logPath = path.join(logsDir, recentLog);
                const logContent = await fs.readFile(logPath, 'utf8');

                // Get last 100 lines
                const lines = logContent.split('\n').slice(-100);

                return {
                    type: 'error_logs',
                    filename: recentLog,
                    data: lines.join('\n')
                };
            }
        } catch (error) {
            return {
                type: 'error_logs',
                error: 'Could not capture error logs: ' + error.message
            };
        }
    }

    async capturePerformanceMetrics() {
        return {
            type: 'performance_metrics',
            data: {
                nodePerformance: performance.now(),
                eventLoopDelay: await this.measureEventLoopDelay(),
                gcStats: this.getGCStats(),
                resourceUsage: process.resourceUsage()
            }
        };
    }

    captureMemoryUsage() {
        return {
            type: 'memory_usage',
            data: {
                process: process.memoryUsage(),
                system: {
                    total: os.totalmem(),
                    free: os.freemem(),
                    used: os.totalmem() - os.freemem()
                },
                percentage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100
            }
        };
    }

    async captureThreatLogs() {
        // This would capture recent threat detection logs
        return {
            type: 'threat_logs',
            data: {
                recentThreats: [], // Would be populated from threat engine
                detectionHistory: [],
                falsePositives: [],
                missedThreats: []
            }
        };
    }

    async captureFileInfo(filePath) {
        try {
            const stats = await fs.stat(filePath);
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);

            stream.on('data', data => hash.update(data));

            return new Promise((resolve) => {
                stream.on('end', () => {
                    resolve({
                        type: 'file_info',
                        data: {
                            path: filePath,
                            size: stats.size,
                            created: stats.birthtime,
                            modified: stats.mtime,
                            sha256: hash.digest('hex'),
                            permissions: stats.mode,
                            isDirectory: stats.isDirectory()
                        }
                    });
                });
            });
        } catch (error) {
            return {
                type: 'file_info',
                error: 'Could not capture file info: ' + error.message
            };
        }
    }

    async captureScreenshot() {
        // This would capture a screenshot of the current application state
        return {
            type: 'screenshot',
            data: {
                timestamp: new Date().toISOString(),
                note: 'Screenshot capture would be implemented with platform-specific APIs'
            }
        };
    }

    captureUIState() {
        return {
            type: 'ui_state',
            data: {
                currentWindow: 'main',
                activeTab: 'dashboard',
                visibleElements: [],
                userActions: []
            }
        };
    }

    async captureScanResults() {
        return {
            type: 'scan_results',
            data: {
                lastScan: null,
                scanHistory: [],
                detectedThreats: [],
                scanSettings: {}
            }
        };
    }

    // Network submission
    async sendFeedback(feedback) {
        try {
            const response = await fetch(this.endpoints.submit, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': `Apollo-Feedback/${this.getApplicationVersion()}`,
                    'X-Apollo-Session': this.getSessionId()
                },
                body: JSON.stringify(feedback),
                timeout: 30000
            });

            if (response.ok) {
                const result = await response.json();

                this.emit('feedbackSubmitted', {
                    feedbackId: feedback.id,
                    serverResponse: result
                });

                return true;
            } else {
                throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
            }

        } catch (error) {
            this.log('warn', 'Failed to send feedback to server', {
                error: error.message,
                feedbackId: feedback.id
            });
            return false;
        }
    }

    // Retry pending feedback
    async retryPendingFeedback() {
        const pending = Array.from(this.pendingFeedback.values());
        let successCount = 0;

        for (const feedback of pending) {
            const submitted = await this.sendFeedback(feedback);

            if (submitted) {
                this.pendingFeedback.delete(feedback.id);
                await this.storeFeedbackLocally(feedback, 'submitted');
                successCount++;
            }
        }

        if (successCount > 0) {
            this.log('info', `Successfully submitted ${successCount} pending feedback items`);
        }

        return successCount;
    }

    // Auto-triggered feedback
    async triggerAutoFeedback(category, context) {
        const feedback = {
            category,
            title: context.title || `Auto-reported ${category}`,
            description: context.description || 'Automatically generated feedback',
            severity: context.severity || 'medium',
            autoGenerated: true,
            context: context
        };

        return await this.submitFeedback(feedback);
    }

    // Satisfaction surveys
    showSatisfactionSurvey() {
        this.emit('showSurvey', {
            type: 'satisfaction',
            questions: [
                {
                    id: 'overall_satisfaction',
                    type: 'rating',
                    question: 'How satisfied are you with Apollo overall?',
                    scale: 10
                },
                {
                    id: 'protection_effectiveness',
                    type: 'rating',
                    question: 'How effective is Apollo at protecting your system?',
                    scale: 10
                },
                {
                    id: 'performance_impact',
                    type: 'rating',
                    question: 'How would you rate Apollo\'s performance impact?',
                    scale: 10
                },
                {
                    id: 'ease_of_use',
                    type: 'rating',
                    question: 'How easy is Apollo to use?',
                    scale: 10
                },
                {
                    id: 'recommendation',
                    type: 'choice',
                    question: 'Would you recommend Apollo to others?',
                    options: ['Definitely', 'Probably', 'Maybe', 'Probably not', 'Definitely not']
                },
                {
                    id: 'improvements',
                    type: 'text',
                    question: 'What improvements would you like to see?',
                    optional: true
                }
            ]
        });
    }

    // Utility methods
    generateFeedbackId() {
        return `feedback_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }

    getUserId() {
        // This would retrieve the actual user ID from the license system
        return 'beta_user_' + crypto.randomBytes(4).toString('hex');
    }

    getApplicationVersion() {
        return '1.0.0-beta.1';
    }

    getBuildId() {
        return process.env.BUILD_ID || 'dev-build';
    }

    getSessionId() {
        if (!this.sessionId) {
            this.sessionId = crypto.randomBytes(8).toString('hex');
        }
        return this.sessionId;
    }

    getApplicationStartTime() {
        return new Date(Date.now() - process.uptime() * 1000).toISOString();
    }

    getEnabledFeatures() {
        return {
            aiOracle: true,
            osintIntegration: true,
            realTimeProtection: true,
            cryptoGuardian: true
        };
    }

    getSafeConfiguration() {
        // Return non-sensitive configuration data
        return {
            performanceMode: 'balanced',
            autoUpdates: true,
            telemetryLevel: 'standard'
        };
    }

    async measureEventLoopDelay() {
        return new Promise((resolve) => {
            const start = process.hrtime.bigint();
            setImmediate(() => {
                const delta = process.hrtime.bigint() - start;
                resolve(Number(delta) / 1000000); // Convert to milliseconds
            });
        });
    }

    getGCStats() {
        if (global.gc && global.gc.getStats) {
            return global.gc.getStats();
        }
        return null;
    }

    async getInstallDate() {
        // This would check the actual install date
        return Date.now() - (7 * 24 * 60 * 60 * 1000); // Mock: 7 days ago
    }

    hasSurveyBeenShown() {
        // Check if satisfaction survey has been shown
        return false; // Mock implementation
    }

    // Storage methods
    async storeFeedbackLocally(feedback, status) {
        try {
            const filename = `feedback-${feedback.id}.json`;
            const filepath = path.join(this.feedbackDirectory, filename);

            const data = {
                ...feedback,
                status,
                storedAt: new Date().toISOString()
            };

            await fs.writeJSON(filepath, data, { spaces: 2 });
        } catch (error) {
            this.log('error', 'Failed to store feedback locally', {
                feedbackId: feedback.id,
                error: error.message
            });
        }
    }

    async loadPendingFeedback() {
        try {
            const files = await fs.readdir(this.feedbackDirectory);

            for (const file of files) {
                if (file.startsWith('feedback-') && file.endsWith('.json')) {
                    const filepath = path.join(this.feedbackDirectory, file);
                    const data = await fs.readJSON(filepath);

                    if (data.status === 'pending') {
                        this.pendingFeedback.set(data.id, data);
                    }
                }
            }

            this.log('info', `Loaded ${this.pendingFeedback.size} pending feedback items`);
        } catch (error) {
            this.log('warn', 'Failed to load pending feedback', { error: error.message });
        }
    }

    async loadFeedbackHistory() {
        // Load recent feedback history for analytics
        this.feedbackHistory = [];
    }

    addToHistory(feedback) {
        this.feedbackHistory.push({
            id: feedback.id,
            category: feedback.category,
            timestamp: feedback.timestamp,
            status: 'submitted'
        });

        // Maintain history size
        if (this.feedbackHistory.length > this.maxHistorySize) {
            this.feedbackHistory.shift();
        }
    }

    // Statistics and reporting
    getFeedbackStatistics() {
        const stats = {
            totalSubmitted: this.feedbackHistory.length,
            pending: this.pendingFeedback.size,
            categories: {},
            recentActivity: this.feedbackHistory.slice(-10)
        };

        // Count by category
        this.feedbackHistory.forEach(item => {
            stats.categories[item.category] = (stats.categories[item.category] || 0) + 1;
        });

        return stats;
    }

    log(level, message, metadata = {}) {
        if (this.logger) {
            this.logger[level](message, metadata);
        } else {
            console.log(`[${level.toUpperCase()}] ${message}`, metadata);
        }
    }

    // Cleanup
    async shutdown() {
        // Attempt to submit any pending feedback
        await this.retryPendingFeedback();

        this.log('info', 'Feedback System shutting down');
        this.removeAllListeners();
    }
}

module.exports = ApolloFeedbackSystem;