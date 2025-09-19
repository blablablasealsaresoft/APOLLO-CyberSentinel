// Apollo Beta Telemetry and Monitoring System
// Anonymous usage analytics and performance monitoring for beta users

const { EventEmitter } = require('events');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class ApolloBetaTelemetry extends EventEmitter {
    constructor(logger = null, userManager = null) {
        super();

        this.logger = logger;
        this.userManager = userManager;
        this.sessionId = crypto.randomBytes(8).toString('hex');
        this.userId = null;
        this.isOptedIn = true; // Default for beta users
        this.batchSize = 50;
        this.flushInterval = 300000; // 5 minutes

        // Telemetry configuration
        this.config = {
            endpoints: {
                events: 'https://telemetry.apollo-shield.org/v1/events',
                metrics: 'https://telemetry.apollo-shield.org/v1/metrics',
                performance: 'https://telemetry.apollo-shield.org/v1/performance',
                errors: 'https://telemetry.apollo-shield.org/v1/errors'
            },
            levels: {
                minimal: ['basic_usage', 'crashes', 'errors'],
                standard: ['basic_usage', 'crashes', 'errors', 'performance', 'features'],
                detailed: ['basic_usage', 'crashes', 'errors', 'performance', 'features', 'detailed_metrics', 'user_flows']
            },
            anonymization: {
                hashUserData: true,
                excludePersonalInfo: true,
                aggregateSmallCounts: true
            }
        };

        // Event queues
        this.eventQueue = [];
        this.metricsQueue = [];
        this.performanceQueue = [];
        this.errorQueue = [];

        // Metrics tracking
        this.metrics = {
            session: {
                startTime: Date.now(),
                eventsCount: 0,
                errorsCount: 0,
                featuresUsed: new Set(),
                threatsDetected: 0,
                threatsBlocked: 0,
                scansPerformed: 0
            },
            application: {
                launchCount: 0,
                crashCount: 0,
                upgradeCount: 0,
                totalUsageTime: 0,
                averageSessionTime: 0
            },
            performance: {
                startupTime: 0,
                memoryPeak: 0,
                cpuPeak: 0,
                responseTimeAvg: 0,
                crashFrequency: 0
            },
            features: {
                aiOracleUsage: 0,
                osintQueries: 0,
                manualScans: 0,
                settingsChanges: 0,
                feedbackSubmissions: 0
            }
        };

        this.init();
    }

    async init() {
        try {
            await this.loadTelemetrySettings();
            await this.loadStoredMetrics();

            if (this.isOptedIn) {
                this.startTelemetryCollection();
                this.startPerformanceMonitoring();
                this.startBatchProcessor();
            }

            this.log('info', 'Apollo Beta Telemetry initialized', {
                sessionId: this.sessionId,
                optedIn: this.isOptedIn,
                level: this.getTelemetryLevel()
            });

        } catch (error) {
            this.log('error', 'Failed to initialize telemetry', { error: error.message });
        }
    }

    async loadTelemetrySettings() {
        try {
            const settingsFile = path.join(os.homedir(), '.apollo', 'config', 'telemetry.json');
            if (await fs.pathExists(settingsFile)) {
                const settings = await fs.readJSON(settingsFile);
                this.isOptedIn = settings.optedIn !== false; // Default to true for beta
                this.userId = settings.userId || this.generateAnonymousId();
            } else {
                this.userId = this.generateAnonymousId();
                await this.saveTelemetrySettings();
            }
        } catch (error) {
            this.userId = this.generateAnonymousId();
            this.log('warn', 'Could not load telemetry settings', { error: error.message });
        }
    }

    async saveTelemetrySettings() {
        try {
            const settingsDir = path.join(os.homedir(), '.apollo', 'config');
            await fs.ensureDir(settingsDir);

            const settings = {
                optedIn: this.isOptedIn,
                userId: this.userId,
                lastUpdated: new Date().toISOString()
            };

            const settingsFile = path.join(settingsDir, 'telemetry.json');
            await fs.writeJSON(settingsFile, settings, { spaces: 2 });
        } catch (error) {
            this.log('error', 'Failed to save telemetry settings', { error: error.message });
        }
    }

    startTelemetryCollection() {
        // Track application lifecycle
        this.trackEvent('app_start', {
            version: this.getAppVersion(),
            platform: os.platform(),
            arch: os.arch(),
            sessionId: this.sessionId
        });

        // Set up event listeners
        this.setupEventListeners();

        // Track session metrics
        this.startSessionTracking();
    }

    setupEventListeners() {
        // Application events
        process.on('exit', () => {
            this.trackSessionEnd();
            this.flush();
        });

        process.on('SIGINT', () => {
            this.trackSessionEnd();
            this.flush();
        });

        process.on('SIGTERM', () => {
            this.trackSessionEnd();
            this.flush();
        });

        // Error tracking
        process.on('uncaughtException', (error) => {
            this.trackError('uncaught_exception', error, { critical: true });
        });

        process.on('unhandledRejection', (reason) => {
            this.trackError('unhandled_rejection', reason, { critical: true });
        });
    }

    startSessionTracking() {
        // Track session metrics every minute
        this.sessionInterval = setInterval(() => {
            this.updateSessionMetrics();
        }, 60000);
    }

    startPerformanceMonitoring() {
        // Collect performance metrics every 30 seconds
        this.performanceInterval = setInterval(() => {
            this.collectPerformanceMetrics();
        }, 30000);
    }

    startBatchProcessor() {
        // Process and send telemetry batches every 5 minutes
        this.batchInterval = setInterval(() => {
            this.processBatches();
        }, this.flushInterval);
    }

    // Event tracking methods
    trackEvent(eventName, properties = {}) {
        if (!this.isOptedIn) return;

        const event = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            sessionId: this.sessionId,
            userId: this.userId,
            event: eventName,
            properties: this.sanitizeProperties(properties),
            platform: os.platform(),
            version: this.getAppVersion()
        };

        this.eventQueue.push(event);
        this.metrics.session.eventsCount++;

        this.log('debug', 'Event tracked', { eventName, properties: Object.keys(properties) });
    }

    trackFeatureUsage(featureName, context = {}) {
        this.metrics.session.featuresUsed.add(featureName);
        this.metrics.features[featureName + 'Usage'] = (this.metrics.features[featureName + 'Usage'] || 0) + 1;

        this.trackEvent('feature_used', {
            feature: featureName,
            context: this.sanitizeProperties(context)
        });
    }

    trackPerformanceMetric(metricName, value, unit = 'ms', tags = {}) {
        const metric = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            sessionId: this.sessionId,
            userId: this.userId,
            metric: metricName,
            value: value,
            unit: unit,
            tags: this.sanitizeProperties(tags)
        };

        this.metricsQueue.push(metric);

        // Update internal metrics
        if (metricName === 'response_time') {
            this.updateAverageResponseTime(value);
        } else if (metricName === 'memory_usage') {
            this.metrics.performance.memoryPeak = Math.max(this.metrics.performance.memoryPeak, value);
        }
    }

    trackError(errorType, error, context = {}) {
        this.metrics.session.errorsCount++;

        const errorData = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            sessionId: this.sessionId,
            userId: this.userId,
            type: errorType,
            message: error.message || String(error),
            stack: error.stack || null,
            context: this.sanitizeProperties(context),
            critical: context.critical || false
        };

        this.errorQueue.push(errorData);

        this.log('warn', 'Error tracked', {
            type: errorType,
            message: errorData.message,
            critical: errorData.critical
        });
    }

    trackThreatDetection(threatType, severity, blocked = false) {
        this.metrics.session.threatsDetected++;
        if (blocked) {
            this.metrics.session.threatsBlocked++;
        }

        this.trackEvent('threat_detected', {
            type: threatType,
            severity: severity,
            blocked: blocked,
            detectionEngine: 'unified_engine'
        });
    }

    trackScanActivity(scanType, duration, threatsFound = 0) {
        this.metrics.session.scansPerformed++;

        this.trackEvent('scan_completed', {
            type: scanType,
            duration: duration,
            threatsFound: threatsFound
        });

        this.trackPerformanceMetric('scan_duration', duration, 'ms', {
            scanType: scanType,
            threatsFound: threatsFound
        });
    }

    trackUserFlow(flowName, step, success = true, duration = null) {
        this.trackEvent('user_flow', {
            flow: flowName,
            step: step,
            success: success,
            duration: duration
        });
    }

    // Performance monitoring
    collectPerformanceMetrics() {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();

        // Memory metrics
        this.trackPerformanceMetric('memory_heap_used', memUsage.heapUsed, 'bytes');
        this.trackPerformanceMetric('memory_heap_total', memUsage.heapTotal, 'bytes');
        this.trackPerformanceMetric('memory_rss', memUsage.rss, 'bytes');

        // System metrics
        this.trackPerformanceMetric('system_memory_free', os.freemem(), 'bytes');
        this.trackPerformanceMetric('system_load_avg', os.loadavg()[0], 'load');

        // Update peaks
        const heapPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
        this.metrics.performance.memoryPeak = Math.max(this.metrics.performance.memoryPeak, heapPercent);

        // Check for performance issues
        if (heapPercent > 90) {
            this.trackEvent('performance_warning', {
                type: 'high_memory_usage',
                percentage: heapPercent
            });
        }
    }

    updateSessionMetrics() {
        const sessionDuration = Date.now() - this.metrics.session.startTime;

        this.trackPerformanceMetric('session_duration', sessionDuration, 'ms');
        this.trackPerformanceMetric('events_per_session', this.metrics.session.eventsCount, 'count');
        this.trackPerformanceMetric('features_used_per_session', this.metrics.session.featuresUsed.size, 'count');
    }

    trackSessionEnd() {
        const sessionDuration = Date.now() - this.metrics.session.startTime;

        this.trackEvent('app_end', {
            sessionDuration: sessionDuration,
            eventsCount: this.metrics.session.eventsCount,
            errorsCount: this.metrics.session.errorsCount,
            featuresUsed: Array.from(this.metrics.session.featuresUsed),
            threatsDetected: this.metrics.session.threatsDetected,
            threatsBlocked: this.metrics.session.threatsBlocked
        });

        // Update application metrics
        this.metrics.application.totalUsageTime += sessionDuration;
        this.updateAverageSessionTime(sessionDuration);
    }

    // Batch processing and transmission
    async processBatches() {
        if (!this.isOptedIn) return;

        try {
            // Process different types of data
            await Promise.all([
                this.processBatch('events', this.eventQueue),
                this.processBatch('metrics', this.metricsQueue),
                this.processBatch('performance', this.performanceQueue),
                this.processBatch('errors', this.errorQueue)
            ]);

        } catch (error) {
            this.log('error', 'Failed to process telemetry batches', { error: error.message });
        }
    }

    async processBatch(type, queue) {
        if (queue.length === 0) return;

        const batch = queue.splice(0, this.batchSize);
        const success = await this.sendBatch(type, batch);

        if (!success) {
            // Re-queue failed items
            queue.unshift(...batch);
            this.log('warn', `Failed to send ${type} batch, re-queued ${batch.length} items`);
        } else {
            this.log('debug', `Successfully sent ${type} batch with ${batch.length} items`);
        }
    }

    async sendBatch(type, batch) {
        try {
            const endpoint = this.config.endpoints[type] || this.config.endpoints.events;

            const payload = {
                type: type,
                timestamp: new Date().toISOString(),
                version: this.getAppVersion(),
                sessionId: this.sessionId,
                userId: this.userId,
                data: batch
            };

            const response = await this.sendToServer(endpoint, payload);
            return response.ok;

        } catch (error) {
            this.log('warn', `Failed to send ${type} batch`, { error: error.message });
            return false;
        }
    }

    async sendToServer(endpoint, payload) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': `Apollo-Telemetry/${this.getAppVersion()}`,
                    'X-Apollo-Session': this.sessionId,
                    'X-Telemetry-Level': this.getTelemetryLevel()
                },
                body: JSON.stringify(payload),
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            return response;

        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    // Data sanitization and privacy
    sanitizeProperties(properties) {
        const sanitized = {};

        for (const [key, value] of Object.entries(properties)) {
            // Skip sensitive data
            if (this.isSensitiveKey(key)) {
                sanitized[key] = '[REDACTED]';
                continue;
            }

            // Hash personal identifiers
            if (this.isPersonalIdentifier(key)) {
                sanitized[key] = this.hashValue(value);
                continue;
            }

            // Limit string length
            if (typeof value === 'string' && value.length > 1000) {
                sanitized[key] = value.substring(0, 1000) + '...';
                continue;
            }

            sanitized[key] = value;
        }

        return sanitized;
    }

    isSensitiveKey(key) {
        const sensitiveKeys = [
            'password', 'token', 'key', 'secret', 'auth',
            'email', 'username', 'phone', 'address',
            'ssn', 'credit', 'license'
        ];

        return sensitiveKeys.some(sensitive =>
            key.toLowerCase().includes(sensitive)
        );
    }

    isPersonalIdentifier(key) {
        const identifiers = ['userId', 'deviceId', 'installId'];
        return identifiers.includes(key);
    }

    hashValue(value) {
        return crypto.createHash('sha256').update(String(value)).digest('hex').substring(0, 16);
    }

    // Configuration and control
    setTelemetryLevel(level) {
        if (this.config.levels[level]) {
            this.telemetryLevel = level;
            this.saveTelemetrySettings();
            this.log('info', 'Telemetry level changed', { level });
        }
    }

    getTelemetryLevel() {
        return this.telemetryLevel || 'standard';
    }

    async optOut() {
        this.isOptedIn = false;
        await this.saveTelemetrySettings();
        this.stopTelemetryCollection();
        this.log('info', 'User opted out of telemetry');
    }

    async optIn() {
        this.isOptedIn = true;
        await this.saveTelemetrySettings();
        this.startTelemetryCollection();
        this.log('info', 'User opted into telemetry');
    }

    stopTelemetryCollection() {
        if (this.sessionInterval) {
            clearInterval(this.sessionInterval);
            this.sessionInterval = null;
        }

        if (this.performanceInterval) {
            clearInterval(this.performanceInterval);
            this.performanceInterval = null;
        }

        if (this.batchInterval) {
            clearInterval(this.batchInterval);
            this.batchInterval = null;
        }
    }

    // Utility methods
    generateAnonymousId() {
        return crypto.randomBytes(16).toString('hex');
    }

    getAppVersion() {
        return '1.0.0-beta.1';
    }

    updateAverageResponseTime(newTime) {
        const count = this.metrics.session.eventsCount || 1;
        this.metrics.performance.responseTimeAvg =
            ((this.metrics.performance.responseTimeAvg * (count - 1)) + newTime) / count;
    }

    updateAverageSessionTime(sessionTime) {
        this.metrics.application.launchCount++;
        const count = this.metrics.application.launchCount;
        this.metrics.application.averageSessionTime =
            ((this.metrics.application.averageSessionTime * (count - 1)) + sessionTime) / count;
    }

    // Analytics and reporting
    getAnalytics() {
        return {
            session: {
                ...this.metrics.session,
                featuresUsed: Array.from(this.metrics.session.featuresUsed),
                duration: Date.now() - this.metrics.session.startTime
            },
            application: this.metrics.application,
            performance: this.metrics.performance,
            queues: {
                events: this.eventQueue.length,
                metrics: this.metricsQueue.length,
                performance: this.performanceQueue.length,
                errors: this.errorQueue.length
            },
            settings: {
                optedIn: this.isOptedIn,
                level: this.getTelemetryLevel(),
                userId: this.userId.substring(0, 8) + '...'
            }
        };
    }

    async loadStoredMetrics() {
        // Load persistent metrics from storage
        try {
            const metricsFile = path.join(os.homedir(), '.apollo', 'telemetry', 'metrics.json');
            if (await fs.pathExists(metricsFile)) {
                const stored = await fs.readJSON(metricsFile);
                this.metrics.application = { ...this.metrics.application, ...stored.application };
            }
        } catch (error) {
            this.log('warn', 'Could not load stored metrics', { error: error.message });
        }
    }

    async saveMetrics() {
        try {
            const metricsDir = path.join(os.homedir(), '.apollo', 'telemetry');
            await fs.ensureDir(metricsDir);

            const metricsFile = path.join(metricsDir, 'metrics.json');
            await fs.writeJSON(metricsFile, this.metrics, { spaces: 2 });
        } catch (error) {
            this.log('error', 'Failed to save metrics', { error: error.message });
        }
    }

    async flush() {
        // Force send all queued data
        await this.processBatches();
        await this.saveMetrics();
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
        this.trackSessionEnd();
        this.stopTelemetryCollection();
        await this.flush();

        this.log('info', 'Beta Telemetry shutting down');
        this.removeAllListeners();
    }
}

module.exports = ApolloBetaTelemetry;