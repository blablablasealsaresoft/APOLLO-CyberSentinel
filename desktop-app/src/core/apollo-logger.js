// Apollo Logging and Monitoring System
// Centralized logging with file rotation, metrics collection, and error tracking

const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');

class ApolloLogger extends EventEmitter {
    constructor() {
        super();

        this.logDirectory = path.join(os.homedir(), '.apollo', 'logs');
        this.currentLogFile = null;
        this.maxLogSize = 10 * 1024 * 1024; // 10MB
        this.maxLogFiles = 10;

        // Log levels
        this.levels = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3,
            CRITICAL: 4
        };

        this.currentLevel = this.levels.INFO;

        // Metrics collection
        this.metrics = {
            logs: {
                debug: 0,
                info: 0,
                warn: 0,
                error: 0,
                critical: 0
            },
            threats: {
                detected: 0,
                blocked: 0,
                quarantined: 0
            },
            performance: {
                averageResponseTime: 0,
                memoryUsage: [],
                cpuUsage: []
            },
            system: {
                uptime: Date.now(),
                lastHealthCheck: null,
                healthStatus: 'unknown'
            }
        };

        // Alert thresholds
        this.alertThresholds = {
            errorRate: 0.1, // 10% error rate
            memoryUsage: 0.8, // 80% memory usage
            responseTime: 5000, // 5 seconds
            diskSpace: 0.9 // 90% disk usage
        };

        this.init();
    }

    async init() {
        try {
            await fs.ensureDir(this.logDirectory);
            await this.initializeLogFile();
            await this.loadMetrics();

            // Start background tasks
            this.startMetricsCollection();
            this.startHealthChecks();
            this.startLogRotation();

            this.info('Apollo Logger initialized', {
                logDirectory: this.logDirectory,
                logLevel: Object.keys(this.levels)[this.currentLevel]
            });

        } catch (error) {
            console.error('Failed to initialize Apollo Logger:', error);
        }
    }

    async initializeLogFile() {
        const timestamp = new Date().toISOString().split('T')[0];
        this.currentLogFile = path.join(this.logDirectory, `apollo-${timestamp}.log`);

        // Create log file if it doesn't exist
        if (!await fs.pathExists(this.currentLogFile)) {
            await fs.writeFile(this.currentLogFile, `# Apollo Security Log - ${new Date().toISOString()}\n`);
        }
    }

    async log(level, message, metadata = {}) {
        if (this.levels[level] < this.currentLevel) {
            return; // Skip if below current log level
        }

        const logEntry = {
            timestamp: new Date().toISOString(),
            level: level,
            message: message,
            metadata: metadata,
            pid: process.pid,
            memory: process.memoryUsage(),
            hostname: os.hostname()
        };

        // Update metrics
        this.metrics.logs[level.toLowerCase()]++;

        // Write to file
        await this.writeToFile(logEntry);

        // Write to console in development
        if (process.env.NODE_ENV !== 'production') {
            this.writeToConsole(logEntry);
        }

        // Emit event for real-time monitoring
        this.emit('log', logEntry);

        // Check for alerts
        this.checkAlerts(logEntry);
    }

    async writeToFile(logEntry) {
        try {
            const logLine = JSON.stringify(logEntry) + '\n';
            await fs.appendFile(this.currentLogFile, logLine);

            // Check if log rotation is needed
            const stats = await fs.stat(this.currentLogFile);
            if (stats.size > this.maxLogSize) {
                await this.rotateLog();
            }

        } catch (error) {
            console.error('Failed to write log entry:', error);
        }
    }

    writeToConsole(logEntry) {
        const levelColors = {
            DEBUG: '\x1b[36m',   // Cyan
            INFO: '\x1b[32m',    // Green
            WARN: '\x1b[33m',    // Yellow
            ERROR: '\x1b[31m',   // Red
            CRITICAL: '\x1b[35m' // Magenta
        };

        const reset = '\x1b[0m';
        const color = levelColors[logEntry.level] || '';

        const timeStr = new Date(logEntry.timestamp).toLocaleTimeString();
        const levelStr = logEntry.level.padEnd(8);

        console.log(`${color}[${timeStr}] ${levelStr}${reset} ${logEntry.message}`);

        if (Object.keys(logEntry.metadata).length > 0) {
            console.log(`${color}└─${reset}`, JSON.stringify(logEntry.metadata, null, 2));
        }
    }

    async rotateLog() {
        try {
            const timestamp = Date.now();
            const rotatedName = path.join(
                this.logDirectory,
                `apollo-${new Date().toISOString().split('T')[0]}-${timestamp}.log`
            );

            await fs.move(this.currentLogFile, rotatedName);
            await this.initializeLogFile();

            // Clean up old log files
            await this.cleanupOldLogs();

            this.info('Log file rotated', {
                oldFile: rotatedName,
                newFile: this.currentLogFile
            });

        } catch (error) {
            console.error('Failed to rotate log:', error);
        }
    }

    async cleanupOldLogs() {
        try {
            const files = await fs.readdir(this.logDirectory);
            const logFiles = files
                .filter(file => file.startsWith('apollo-') && file.endsWith('.log'))
                .map(file => ({
                    name: file,
                    path: path.join(this.logDirectory, file),
                    stats: null
                }));

            // Get file stats
            for (const file of logFiles) {
                file.stats = await fs.stat(file.path);
            }

            // Sort by modification time (oldest first)
            logFiles.sort((a, b) => a.stats.mtime - b.stats.mtime);

            // Delete old files if we exceed the limit
            if (logFiles.length > this.maxLogFiles) {
                const filesToDelete = logFiles.slice(0, logFiles.length - this.maxLogFiles);

                for (const file of filesToDelete) {
                    await fs.unlink(file.path);
                    this.debug('Old log file deleted', { file: file.name });
                }
            }

        } catch (error) {
            console.error('Failed to cleanup old logs:', error);
        }
    }

    startMetricsCollection() {
        // Collect system metrics every 30 seconds
        setInterval(async () => {
            await this.collectSystemMetrics();
        }, 30000);
    }

    async collectSystemMetrics() {
        try {
            const memInfo = process.memoryUsage();
            const cpuUsage = process.cpuUsage();

            // Store metrics (keep last 100 data points)
            this.metrics.performance.memoryUsage.push({
                timestamp: Date.now(),
                rss: memInfo.rss,
                heapUsed: memInfo.heapUsed,
                heapTotal: memInfo.heapTotal,
                external: memInfo.external
            });

            if (this.metrics.performance.memoryUsage.length > 100) {
                this.metrics.performance.memoryUsage.shift();
            }

            // Check for memory alerts
            const memoryPercent = memInfo.heapUsed / memInfo.heapTotal;
            if (memoryPercent > this.alertThresholds.memoryUsage) {
                this.warn('High memory usage detected', {
                    percentage: (memoryPercent * 100).toFixed(2) + '%',
                    heapUsed: memInfo.heapUsed,
                    heapTotal: memInfo.heapTotal
                });
            }

        } catch (error) {
            this.error('Failed to collect system metrics', { error: error.message });
        }
    }

    startHealthChecks() {
        // Perform health checks every 60 seconds
        setInterval(async () => {
            await this.performHealthCheck();
        }, 60000);
    }

    async performHealthCheck() {
        try {
            const healthStatus = {
                timestamp: new Date().toISOString(),
                status: 'healthy',
                checks: {}
            };

            // Check disk space
            try {
                const stats = await fs.stat(this.logDirectory);
                healthStatus.checks.diskSpace = 'ok';
            } catch (error) {
                healthStatus.checks.diskSpace = 'error';
                healthStatus.status = 'unhealthy';
            }

            // Check log file writability
            try {
                await fs.access(this.currentLogFile, fs.constants.W_OK);
                healthStatus.checks.logFile = 'ok';
            } catch (error) {
                healthStatus.checks.logFile = 'error';
                healthStatus.status = 'unhealthy';
            }

            // Check memory usage
            const memInfo = process.memoryUsage();
            const memoryPercent = memInfo.heapUsed / memInfo.heapTotal;
            healthStatus.checks.memory = memoryPercent < this.alertThresholds.memoryUsage ? 'ok' : 'warning';

            this.metrics.system.lastHealthCheck = Date.now();
            this.metrics.system.healthStatus = healthStatus.status;

            if (healthStatus.status !== 'healthy') {
                this.warn('Health check failed', healthStatus);
            } else {
                this.debug('Health check passed', healthStatus);
            }

        } catch (error) {
            this.error('Health check error', { error: error.message });
        }
    }

    startLogRotation() {
        // Check for log rotation every hour
        setInterval(async () => {
            try {
                const stats = await fs.stat(this.currentLogFile);
                if (stats.size > this.maxLogSize) {
                    await this.rotateLog();
                }
            } catch (error) {
                this.error('Log rotation check failed', { error: error.message });
            }
        }, 3600000); // 1 hour
    }

    checkAlerts(logEntry) {
        // Critical and error level logs trigger immediate alerts
        if (logEntry.level === 'CRITICAL' || logEntry.level === 'ERROR') {
            this.emit('alert', {
                type: 'log_alert',
                level: logEntry.level,
                message: logEntry.message,
                metadata: logEntry.metadata,
                timestamp: logEntry.timestamp
            });
        }

        // Check error rate
        const totalLogs = Object.values(this.metrics.logs).reduce((sum, count) => sum + count, 0);
        const errorLogs = this.metrics.logs.error + this.metrics.logs.critical;
        const errorRate = totalLogs > 0 ? errorLogs / totalLogs : 0;

        if (errorRate > this.alertThresholds.errorRate && totalLogs > 10) {
            this.emit('alert', {
                type: 'high_error_rate',
                errorRate: (errorRate * 100).toFixed(2) + '%',
                totalLogs,
                errorLogs,
                timestamp: new Date().toISOString()
            });
        }
    }

    async loadMetrics() {
        try {
            const metricsFile = path.join(this.logDirectory, 'metrics.json');
            if (await fs.pathExists(metricsFile)) {
                const savedMetrics = await fs.readJSON(metricsFile);
                this.metrics = { ...this.metrics, ...savedMetrics };
            }
        } catch (error) {
            this.warn('Failed to load saved metrics', { error: error.message });
        }
    }

    async saveMetrics() {
        try {
            const metricsFile = path.join(this.logDirectory, 'metrics.json');
            await fs.writeJSON(metricsFile, this.metrics, { spaces: 2 });
        } catch (error) {
            this.error('Failed to save metrics', { error: error.message });
        }
    }

    // Public logging methods
    debug(message, metadata = {}) {
        return this.log('DEBUG', message, metadata);
    }

    info(message, metadata = {}) {
        return this.log('INFO', message, metadata);
    }

    warn(message, metadata = {}) {
        return this.log('WARN', message, metadata);
    }

    error(message, metadata = {}) {
        return this.log('ERROR', message, metadata);
    }

    critical(message, metadata = {}) {
        return this.log('CRITICAL', message, metadata);
    }

    // Threat-specific logging methods
    threatDetected(threat) {
        this.metrics.threats.detected++;
        this.warn('Threat detected', {
            type: threat.type,
            severity: threat.severity,
            source: threat.source,
            details: threat.details
        });
    }

    threatBlocked(threat) {
        this.metrics.threats.blocked++;
        this.info('Threat blocked', {
            type: threat.type,
            severity: threat.severity,
            action: 'blocked',
            details: threat.details
        });
    }

    threatQuarantined(threat, path) {
        this.metrics.threats.quarantined++;
        this.info('Threat quarantined', {
            type: threat.type,
            originalPath: path,
            quarantineTime: new Date().toISOString()
        });
    }

    // Performance logging
    logPerformance(operation, duration, metadata = {}) {
        this.debug('Performance metric', {
            operation,
            duration: `${duration}ms`,
            ...metadata
        });

        if (duration > this.alertThresholds.responseTime) {
            this.warn('Slow operation detected', {
                operation,
                duration: `${duration}ms`,
                threshold: `${this.alertThresholds.responseTime}ms`
            });
        }
    }

    // Get current metrics
    getMetrics() {
        return {
            ...this.metrics,
            uptime: Date.now() - this.metrics.system.uptime,
            logLevel: Object.keys(this.levels)[this.currentLevel]
        };
    }

    // Set log level
    setLogLevel(level) {
        if (this.levels.hasOwnProperty(level)) {
            this.currentLevel = this.levels[level];
            this.info('Log level changed', { newLevel: level });
        } else {
            this.error('Invalid log level', { attemptedLevel: level });
        }
    }

    // Shutdown gracefully
    async shutdown() {
        try {
            await this.saveMetrics();
            this.info('Apollo Logger shutting down');

            // Clear intervals
            clearInterval(this.metricsInterval);
            clearInterval(this.healthInterval);
            clearInterval(this.rotationInterval);

        } catch (error) {
            console.error('Error during logger shutdown:', error);
        }
    }
}

module.exports = ApolloLogger;