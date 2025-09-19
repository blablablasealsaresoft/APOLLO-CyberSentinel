// Apollo Error Handling and Recovery System
// Provides robust error handling, automatic recovery, and system resilience

const { EventEmitter } = require('events');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');

class ApolloErrorHandler extends EventEmitter {
    constructor(logger = null) {
        super();

        this.logger = logger;
        this.errorDirectory = path.join(os.homedir(), '.apollo', 'errors');
        this.recoveryAttempts = new Map();
        this.maxRecoveryAttempts = 3;
        this.isRecovering = false;

        // Error categories
        this.errorCategories = {
            CRITICAL: {
                level: 'critical',
                requiresImmediateAction: true,
                autoRecover: false,
                alertUser: true
            },
            RECOVERABLE: {
                level: 'error',
                requiresImmediateAction: false,
                autoRecover: true,
                alertUser: false
            },
            WARNING: {
                level: 'warn',
                requiresImmediateAction: false,
                autoRecover: true,
                alertUser: false
            },
            INFO: {
                level: 'info',
                requiresImmediateAction: false,
                autoRecover: false,
                alertUser: false
            }
        };

        // Recovery strategies
        this.recoveryStrategies = {
            'API_CONNECTION_FAILED': this.recoverAPIConnection.bind(this),
            'DATABASE_ERROR': this.recoverDatabase.bind(this),
            'FILE_SYSTEM_ERROR': this.recoverFileSystem.bind(this),
            'MEMORY_LEAK': this.recoverMemoryLeak.bind(this),
            'THREAD_DEADLOCK': this.recoverDeadlock.bind(this),
            'NETWORK_TIMEOUT': this.recoverNetworkTimeout.bind(this),
            'PERMISSION_DENIED': this.recoverPermissions.bind(this),
            'SERVICE_CRASH': this.recoverService.bind(this),
            'RESOURCE_EXHAUSTION': this.recoverResources.bind(this)
        };

        // Error patterns for automatic categorization
        this.errorPatterns = {
            API_CONNECTION: /connection|timeout|refused|network|ECONNREFUSED|ETIMEDOUT/i,
            FILE_SYSTEM: /ENOENT|EACCES|EPERM|file|directory|path/i,
            MEMORY: /memory|heap|allocation|out of memory/i,
            PERMISSION: /permission|access|denied|unauthorized|EPERM|EACCES/i,
            DATABASE: /database|sql|query|connection pool/i,
            NETWORK: /network|socket|dns|hostname|resolve/i,
            THREAD: /deadlock|thread|process|spawn/i,
            RESOURCE: /resource|limit|quota|exceeded/i
        };

        this.init();
    }

    async init() {
        try {
            await fs.ensureDir(this.errorDirectory);

            // Set up global error handlers
            this.setupGlobalErrorHandlers();

            // Start background error monitoring
            this.startErrorMonitoring();

            this.log('info', 'Apollo Error Handler initialized');

        } catch (error) {
            console.error('Failed to initialize Error Handler:', error);
        }
    }

    setupGlobalErrorHandlers() {
        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            this.handleCriticalError('UNCAUGHT_EXCEPTION', error, {
                context: 'global',
                requiresRestart: true
            });
        });

        // Handle unhandled promise rejections
        process.on('unhandledRejection', (reason, promise) => {
            this.handleError('UNHANDLED_REJECTION', reason, {
                context: 'promise',
                promise: promise.toString()
            });
        });

        // Handle warnings
        process.on('warning', (warning) => {
            this.handleWarning('PROCESS_WARNING', warning, {
                context: 'process',
                stack: warning.stack
            });
        });
    }

    startErrorMonitoring() {
        // Monitor system resources every 30 seconds
        setInterval(() => {
            this.monitorSystemHealth();
        }, 30000);

        // Check for stuck processes every 60 seconds
        setInterval(() => {
            this.checkForDeadlocks();
        }, 60000);
    }

    async handleError(type, error, context = {}) {
        const errorInfo = this.analyzeError(type, error, context);

        // Log the error
        this.log(errorInfo.category.level, `Error: ${type}`, {
            error: error.message || error,
            stack: error.stack,
            context,
            errorId: errorInfo.id,
            timestamp: errorInfo.timestamp
        });

        // Save error details
        await this.saveErrorDetails(errorInfo);

        // Attempt recovery if applicable
        if (errorInfo.category.autoRecover && !this.isRecovering) {
            await this.attemptRecovery(errorInfo);
        }

        // Alert user if required
        if (errorInfo.category.alertUser) {
            this.emit('userAlert', {
                type: 'error',
                message: `Apollo detected a ${errorInfo.category.level} error: ${type}`,
                details: errorInfo,
                requiresAction: errorInfo.category.requiresImmediateAction
            });
        }

        // Emit error event for other components
        this.emit('error', errorInfo);

        return errorInfo;
    }

    handleCriticalError(type, error, context = {}) {
        const errorInfo = this.analyzeError(type, error, context);
        errorInfo.category = this.errorCategories.CRITICAL;

        this.log('critical', `Critical Error: ${type}`, {
            error: error.message || error,
            stack: error.stack,
            context,
            errorId: errorInfo.id,
            requiresRestart: context.requiresRestart || false
        });

        // Emit critical error event
        this.emit('criticalError', errorInfo);

        // If restart is required, initiate graceful shutdown
        if (context.requiresRestart) {
            this.emit('requestRestart', errorInfo);
        }

        return errorInfo;
    }

    handleWarning(type, warning, context = {}) {
        const warningInfo = {
            id: this.generateErrorId(),
            type,
            message: warning.message || warning,
            category: this.errorCategories.WARNING,
            context,
            timestamp: new Date().toISOString()
        };

        this.log('warn', `Warning: ${type}`, {
            warning: warning.message || warning,
            context,
            warningId: warningInfo.id
        });

        this.emit('warning', warningInfo);
        return warningInfo;
    }

    analyzeError(type, error, context) {
        const errorInfo = {
            id: this.generateErrorId(),
            type,
            error: error.message || error,
            stack: error.stack,
            context,
            timestamp: new Date().toISOString(),
            category: this.categorizeError(type, error),
            pattern: this.identifyErrorPattern(error)
        };

        return errorInfo;
    }

    categorizeError(type, error) {
        const errorStr = (error.message || error.toString()).toLowerCase();

        // Check for critical errors
        if (type === 'UNCAUGHT_EXCEPTION' ||
            errorStr.includes('out of memory') ||
            errorStr.includes('segmentation fault') ||
            errorStr.includes('access violation')) {
            return this.errorCategories.CRITICAL;
        }

        // Check for recoverable errors
        if (errorStr.includes('connection') ||
            errorStr.includes('timeout') ||
            errorStr.includes('file not found') ||
            errorStr.includes('permission')) {
            return this.errorCategories.RECOVERABLE;
        }

        // Default to warning
        return this.errorCategories.WARNING;
    }

    identifyErrorPattern(error) {
        const errorStr = error.message || error.toString();

        for (const [pattern, regex] of Object.entries(this.errorPatterns)) {
            if (regex.test(errorStr)) {
                return pattern;
            }
        }

        return 'UNKNOWN';
    }

    async attemptRecovery(errorInfo) {
        if (this.isRecovering) {
            this.log('warn', 'Recovery already in progress, skipping');
            return false;
        }

        const attemptKey = `${errorInfo.type}_${errorInfo.pattern}`;
        const currentAttempts = this.recoveryAttempts.get(attemptKey) || 0;

        if (currentAttempts >= this.maxRecoveryAttempts) {
            this.log('error', 'Maximum recovery attempts exceeded', {
                errorType: errorInfo.type,
                pattern: errorInfo.pattern,
                attempts: currentAttempts
            });
            return false;
        }

        this.isRecovering = true;
        this.recoveryAttempts.set(attemptKey, currentAttempts + 1);

        try {
            this.log('info', 'Attempting error recovery', {
                errorId: errorInfo.id,
                strategy: errorInfo.pattern,
                attempt: currentAttempts + 1
            });

            // Get recovery strategy
            const strategy = this.recoveryStrategies[errorInfo.pattern] || this.defaultRecovery;
            const success = await strategy(errorInfo);

            if (success) {
                this.log('info', 'Recovery successful', {
                    errorId: errorInfo.id,
                    strategy: errorInfo.pattern
                });

                // Reset attempt counter on success
                this.recoveryAttempts.delete(attemptKey);
                this.emit('recoverySuccess', errorInfo);
            } else {
                this.log('warn', 'Recovery failed', {
                    errorId: errorInfo.id,
                    strategy: errorInfo.pattern,
                    attempt: currentAttempts + 1
                });
                this.emit('recoveryFailed', errorInfo);
            }

            return success;

        } catch (recoveryError) {
            this.log('error', 'Recovery strategy threw error', {
                originalError: errorInfo.id,
                recoveryError: recoveryError.message,
                stack: recoveryError.stack
            });
            return false;
        } finally {
            this.isRecovering = false;
        }
    }

    // Recovery strategy implementations
    async recoverAPIConnection(errorInfo) {
        this.log('info', 'Attempting API connection recovery');

        // Wait before retry
        await this.sleep(2000);

        // Try to reinitialize connection
        try {
            // This would be implemented by the specific API client
            this.emit('reconnectAPI', errorInfo.context);
            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverDatabase(errorInfo) {
        this.log('info', 'Attempting database recovery');

        // Database connection issues
        await this.sleep(1000);

        try {
            this.emit('reconnectDatabase', errorInfo.context);
            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverFileSystem(errorInfo) {
        this.log('info', 'Attempting file system recovery');

        try {
            // Create missing directories
            if (errorInfo.context.path) {
                const dir = path.dirname(errorInfo.context.path);
                await fs.ensureDir(dir);
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverMemoryLeak(errorInfo) {
        this.log('warn', 'Memory leak detected, forcing garbage collection');

        try {
            if (global.gc) {
                global.gc();
            }

            // Clear caches
            this.emit('clearCaches');

            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverDeadlock(errorInfo) {
        this.log('warn', 'Attempting deadlock recovery');

        try {
            // Restart affected services
            this.emit('restartServices', errorInfo.context);
            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverNetworkTimeout(errorInfo) {
        this.log('info', 'Recovering from network timeout');

        // Exponential backoff
        const backoffTime = Math.min(1000 * Math.pow(2, this.recoveryAttempts.get(errorInfo.type) || 0), 30000);
        await this.sleep(backoffTime);

        return true;
    }

    async recoverPermissions(errorInfo) {
        this.log('warn', 'Permission error detected');

        // Request elevated permissions if needed
        this.emit('requestElevation', errorInfo.context);
        return false; // Usually requires user intervention
    }

    async recoverService(errorInfo) {
        this.log('info', 'Attempting service recovery');

        try {
            this.emit('restartService', errorInfo.context);
            await this.sleep(3000); // Wait for service restart
            return true;
        } catch (error) {
            return false;
        }
    }

    async recoverResources(errorInfo) {
        this.log('warn', 'Resource exhaustion detected');

        try {
            // Free up resources
            this.emit('freeResources');

            // Force garbage collection
            if (global.gc) {
                global.gc();
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    async defaultRecovery(errorInfo) {
        this.log('info', 'Using default recovery strategy');

        // Generic recovery: wait and retry
        await this.sleep(1000);
        return true;
    }

    async monitorSystemHealth() {
        try {
            const memUsage = process.memoryUsage();
            const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

            // Check memory usage
            if (heapUsedPercent > 85) {
                this.handleWarning('HIGH_MEMORY_USAGE', new Error('Memory usage above 85%'), {
                    heapUsedPercent: heapUsedPercent.toFixed(2),
                    heapUsed: memUsage.heapUsed,
                    heapTotal: memUsage.heapTotal
                });
            }

            // Check for resource exhaustion
            if (heapUsedPercent > 95) {
                this.handleError('RESOURCE_EXHAUSTION', new Error('Critical memory usage'), {
                    heapUsedPercent: heapUsedPercent.toFixed(2)
                });
            }

        } catch (error) {
            this.log('error', 'System health monitoring failed', { error: error.message });
        }
    }

    async checkForDeadlocks() {
        // This is a simplified deadlock check
        // In production, this would be more sophisticated
        const currentTime = Date.now();

        // Check if any operations are taking too long
        this.emit('checkOperationTimeouts', currentTime);
    }

    async saveErrorDetails(errorInfo) {
        try {
            const errorFile = path.join(
                this.errorDirectory,
                `error-${errorInfo.id}.json`
            );

            await fs.writeJSON(errorFile, {
                ...errorInfo,
                systemInfo: {
                    platform: os.platform(),
                    arch: os.arch(),
                    nodeVersion: process.version,
                    pid: process.pid,
                    uptime: process.uptime(),
                    memory: process.memoryUsage()
                }
            }, { spaces: 2 });

        } catch (error) {
            console.error('Failed to save error details:', error);
        }
    }

    generateErrorId() {
        return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    log(level, message, metadata = {}) {
        if (this.logger) {
            this.logger[level](message, metadata);
        } else {
            console.log(`[${level.toUpperCase()}] ${message}`, metadata);
        }
    }

    // Get error statistics
    getErrorStats() {
        const stats = {
            totalRecoveryAttempts: Array.from(this.recoveryAttempts.values()).reduce((sum, count) => sum + count, 0),
            activeRecoveryAttempts: this.recoveryAttempts.size,
            isRecovering: this.isRecovering,
            maxRecoveryAttempts: this.maxRecoveryAttempts
        };

        return stats;
    }

    // Reset recovery attempts (for testing or manual intervention)
    resetRecoveryAttempts(type = null) {
        if (type) {
            this.recoveryAttempts.delete(type);
        } else {
            this.recoveryAttempts.clear();
        }

        this.log('info', 'Recovery attempts reset', { type: type || 'all' });
    }

    // Shutdown gracefully
    async shutdown() {
        this.log('info', 'Error Handler shutting down');
        this.removeAllListeners();
    }
}

module.exports = ApolloErrorHandler;