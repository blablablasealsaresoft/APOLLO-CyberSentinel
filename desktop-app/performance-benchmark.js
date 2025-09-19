// Apollo Performance Benchmark Suite
// Comprehensive performance testing for all Apollo components

require('dotenv').config();

const ApolloUnifiedProtectionEngine = require('./src/core/unified-protection-engine');
const ApolloAIOracle = require('./src/ai/oracle-integration');
const OSINTThreatIntelligence = require('./src/intelligence/osint-sources');
const ApolloLogger = require('./src/core/apollo-logger');
const ApolloErrorHandler = require('./src/core/error-handler');

class ApolloPerformanceBenchmark {
    constructor() {
        this.logger = new ApolloLogger();
        this.errorHandler = new ApolloErrorHandler(this.logger);
        this.results = new Map();
        this.metrics = {
            totalTests: 0,
            passedTests: 0,
            failedTests: 0,
            averageResponseTime: 0,
            memoryBaseline: null,
            memoryPeak: 0,
            cpuBaseline: null,
            cpuPeak: 0
        };
    }

    async runBenchmarks() {
        console.log('⚡ Starting Apollo Performance Benchmark Suite...\n');
        console.log('=' .repeat(70));

        // Record baseline metrics
        await this.recordBaseline();

        // Core component benchmarks
        await this.benchmarkUnifiedEngine();
        await this.benchmarkAIOracle();
        await this.benchmarkOSINTIntelligence();
        await this.benchmarkLogger();
        await this.benchmarkErrorHandler();

        // Integrated performance tests
        await this.benchmarkFullThreatPipeline();
        await this.benchmarkConcurrentOperations();
        await this.benchmarkMemoryUsage();
        await this.benchmarkScalability();

        await this.printBenchmarkResults();
        await this.cleanup();
    }

    async recordBaseline() {
        console.log('📊 Recording baseline metrics...');

        this.metrics.memoryBaseline = process.memoryUsage();
        this.metrics.cpuBaseline = process.cpuUsage();

        console.log(`  Memory baseline: ${(this.metrics.memoryBaseline.heapUsed / 1024 / 1024).toFixed(2)} MB`);
        console.log(`  CPU baseline recorded`);
    }

    async benchmarkUnifiedEngine() {
        console.log('\n🛡️ Benchmarking Unified Protection Engine...');

        const engine = new ApolloUnifiedProtectionEngine();

        // Test 1: Engine initialization
        await this.measurePerformance('Engine Initialization', async () => {
            return await engine.initialize();
        });

        // Test 2: Threat analysis speed
        await this.measurePerformance('Single Threat Analysis', async () => {
            return await engine.performUnifiedThreatAnalysis('malicious.exe', 'file_system');
        });

        // Test 3: Batch threat analysis
        await this.measurePerformance('Batch Threat Analysis (10 files)', async () => {
            const files = Array.from({ length: 10 }, (_, i) => `test_file_${i}.exe`);
            const promises = files.map(file =>
                engine.performUnifiedThreatAnalysis(file, 'file_system')
            );
            return await Promise.all(promises);
        });

        // Test 4: Statistics retrieval
        await this.measurePerformance('Statistics Retrieval', async () => {
            return engine.getStatistics();
        });

        // Test 5: Configuration changes
        await this.measurePerformance('Performance Mode Change', async () => {
            engine.setPerformanceMode('maximum_protection');
            engine.setPerformanceMode('balanced');
            return true;
        });

        await engine.stop();
        this.recordResult('Unified Engine', 'All tests completed');
    }

    async benchmarkAIOracle() {
        console.log('\n🧠 Benchmarking AI Oracle...');

        const oracle = new ApolloAIOracle();

        // Test 1: Fallback analysis (no API)
        await this.measurePerformance('Fallback Analysis', async () => {
            return await oracle.fallbackAnalysis('suspicious.exe', { type: 'file' });
        });

        // Test 2: Threat context lookup
        await this.measurePerformance('Threat Context Lookup', async () => {
            return oracle.threatContextDatabase.get('pegasus');
        });

        // Test 3: Smart contract analysis
        await this.measurePerformance('Smart Contract Analysis', async () => {
            return await oracle.analyzeSmartContract('0x1234567890123456789012345678901234567890');
        });

        // Test 4: Phishing URL analysis
        await this.measurePerformance('Phishing URL Analysis', async () => {
            return await oracle.analyzePhishingURL('https://fake-metamask.com');
        });

        // Test 5: Batch analysis
        await this.measurePerformance('Batch Threat Analysis (5 indicators)', async () => {
            const indicators = [
                'malicious.exe',
                'suspicious.dll',
                'trojan.bat',
                'keylogger.exe',
                'backdoor.sys'
            ];

            const promises = indicators.map(indicator =>
                oracle.analyzeThreat(indicator, { type: 'file' })
            );

            return await Promise.all(promises);
        });

        this.recordResult('AI Oracle', 'All tests completed');
    }

    async benchmarkOSINTIntelligence() {
        console.log('\n🔍 Benchmarking OSINT Intelligence...');

        const osint = new OSINTThreatIntelligence();

        // Test 1: Phishing heuristics
        await this.measurePerformance('Phishing Heuristics', async () => {
            return osint.checkPhishingHeuristics('https://metamask-wallet-verify.com');
        });

        // Test 2: Phishing flags detection
        await this.measurePerformance('Phishing Flags Detection', async () => {
            return osint.getPhishingFlags('https://bit.ly/fake-binance');
        });

        // Test 3: Cache operations
        await this.measurePerformance('Cache Operations', async () => {
            // Simulate cache operations
            for (let i = 0; i < 100; i++) {
                osint.cache.set(`test_${i}`, { data: `value_${i}`, timestamp: Date.now() });
            }
            return osint.cache.size;
        });

        // Test 4: Statistics calculation
        await this.measurePerformance('Statistics Calculation', async () => {
            return osint.getStats();
        });

        // Test 5: Threat feed refresh
        await this.measurePerformance('Threat Feed Refresh', async () => {
            return await osint.refreshThreatFeeds();
        });

        this.recordResult('OSINT Intelligence', 'All tests completed');
    }

    async benchmarkLogger() {
        console.log('\n📝 Benchmarking Logger...');

        const logger = new ApolloLogger();
        await new Promise(resolve => setTimeout(resolve, 1000)); // Let logger initialize

        // Test 1: Single log entry
        await this.measurePerformance('Single Log Entry', async () => {
            logger.info('Benchmark test message', { test: true });
            return true;
        });

        // Test 2: Batch logging
        await this.measurePerformance('Batch Logging (100 entries)', async () => {
            for (let i = 0; i < 100; i++) {
                logger.debug(`Batch log entry ${i}`, { index: i, batch: true });
            }
            return true;
        });

        // Test 3: Different log levels
        await this.measurePerformance('Mixed Log Levels', async () => {
            logger.debug('Debug message');
            logger.info('Info message');
            logger.warn('Warning message');
            logger.error('Error message');
            return true;
        });

        // Test 4: Metrics retrieval
        await this.measurePerformance('Metrics Retrieval', async () => {
            return logger.getMetrics();
        });

        // Test 5: Performance logging
        await this.measurePerformance('Performance Logging', async () => {
            logger.logPerformance('test_operation', 150, { component: 'benchmark' });
            return true;
        });

        await logger.shutdown();
        this.recordResult('Logger', 'All tests completed');
    }

    async benchmarkErrorHandler() {
        console.log('\n⚠️ Benchmarking Error Handler...');

        const errorHandler = new ApolloErrorHandler(this.logger);
        await new Promise(resolve => setTimeout(resolve, 500)); // Let handler initialize

        // Test 1: Error analysis
        await this.measurePerformance('Error Analysis', async () => {
            const testError = new Error('Test error for benchmarking');
            return errorHandler.analyzeError('TEST_ERROR', testError, { benchmark: true });
        });

        // Test 2: Error categorization
        await this.measurePerformance('Error Categorization', async () => {
            const errors = [
                new Error('Connection timeout'),
                new Error('File not found'),
                new Error('Permission denied'),
                new Error('Out of memory'),
                new Error('Unknown error')
            ];

            return errors.map(error => errorHandler.categorizeError('TEST', error));
        });

        // Test 3: Error pattern identification
        await this.measurePerformance('Error Pattern Identification', async () => {
            const errors = [
                new Error('ECONNREFUSED: Connection refused'),
                new Error('ENOENT: File not found'),
                new Error('EACCES: Permission denied'),
                new Error('Memory allocation failed'),
                new Error('Network timeout')
            ];

            return errors.map(error => errorHandler.identifyErrorPattern(error));
        });

        // Test 4: Statistics retrieval
        await this.measurePerformance('Error Stats Retrieval', async () => {
            return errorHandler.getErrorStats();
        });

        await errorHandler.shutdown();
        this.recordResult('Error Handler', 'All tests completed');
    }

    async benchmarkFullThreatPipeline() {
        console.log('\n🔗 Benchmarking Full Threat Detection Pipeline...');

        const engine = new ApolloUnifiedProtectionEngine();
        const oracle = new ApolloAIOracle();
        const osint = new OSINTThreatIntelligence();

        await engine.initialize();

        // Test full pipeline: File -> Engine -> AI -> OSINT
        await this.measurePerformance('Full Threat Pipeline', async () => {
            const fileName = 'suspicious_payload.exe';

            // 1. Engine analysis
            const engineResult = await engine.performUnifiedThreatAnalysis(fileName, 'file_system');

            // 2. AI Oracle analysis
            const aiResult = await oracle.analyzeThreat(fileName, {
                type: 'file',
                engineResults: engineResult
            });

            // 3. OSINT check (heuristics only for speed)
            const osintResult = osint.checkPhishingHeuristics(`https://download.com/${fileName}`);

            return {
                engine: engineResult,
                ai: aiResult,
                osint: osintResult
            };
        });

        await engine.stop();
        this.recordResult('Threat Pipeline', 'Full pipeline benchmark completed');
    }

    async benchmarkConcurrentOperations() {
        console.log('\n⚡ Benchmarking Concurrent Operations...');

        const engine = new ApolloUnifiedProtectionEngine();
        const oracle = new ApolloAIOracle();

        await engine.initialize();

        // Test concurrent threat analysis
        await this.measurePerformance('Concurrent Threat Analysis (20 operations)', async () => {
            const operations = [];

            for (let i = 0; i < 20; i++) {
                operations.push(
                    engine.performUnifiedThreatAnalysis(`file_${i}.exe`, 'file_system')
                );
            }

            return await Promise.all(operations);
        });

        // Test concurrent AI analysis
        await this.measurePerformance('Concurrent AI Analysis (10 operations)', async () => {
            const operations = [];

            for (let i = 0; i < 10; i++) {
                operations.push(
                    oracle.analyzeThreat(`threat_${i}`, { type: 'file' })
                );
            }

            return await Promise.all(operations);
        });

        await engine.stop();
        this.recordResult('Concurrent Operations', 'Concurrency benchmarks completed');
    }

    async benchmarkMemoryUsage() {
        console.log('\n🧠 Benchmarking Memory Usage...');

        const initialMemory = process.memoryUsage();

        // Test memory usage with large operations
        await this.measurePerformance('Memory Stress Test', async () => {
            const engine = new ApolloUnifiedProtectionEngine();
            const oracle = new ApolloAIOracle();

            await engine.initialize();

            // Perform many operations
            for (let i = 0; i < 50; i++) {
                await engine.performUnifiedThreatAnalysis(`stress_test_${i}.exe`, 'file_system');
                await oracle.analyzeThreat(`stress_${i}`, { type: 'file' });
            }

            await engine.stop();

            const finalMemory = process.memoryUsage();
            const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

            return {
                memoryIncrease: memoryIncrease / 1024 / 1024, // MB
                finalHeapUsed: finalMemory.heapUsed / 1024 / 1024 // MB
            };
        });

        this.recordResult('Memory Usage', 'Memory benchmarks completed');
    }

    async benchmarkScalability() {
        console.log('\n📈 Benchmarking Scalability...');

        const engine = new ApolloUnifiedProtectionEngine();
        await engine.initialize();

        // Test with increasing loads
        const loadSizes = [1, 5, 10, 25, 50];

        for (const loadSize of loadSizes) {
            await this.measurePerformance(`Scalability Test (${loadSize} operations)`, async () => {
                const operations = [];

                for (let i = 0; i < loadSize; i++) {
                    operations.push(
                        engine.performUnifiedThreatAnalysis(`scale_test_${i}.exe`, 'file_system')
                    );
                }

                return await Promise.all(operations);
            });
        }

        await engine.stop();
        this.recordResult('Scalability', 'Scalability benchmarks completed');
    }

    async measurePerformance(testName, testFunction) {
        this.metrics.totalTests++;

        const startTime = process.hrtime.bigint();
        const startMemory = process.memoryUsage();

        try {
            const result = await testFunction();

            const endTime = process.hrtime.bigint();
            const endMemory = process.memoryUsage();

            const durationMs = Number(endTime - startTime) / 1000000; // Convert to milliseconds
            const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;

            // Update peak memory usage
            if (endMemory.heapUsed > this.metrics.memoryPeak) {
                this.metrics.memoryPeak = endMemory.heapUsed;
            }

            // Record result
            this.results.set(testName, {
                duration: durationMs,
                memoryDelta: memoryDelta,
                success: true,
                result: result
            });

            // Update average response time
            this.updateAverageResponseTime(durationMs);

            console.log(`  ✅ ${testName}: ${durationMs.toFixed(2)}ms (${this.formatMemory(memoryDelta)} memory)`);

            this.metrics.passedTests++;
            return result;

        } catch (error) {
            const endTime = process.hrtime.bigint();
            const durationMs = Number(endTime - startTime) / 1000000;

            this.results.set(testName, {
                duration: durationMs,
                memoryDelta: 0,
                success: false,
                error: error.message
            });

            console.log(`  ❌ ${testName}: FAILED (${error.message})`);

            this.metrics.failedTests++;
            throw error;
        }
    }

    updateAverageResponseTime(duration) {
        const totalDuration = this.metrics.averageResponseTime * (this.metrics.totalTests - 1) + duration;
        this.metrics.averageResponseTime = totalDuration / this.metrics.totalTests;
    }

    recordResult(component, message) {
        console.log(`  📊 ${component}: ${message}`);
    }

    formatMemory(bytes) {
        if (bytes >= 0) {
            return `+${(bytes / 1024 / 1024).toFixed(2)}MB`;
        } else {
            return `${(bytes / 1024 / 1024).toFixed(2)}MB`;
        }
    }

    async printBenchmarkResults() {
        console.log('\n' + '='.repeat(70));
        console.log('📊 Performance Benchmark Results');
        console.log('='.repeat(70));

        // Overall metrics
        console.log(`\n📈 Overall Performance:`);
        console.log(`  • Total Tests: ${this.metrics.totalTests}`);
        console.log(`  • Passed: ${this.metrics.passedTests}`);
        console.log(`  • Failed: ${this.metrics.failedTests}`);
        console.log(`  • Success Rate: ${((this.metrics.passedTests / this.metrics.totalTests) * 100).toFixed(1)}%`);
        console.log(`  • Average Response Time: ${this.metrics.averageResponseTime.toFixed(2)}ms`);

        // Memory metrics
        const baselineMemoryMB = this.metrics.memoryBaseline.heapUsed / 1024 / 1024;
        const peakMemoryMB = this.metrics.memoryPeak / 1024 / 1024;
        const memoryIncrease = peakMemoryMB - baselineMemoryMB;

        console.log(`\n🧠 Memory Usage:`);
        console.log(`  • Baseline: ${baselineMemoryMB.toFixed(2)}MB`);
        console.log(`  • Peak: ${peakMemoryMB.toFixed(2)}MB`);
        console.log(`  • Increase: ${memoryIncrease.toFixed(2)}MB`);

        // Performance categories
        console.log(`\n⚡ Performance Categories:`);

        const avgResponseTime = this.metrics.averageResponseTime;
        let performanceRating = '';

        if (avgResponseTime < 10) {
            performanceRating = '🚀 Excellent (< 10ms)';
        } else if (avgResponseTime < 50) {
            performanceRating = '✅ Good (< 50ms)';
        } else if (avgResponseTime < 100) {
            performanceRating = '⚠️ Acceptable (< 100ms)';
        } else {
            performanceRating = '❌ Needs Optimization (> 100ms)';
        }

        console.log(`  • Response Time: ${performanceRating}`);

        // Memory efficiency
        let memoryRating = '';
        if (memoryIncrease < 50) {
            memoryRating = '🚀 Excellent (< 50MB)';
        } else if (memoryIncrease < 100) {
            memoryRating = '✅ Good (< 100MB)';
        } else if (memoryIncrease < 200) {
            memoryRating = '⚠️ Acceptable (< 200MB)';
        } else {
            memoryRating = '❌ High Memory Usage (> 200MB)';
        }

        console.log(`  • Memory Efficiency: ${memoryRating}`);

        // Detailed results
        console.log(`\n📋 Detailed Results:`);
        for (const [testName, result] of this.results) {
            const status = result.success ? '✅' : '❌';
            const duration = result.duration.toFixed(2);
            const memory = this.formatMemory(result.memoryDelta);

            console.log(`  ${status} ${testName}: ${duration}ms (${memory})`);
        }

        // Recommendations
        console.log(`\n💡 Recommendations:`);
        if (this.metrics.averageResponseTime > 50) {
            console.log(`  • Consider optimizing slow operations (avg: ${this.metrics.averageResponseTime.toFixed(2)}ms)`);
        }
        if (memoryIncrease > 100) {
            console.log(`  • Review memory usage patterns (increase: ${memoryIncrease.toFixed(2)}MB)`);
        }
        if (this.metrics.failedTests > 0) {
            console.log(`  • Address ${this.metrics.failedTests} failed test(s)`);
        }
        if (this.metrics.passedTests === this.metrics.totalTests) {
            console.log(`  • 🎉 All tests passed! Performance looks good.`);
        }
    }

    async cleanup() {
        console.log('\n🧹 Cleaning up benchmark resources...');

        // Force garbage collection if available
        if (global.gc) {
            global.gc();
        }

        await this.logger.shutdown();
        await this.errorHandler.shutdown();

        console.log('✅ Benchmark cleanup completed');
    }
}

// Run benchmarks if executed directly
if (require.main === module) {
    (async () => {
        const benchmark = new ApolloPerformanceBenchmark();
        await benchmark.runBenchmarks();

        setTimeout(() => {
            process.exit(0);
        }, 2000);
    })();
}

module.exports = ApolloPerformanceBenchmark;