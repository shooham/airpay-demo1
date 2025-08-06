/**
 * Health Check Utilities
 * Provides comprehensive system health monitoring
 */

const mongoose = require('mongoose');
const axios = require('axios');

class HealthChecker {
    constructor() {
        this.checks = new Map();
        this.lastResults = new Map();
        this.setupChecks();
    }

    // Setup health checks
    setupChecks() {
        this.checks.set('database', this.checkDatabase.bind(this));
        this.checks.set('airpay_api', this.checkAirPayAPI.bind(this));
        this.checks.set('memory', this.checkMemory.bind(this));
        this.checks.set('environment', this.checkEnvironment.bind(this));
    }

    // Check database connectivity
    async checkDatabase() {
        try {
            const start = Date.now();
            
            if (mongoose.connection.readyState !== 1) {
                return {
                    status: 'unhealthy',
                    message: 'Database not connected',
                    details: {
                        state: mongoose.connection.readyState,
                        states: {
                            0: 'disconnected',
                            1: 'connected',
                            2: 'connecting',
                            3: 'disconnecting'
                        }
                    }
                };
            }
            
            // Test query
            await mongoose.connection.db.admin().ping();
            const responseTime = Date.now() - start;
            
            return {
                status: 'healthy',
                message: 'Database connected',
                details: {
                    response_time: `${responseTime}ms`,
                    database: mongoose.connection.name,
                    host: mongoose.connection.host,
                    port: mongoose.connection.port
                }
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                message: 'Database check failed',
                error: error.message
            };
        }
    }

    // Check AirPay API connectivity
    async checkAirPayAPI() {
        try {
            const start = Date.now();
            const apiUrl = process.env.AIRPAY_ENVIRONMENT === 'production' 
                ? 'https://kraken.airpay.co.in'
                : 'https://kraken.airpay.co.in';
            
            // Simple connectivity check
            const response = await axios.get(apiUrl, {
                timeout: 10000,
                validateStatus: () => true // Don't throw on any status
            });
            
            const responseTime = Date.now() - start;
            
            if (response.status < 500) {
                return {
                    status: 'healthy',
                    message: 'AirPay API reachable',
                    details: {
                        response_time: `${responseTime}ms`,
                        status_code: response.status,
                        environment: process.env.AIRPAY_ENVIRONMENT || 'sandbox'
                    }
                };
            } else {
                return {
                    status: 'degraded',
                    message: 'AirPay API responding with errors',
                    details: {
                        response_time: `${responseTime}ms`,
                        status_code: response.status
                    }
                };
            }
        } catch (error) {
            return {
                status: 'unhealthy',
                message: 'AirPay API unreachable',
                error: error.code || error.message
            };
        }
    }

    // Check memory usage
    async checkMemory() {
        try {
            const memUsage = process.memoryUsage();
            const totalMem = require('os').totalmem();
            const freeMem = require('os').freemem();
            
            const heapUsedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
            const heapTotalMB = Math.round(memUsage.heapTotal / 1024 / 1024);
            const memoryUsagePercent = Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100);
            
            let status = 'healthy';
            let message = 'Memory usage normal';
            
            if (memoryUsagePercent > 90) {
                status = 'unhealthy';
                message = 'High memory usage detected';
            } else if (memoryUsagePercent > 75) {
                status = 'degraded';
                message = 'Elevated memory usage';
            }
            
            return {
                status,
                message,
                details: {
                    heap_used: `${heapUsedMB}MB`,
                    heap_total: `${heapTotalMB}MB`,
                    heap_usage_percent: `${memoryUsagePercent}%`,
                    system_total: `${Math.round(totalMem / 1024 / 1024)}MB`,
                    system_free: `${Math.round(freeMem / 1024 / 1024)}MB`
                }
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                message: 'Memory check failed',
                error: error.message
            };
        }
    }

    // Check environment configuration
    async checkEnvironment() {
        try {
            const requiredVars = [
                'AIRPAY_MERCHANT_ID',
                'AIRPAY_USERNAME',
                'AIRPAY_PASSWORD',
                'AIRPAY_SECRET_KEY',
                'AIRPAY_CLIENT_ID',
                'AIRPAY_CLIENT_SECRET'
            ];
            
            const missingVars = requiredVars.filter(varName => !process.env[varName]);
            const warnings = [];
            
            // Check for recommended variables
            if (!process.env.JWT_SECRET) {
                warnings.push('JWT_SECRET not set - using generated secret');
            }
            
            if (missingVars.length > 0) {
                return {
                    status: 'unhealthy',
                    message: 'Missing required environment variables',
                    details: {
                        missing_variables: missingVars,
                        warnings: warnings
                    }
                };
            }
            
            return {
                status: warnings.length > 0 ? 'degraded' : 'healthy',
                message: 'Environment configuration OK',
                details: {
                    node_env: process.env.NODE_ENV || 'development',
                    airpay_env: process.env.AIRPAY_ENVIRONMENT || 'sandbox',
                    warnings: warnings
                }
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                message: 'Environment check failed',
                error: error.message
            };
        }
    }

    // Run all health checks
    async runAllChecks() {
        const results = {};
        const promises = [];
        
        for (const [name, checkFn] of this.checks) {
            promises.push(
                checkFn()
                    .then(result => ({ name, result }))
                    .catch(error => ({
                        name,
                        result: {
                            status: 'unhealthy',
                            message: 'Check failed',
                            error: error.message
                        }
                    }))
            );
        }
        
        const checkResults = await Promise.all(promises);
        
        checkResults.forEach(({ name, result }) => {
            results[name] = result;
            this.lastResults.set(name, result);
        });
        
        // Determine overall status
        const statuses = Object.values(results).map(r => r.status);
        let overallStatus = 'healthy';
        
        if (statuses.includes('unhealthy')) {
            overallStatus = 'unhealthy';
        } else if (statuses.includes('degraded')) {
            overallStatus = 'degraded';
        }
        
        return {
            status: overallStatus,
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            version: process.env.npm_package_version || '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            checks: results
        };
    }

    // Express middleware for health endpoint
    healthEndpoint() {
        return async (req, res) => {
            try {
                const healthData = await this.runAllChecks();
                
                const statusCode = healthData.status === 'healthy' ? 200 : 
                                 healthData.status === 'degraded' ? 200 : 503;
                
                res.status(statusCode).json(healthData);
            } catch (error) {
                console.error('Health check error:', error);
                res.status(503).json({
                    status: 'unhealthy',
                    timestamp: new Date().toISOString(),
                    error: 'Health check failed',
                    message: error.message
                });
            }
        };
    }
}

// Create singleton instance
const healthChecker = new HealthChecker();

module.exports = {
    healthChecker,
    healthEndpoint: healthChecker.healthEndpoint.bind(healthChecker)
};