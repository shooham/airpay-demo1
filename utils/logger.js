/**
 * Production-Ready Logger
 * Provides structured logging with different levels and outputs
 */

const fs = require('fs');
const path = require('path');

class Logger {
    constructor() {
        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3
        };
        
        this.currentLevel = this.levels[process.env.LOG_LEVEL] || this.levels.info;
        this.logDir = process.env.LOG_DIR || './logs';
        this.maxFileSize = parseInt(process.env.LOG_MAX_SIZE) || 10 * 1024 * 1024; // 10MB
        this.maxFiles = parseInt(process.env.LOG_MAX_FILES) || 5;
        
        this.ensureLogDirectory();
        this.setupRotation();
    }

    // Ensure log directory exists
    ensureLogDirectory() {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    // Setup log rotation
    setupRotation() {
        // Check file sizes every hour
        setInterval(() => {
            this.rotateLogsIfNeeded();
        }, 60 * 60 * 1000);
    }

    // Format log message
    formatMessage(level, message, meta = {}) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            message,
            ...meta
        };

        // Add request context if available
        if (meta.req) {
            logEntry.request = {
                method: meta.req.method,
                url: meta.req.url,
                ip: meta.req.ip,
                userAgent: meta.req.get('User-Agent'),
                requestId: meta.req.id
            };
            delete logEntry.req;
        }

        // Add error stack if available
        if (meta.error && meta.error.stack) {
            logEntry.stack = meta.error.stack;
            logEntry.errorMessage = meta.error.message;
            delete logEntry.error;
        }

        return logEntry;
    }

    // Write to console with colors
    writeToConsole(level, formattedMessage) {
        const colors = {
            error: '\x1b[31m', // Red
            warn: '\x1b[33m',  // Yellow
            info: '\x1b[36m',  // Cyan
            debug: '\x1b[37m'  // White
        };
        
        const reset = '\x1b[0m';
        const color = colors[level] || colors.info;
        
        const consoleMessage = `${color}[${formattedMessage.timestamp}] ${formattedMessage.level}: ${formattedMessage.message}${reset}`;
        
        if (level === 'error') {
            console.error(consoleMessage);
            if (formattedMessage.stack) {
                console.error(formattedMessage.stack);
            }
        } else {
            console.log(consoleMessage);
        }
    }

    // Write to file
    writeToFile(level, formattedMessage) {
        try {
            const filename = path.join(this.logDir, `${level}.log`);
            const logLine = JSON.stringify(formattedMessage) + '\n';
            
            fs.appendFileSync(filename, logLine);
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
        }
    }

    // Rotate logs if needed
    rotateLogsIfNeeded() {
        const levels = ['error', 'warn', 'info', 'debug'];
        
        levels.forEach(level => {
            const filename = path.join(this.logDir, `${level}.log`);
            
            if (fs.existsSync(filename)) {
                const stats = fs.statSync(filename);
                
                if (stats.size > this.maxFileSize) {
                    this.rotateLogFile(level);
                }
            }
        });
    }

    // Rotate a specific log file
    rotateLogFile(level) {
        try {
            const baseFilename = path.join(this.logDir, `${level}.log`);
            
            // Remove oldest file if we have too many
            const oldestFile = path.join(this.logDir, `${level}.log.${this.maxFiles}`);
            if (fs.existsSync(oldestFile)) {
                fs.unlinkSync(oldestFile);
            }
            
            // Rotate existing files
            for (let i = this.maxFiles - 1; i >= 1; i--) {
                const oldFile = path.join(this.logDir, `${level}.log.${i}`);
                const newFile = path.join(this.logDir, `${level}.log.${i + 1}`);
                
                if (fs.existsSync(oldFile)) {
                    fs.renameSync(oldFile, newFile);
                }
            }
            
            // Rotate current file
            if (fs.existsSync(baseFilename)) {
                const rotatedFile = path.join(this.logDir, `${level}.log.1`);
                fs.renameSync(baseFilename, rotatedFile);
            }
            
            console.log(`Log file rotated: ${level}.log`);
        } catch (error) {
            console.error(`Failed to rotate log file ${level}:`, error.message);
        }
    }

    // Generic log method
    log(level, message, meta = {}) {
        if (this.levels[level] > this.currentLevel) {
            return; // Skip if level is higher than current level
        }

        const formattedMessage = this.formatMessage(level, message, meta);
        
        // Always write to console in development
        if (process.env.NODE_ENV !== 'production' || process.env.LOG_TO_CONSOLE === 'true') {
            this.writeToConsole(level, formattedMessage);
        }
        
        // Write to file in production or if explicitly enabled
        if (process.env.NODE_ENV === 'production' || process.env.LOG_TO_FILE === 'true') {
            this.writeToFile(level, formattedMessage);
        }
    }

    // Convenience methods
    error(message, meta = {}) {
        this.log('error', message, meta);
    }

    warn(message, meta = {}) {
        this.log('warn', message, meta);
    }

    info(message, meta = {}) {
        this.log('info', message, meta);
    }

    debug(message, meta = {}) {
        this.log('debug', message, meta);
    }

    // Security logging
    security(message, meta = {}) {
        this.log('warn', `SECURITY: ${message}`, {
            ...meta,
            security_event: true,
            timestamp: new Date().toISOString()
        });
    }

    // Payment logging
    payment(message, meta = {}) {
        this.log('info', `PAYMENT: ${message}`, {
            ...meta,
            payment_event: true,
            timestamp: new Date().toISOString()
        });
    }

    // Express middleware for request logging
    requestLogger() {
        return (req, res, next) => {
            const start = Date.now();
            
            // Generate request ID
            req.id = require('crypto').randomBytes(8).toString('hex');
            
            // Log request
            this.info('Request received', {
                req,
                body: req.method === 'POST' ? this.sanitizeBody(req.body) : undefined
            });
            
            // Log response
            res.on('finish', () => {
                const duration = Date.now() - start;
                const level = res.statusCode >= 400 ? 'warn' : 'info';
                
                this.log(level, 'Request completed', {
                    requestId: req.id,
                    method: req.method,
                    url: req.url,
                    statusCode: res.statusCode,
                    duration: `${duration}ms`,
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
                });
            });
            
            next();
        };
    }

    // Sanitize request body for logging
    sanitizeBody(body) {
        if (!body || typeof body !== 'object') {
            return body;
        }
        
        const sanitized = { ...body };
        const sensitiveFields = [
            'password', 'cardNumber', 'cardCvv', 'pin', 'otp',
            'secret', 'token', 'key', 'authorization'
        ];
        
        sensitiveFields.forEach(field => {
            if (sanitized[field]) {
                sanitized[field] = '[REDACTED]';
            }
        });
        
        return sanitized;
    }
}

// Create singleton instance
const logger = new Logger();

module.exports = logger;