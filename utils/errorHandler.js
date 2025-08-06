/**
 * Centralized Error Handler for AirPay Integration
 * Provides consistent error handling and logging
 */

class ErrorHandler {
    constructor() {
        this.errorCodes = {
            // Authentication errors
            'AUTH_FAILED': { status: 401, message: 'Authentication failed' },
            'TOKEN_EXPIRED': { status: 401, message: 'Token has expired' },
            'INVALID_CREDENTIALS': { status: 401, message: 'Invalid credentials' },
            
            // Authorization errors
            'ACCESS_DENIED': { status: 403, message: 'Access denied' },
            'INSUFFICIENT_PERMISSIONS': { status: 403, message: 'Insufficient permissions' },
            
            // Validation errors
            'VALIDATION_FAILED': { status: 400, message: 'Validation failed' },
            'INVALID_INPUT': { status: 400, message: 'Invalid input data' },
            'MISSING_REQUIRED_FIELD': { status: 400, message: 'Required field missing' },
            
            // Payment errors
            'PAYMENT_FAILED': { status: 400, message: 'Payment processing failed' },
            'INSUFFICIENT_FUNDS': { status: 400, message: 'Insufficient funds' },
            'PAYMENT_DECLINED': { status: 400, message: 'Payment declined by bank' },
            'INVALID_CARD': { status: 400, message: 'Invalid card details' },
            'EXPIRED_CARD': { status: 400, message: 'Card has expired' },
            'TRANSACTION_LIMIT_EXCEEDED': { status: 400, message: 'Transaction limit exceeded' },
            
            // Gateway errors
            'GATEWAY_ERROR': { status: 502, message: 'Payment gateway error' },
            'GATEWAY_TIMEOUT': { status: 504, message: 'Payment gateway timeout' },
            'GATEWAY_UNAVAILABLE': { status: 503, message: 'Payment gateway unavailable' },
            
            // System errors
            'INTERNAL_ERROR': { status: 500, message: 'Internal server error' },
            'DATABASE_ERROR': { status: 500, message: 'Database operation failed' },
            'NETWORK_ERROR': { status: 500, message: 'Network communication failed' },
            'SERVICE_UNAVAILABLE': { status: 503, message: 'Service temporarily unavailable' },
            
            // Rate limiting
            'RATE_LIMIT_EXCEEDED': { status: 429, message: 'Rate limit exceeded' },
            'TOO_MANY_REQUESTS': { status: 429, message: 'Too many requests' },
            
            // Not found
            'NOT_FOUND': { status: 404, message: 'Resource not found' },
            'TRANSACTION_NOT_FOUND': { status: 404, message: 'Transaction not found' },
            'ORDER_NOT_FOUND': { status: 404, message: 'Order not found' }
        };
    }

    // Handle AirPay specific errors
    handleAirPayError(error, context = 'AirPay Operation') {
        console.error(`${context} Error:`, {
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
            timestamp: new Date().toISOString(),
            context
        });

        // Network/timeout errors
        if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
            return this.createErrorResponse('GATEWAY_TIMEOUT', {
                details: 'Request to payment gateway timed out'
            });
        }

        // Connection errors
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
            return this.createErrorResponse('GATEWAY_UNAVAILABLE', {
                details: 'Unable to connect to payment gateway'
            });
        }

        // HTTP response errors
        if (error.response) {
            const status = error.response.status;
            const data = error.response.data;

            if (status === 401) {
                return this.createErrorResponse('AUTH_FAILED', {
                    details: 'Invalid AirPay credentials'
                });
            }

            if (status === 403) {
                return this.createErrorResponse('ACCESS_DENIED', {
                    details: 'AirPay access denied'
                });
            }

            if (status >= 500) {
                return this.createErrorResponse('GATEWAY_ERROR', {
                    details: 'AirPay server error',
                    gatewayStatus: status
                });
            }

            // Parse AirPay specific error messages
            if (data && data.message) {
                return this.parseAirPayMessage(data.message, data);
            }
        }

        // Encryption/decryption errors
        if (error.message.includes('encryption') || error.message.includes('decryption')) {
            return this.createErrorResponse('GATEWAY_ERROR', {
                details: 'Data processing error'
            });
        }

        // Default to internal error
        return this.createErrorResponse('INTERNAL_ERROR', {
            details: 'An unexpected error occurred'
        });
    }

    // Parse AirPay specific error messages
    parseAirPayMessage(message, data = {}) {
        const lowerMessage = message.toLowerCase();

        if (lowerMessage.includes('insufficient fund')) {
            return this.createErrorResponse('INSUFFICIENT_FUNDS');
        }

        if (lowerMessage.includes('declined') || lowerMessage.includes('reject')) {
            return this.createErrorResponse('PAYMENT_DECLINED');
        }

        if (lowerMessage.includes('invalid card') || lowerMessage.includes('card not valid')) {
            return this.createErrorResponse('INVALID_CARD');
        }

        if (lowerMessage.includes('expired')) {
            return this.createErrorResponse('EXPIRED_CARD');
        }

        if (lowerMessage.includes('limit exceed')) {
            return this.createErrorResponse('TRANSACTION_LIMIT_EXCEEDED');
        }

        if (lowerMessage.includes('timeout')) {
            return this.createErrorResponse('GATEWAY_TIMEOUT');
        }

        // Default payment failure
        return this.createErrorResponse('PAYMENT_FAILED', {
            details: message,
            gatewayData: data
        });
    }

    // Create standardized error response
    createErrorResponse(errorCode, additionalData = {}) {
        const errorInfo = this.errorCodes[errorCode] || this.errorCodes['INTERNAL_ERROR'];
        
        return {
            status: 'error',
            error: errorInfo.message,
            code: errorCode,
            timestamp: new Date().toISOString(),
            ...additionalData
        };
    }

    // Handle validation errors
    handleValidationError(validationResult) {
        return {
            status: 'error',
            message: 'Validation failed',
            error: 'Invalid input data',
            code: 'VALIDATION_FAILED',
            errors: validationResult.errors || [],
            timestamp: new Date().toISOString()
        };
    }

    // Handle database errors
    handleDatabaseError(error, operation = 'Database Operation') {
        console.error(`${operation} Error:`, {
            message: error.message,
            code: error.code,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
            timestamp: new Date().toISOString()
        });

        // MongoDB specific errors
        if (error.code === 11000) {
            return this.createErrorResponse('VALIDATION_FAILED', {
                details: 'Duplicate entry found',
                field: Object.keys(error.keyPattern || {})[0]
            });
        }

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => ({
                field: err.path,
                message: err.message
            }));
            
            return {
                status: 'error',
                message: 'Validation failed',
                error: 'Invalid data format',
                code: 'VALIDATION_FAILED',
                errors: errors,
                timestamp: new Date().toISOString()
            };
        }

        if (error.name === 'CastError') {
            return this.createErrorResponse('VALIDATION_FAILED', {
                details: 'Invalid data type',
                field: error.path
            });
        }

        return this.createErrorResponse('DATABASE_ERROR', {
            details: 'Database operation failed'
        });
    }

    // Express error handling middleware
    expressErrorHandler() {
        return (error, req, res, next) => {
            // Log the error
            console.error('Express Error Handler:', {
                message: error.message,
                stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
                url: req.url,
                method: req.method,
                ip: req.ip,
                timestamp: new Date().toISOString()
            });

            // Handle different error types
            let errorResponse;

            if (error.name === 'ValidationError') {
                errorResponse = this.handleDatabaseError(error);
            } else if (error.code && this.errorCodes[error.code]) {
                errorResponse = this.createErrorResponse(error.code);
            } else if (error.status) {
                // Express HTTP errors
                errorResponse = {
                    status: 'error',
                    error: error.message || 'Request failed',
                    code: 'HTTP_ERROR',
                    timestamp: new Date().toISOString()
                };
            } else {
                errorResponse = this.createErrorResponse('INTERNAL_ERROR');
            }

            // Send error response
            const statusCode = errorResponse.status === 'error' ? 
                (this.errorCodes[errorResponse.code]?.status || 500) : 500;

            res.status(statusCode).json(errorResponse);
        };
    }

    // Async error wrapper
    asyncHandler(fn) {
        return (req, res, next) => {
            Promise.resolve(fn(req, res, next)).catch(next);
        };
    }

    // Log error for monitoring
    logError(error, context = {}) {
        const errorLog = {
            message: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString(),
            context,
            level: 'error'
        };

        // In production, send to logging service (e.g., Winston, Sentry)
        console.error('Error Log:', errorLog);

        // You can integrate with external logging services here
        // Example: Sentry.captureException(error, { extra: context });
    }

    // Create custom error
    createError(message, code = 'CUSTOM_ERROR', statusCode = 500) {
        const error = new Error(message);
        error.code = code;
        error.statusCode = statusCode;
        return error;
    }

    // Handle unhandled promise rejections
    handleUnhandledRejection() {
        process.on('unhandledRejection', (reason, promise) => {
            console.error('Unhandled Promise Rejection:', {
                reason: reason,
                promise: promise,
                timestamp: new Date().toISOString()
            });

            // In production, you might want to gracefully shutdown
            if (process.env.NODE_ENV === 'production') {
                console.log('Shutting down due to unhandled promise rejection');
                process.exit(1);
            }
        });
    }

    // Handle uncaught exceptions
    handleUncaughtException() {
        process.on('uncaughtException', (error) => {
            console.error('Uncaught Exception:', {
                message: error.message,
                stack: error.stack,
                timestamp: new Date().toISOString()
            });

            // Graceful shutdown
            console.log('Shutting down due to uncaught exception');
            process.exit(1);
        });
    }
}

// Create singleton instance
const errorHandler = new ErrorHandler();

// Setup global error handlers
errorHandler.handleUnhandledRejection();
errorHandler.handleUncaughtException();

module.exports = errorHandler;