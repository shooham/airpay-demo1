/**
 * Error Handler Utility for AirPay Integration
 * Provides consistent error handling across the application
 */

class ErrorHandler {
    static handleAirPayError(error, context = 'AirPay Operation') {
        console.error(`${context} Error:`, error);
        
        // Network errors
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
            return {
                status: 'error',
                message: 'Network connection failed',
                error: 'Unable to connect to AirPay servers',
                code: 'NETWORK_ERROR'
            };
        }
        
        // Timeout errors
        if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            return {
                status: 'error',
                message: 'Request timeout',
                error: 'AirPay API request timed out',
                code: 'TIMEOUT_ERROR'
            };
        }
        
        // HTTP errors
        if (error.response) {
            const status = error.response.status;
            const data = error.response.data;
            
            if (status === 401) {
                return {
                    status: 'error',
                    message: 'Authentication failed',
                    error: 'Invalid AirPay credentials',
                    code: 'AUTH_ERROR'
                };
            }
            
            if (status === 400) {
                return {
                    status: 'error',
                    message: 'Bad request',
                    error: data?.message || 'Invalid request parameters',
                    code: 'VALIDATION_ERROR'
                };
            }
            
            if (status >= 500) {
                return {
                    status: 'error',
                    message: 'Server error',
                    error: 'AirPay server error',
                    code: 'SERVER_ERROR'
                };
            }
        }
        
        // Encryption/Decryption errors
        if (error.message.includes('encrypt') || error.message.includes('decrypt')) {
            return {
                status: 'error',
                message: 'Encryption error',
                error: 'Failed to process encrypted data',
                code: 'ENCRYPTION_ERROR'
            };
        }
        
        // Generic error
        return {
            status: 'error',
            message: 'Operation failed',
            error: error.message || 'Unknown error occurred',
            code: 'GENERIC_ERROR'
        };
    }
    
    static handleValidationError(missingFields) {
        return {
            status: 'error',
            message: 'Validation failed',
            error: `Missing required fields: ${missingFields.join(', ')}`,
            code: 'VALIDATION_ERROR'
        };
    }
    
    static handleDatabaseError(error, operation = 'Database operation') {
        console.error(`${operation} Error:`, error);
        
        if (error.name === 'ValidationError') {
            return {
                status: 'error',
                message: 'Data validation failed',
                error: error.message,
                code: 'DB_VALIDATION_ERROR'
            };
        }
        
        if (error.name === 'MongoError' || error.name === 'MongooseError') {
            return {
                status: 'error',
                message: 'Database error',
                error: 'Database operation failed',
                code: 'DB_ERROR'
            };
        }
        
        return {
            status: 'error',
            message: 'Database operation failed',
            error: error.message,
            code: 'DB_GENERIC_ERROR'
        };
    }
}

module.exports = ErrorHandler;