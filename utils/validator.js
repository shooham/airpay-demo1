/**
 * Enhanced Validation Utility for AirPay Integration
 * Provides comprehensive input validation and sanitization
 */

class Validator {
    static validatePaymentRequest(data) {
        const errors = [];
        
        // Required fields
        const requiredFields = ['amount', 'orderId', 'customerEmail', 'customerPhone', 'customerName'];
        requiredFields.forEach(field => {
            if (!data[field]) {
                errors.push(`${field} is required`);
            }
        });
        
        // Amount validation with configurable limits
        if (data.amount) {
            const amount = parseFloat(data.amount);
            if (isNaN(amount) || amount <= 0) {
                errors.push('Amount must be a positive number');
            }
            
            // Get limits from environment or use defaults
            const minAmount = parseFloat(process.env.MIN_PAYMENT_AMOUNT) || 1;
            const maxAmount = parseFloat(process.env.MAX_PAYMENT_AMOUNT) || 1000000;
            
            if (amount < minAmount) {
                errors.push(`Amount must be at least ₹${minAmount}`);
            }
            if (amount > maxAmount) {
                errors.push(`Amount exceeds maximum limit of ₹${maxAmount.toLocaleString('en-IN')}`);
            }
            
            // Check for decimal places (max 2)
            if (amount.toString().includes('.') && amount.toString().split('.')[1].length > 2) {
                errors.push('Amount can have maximum 2 decimal places');
            }
        }
        
        // Enhanced email validation
        if (data.customerEmail) {
            const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            if (!emailRegex.test(data.customerEmail)) {
                errors.push('Invalid email format');
            }
            if (data.customerEmail.length > 254) {
                errors.push('Email address too long');
            }
            // Check for common disposable email domains
            const disposableDomains = ['10minutemail.com', 'tempmail.org', 'guerrillamail.com'];
            const emailDomain = data.customerEmail.split('@')[1]?.toLowerCase();
            if (disposableDomains.includes(emailDomain)) {
                errors.push('Disposable email addresses are not allowed');
            }
        }
        
        // Enhanced phone validation
        if (data.customerPhone) {
            // Remove any non-digit characters
            const cleanPhone = data.customerPhone.replace(/\D/g, '');
            
            // Indian mobile number validation
            const phoneRegex = /^[6-9]\d{9}$/;
            if (!phoneRegex.test(cleanPhone)) {
                errors.push('Invalid phone number format (must be 10 digits starting with 6-9)');
            }
            
            // Check for sequential or repeated numbers (basic fraud detection)
            if (/^(\d)\1{9}$/.test(cleanPhone) || /^(0123456789|9876543210)$/.test(cleanPhone)) {
                errors.push('Invalid phone number pattern');
            }
        }
        
        // Enhanced Order ID validation
        if (data.orderId) {
            if (data.orderId.length < 3) {
                errors.push('Order ID must be at least 3 characters long');
            }
            if (data.orderId.length > 50) {
                errors.push('Order ID must be less than 50 characters');
            }
            if (!/^[a-zA-Z0-9_-]+$/.test(data.orderId)) {
                errors.push('Order ID can only contain alphanumeric characters, hyphens, and underscores');
            }
            // Check for SQL injection patterns
            const sqlPatterns = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'script'];
            const lowerOrderId = data.orderId.toLowerCase();
            if (sqlPatterns.some(pattern => lowerOrderId.includes(pattern))) {
                errors.push('Order ID contains invalid characters');
            }
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }
    
    static validateSeamlessPayment(data) {
        const baseValidation = this.validatePaymentRequest(data);
        if (!baseValidation.isValid) {
            return baseValidation;
        }
        
        const errors = [];
        
        // Payment mode validation
        if (!data.paymentMode) {
            errors.push('Payment mode is required for seamless payments');
        }
        
        // Card payment validation
        if (data.paymentMode === 'pg') {
            if (!data.cardNumber || !data.cardCvv || !data.expiryMm || !data.expiryYy) {
                errors.push('Card details are required for card payments');
            }
            
            if (data.cardNumber && !/^\d{13,19}$/.test(data.cardNumber.replace(/\s/g, ''))) {
                errors.push('Invalid card number format');
            }
            
            if (data.cardCvv && !/^\d{3,4}$/.test(data.cardCvv)) {
                errors.push('Invalid CVV format');
            }
            
            if (data.expiryMm && (!/^\d{2}$/.test(data.expiryMm) || parseInt(data.expiryMm) < 1 || parseInt(data.expiryMm) > 12)) {
                errors.push('Invalid expiry month');
            }
            
            if (data.expiryYy && !/^\d{2}$/.test(data.expiryYy)) {
                errors.push('Invalid expiry year');
            }
        }
        
        // UPI payment validation
        if (data.paymentMode === 'upi') {
            if (!data.customerVpa) {
                errors.push('VPA is required for UPI payments');
            }
            
            if (data.customerVpa && !/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/.test(data.customerVpa)) {
                errors.push('Invalid VPA format');
            }
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }
    
    static validateRefundRequest(data) {
        const errors = [];
        
        // Required fields
        if (!data.transactionId) {
            errors.push('Transaction ID is required');
        }
        
        if (!data.amount) {
            errors.push('Refund amount is required');
        }
        
        // Amount validation
        if (data.amount) {
            const amount = parseFloat(data.amount);
            if (isNaN(amount) || amount <= 0) {
                errors.push('Refund amount must be a positive number');
            }
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }
    
    static sanitizeInput(data) {
        const sanitized = {};
        
        Object.keys(data).forEach(key => {
            if (typeof data[key] === 'string') {
                // Comprehensive sanitization
                sanitized[key] = data[key]
                    .replace(/[<>]/g, '') // Remove HTML tags
                    .replace(/['"]/g, '') // Remove quotes
                    .replace(/[&]/g, '&amp;') // Escape ampersand
                    .replace(/javascript:/gi, '') // Remove javascript: protocol
                    .replace(/on\w+=/gi, '') // Remove event handlers
                    .replace(/script/gi, '') // Remove script tags
                    .replace(/eval\(/gi, '') // Remove eval calls
                    .replace(/expression\(/gi, '') // Remove CSS expressions
                    .trim();
                
                // Limit string length to prevent buffer overflow
                if (sanitized[key].length > 1000) {
                    sanitized[key] = sanitized[key].substring(0, 1000);
                }
            } else if (typeof data[key] === 'number') {
                // Validate numbers
                if (isNaN(data[key]) || !isFinite(data[key])) {
                    sanitized[key] = 0;
                } else {
                    sanitized[key] = data[key];
                }
            } else {
                sanitized[key] = data[key];
            }
        });
        
        return sanitized;
    }

    // Additional security validation methods
    static validateIPAddress(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    static detectSQLInjection(input) {
        const sqlPatterns = [
            /(\b(select|insert|update|delete|drop|create|alter|exec|execute|union|script)\b)/gi,
            /(\b(or|and)\s+\d+\s*=\s*\d+)/gi,
            /(--|\/\*|\*\/|;)/g,
            /(\b(char|varchar|nchar|nvarchar|text|ntext)\s*\()/gi
        ];
        
        return sqlPatterns.some(pattern => pattern.test(input));
    }

    static detectXSS(input) {
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
            /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi
        ];
        
        return xssPatterns.some(pattern => pattern.test(input));
    }
}

module.exports = Validator;