/**
 * Validation Utility for AirPay Integration
 * Provides input validation for payment requests
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
        
        // Amount validation
        if (data.amount) {
            const amount = parseFloat(data.amount);
            if (isNaN(amount) || amount <= 0) {
                errors.push('Amount must be a positive number');
            }
            if (amount > 1000000) { // 10 Lakh limit
                errors.push('Amount exceeds maximum limit of ₹10,00,000');
            }
        }
        
        // Email validation
        if (data.customerEmail) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(data.customerEmail)) {
                errors.push('Invalid email format');
            }
        }
        
        // Phone validation
        if (data.customerPhone) {
            const phoneRegex = /^[6-9]\d{9}$/;
            if (!phoneRegex.test(data.customerPhone)) {
                errors.push('Invalid phone number format (must be 10 digits starting with 6-9)');
            }
        }
        
        // Order ID validation
        if (data.orderId) {
            if (data.orderId.length > 50) {
                errors.push('Order ID must be less than 50 characters');
            }
            if (!/^[a-zA-Z0-9_-]+$/.test(data.orderId)) {
                errors.push('Order ID can only contain alphanumeric characters, hyphens, and underscores');
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
                // Remove potentially harmful characters
                sanitized[key] = data[key]
                    .replace(/[<>]/g, '') // Remove HTML tags
                    .replace(/['"]/g, '') // Remove quotes
                    .trim();
            } else {
                sanitized[key] = data[key];
            }
        });
        
        return sanitized;
    }
}

module.exports = Validator;