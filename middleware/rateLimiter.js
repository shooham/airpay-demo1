const rateLimit = require('express-rate-limit');
const MongoStore = require('rate-limit-mongo');

/**
 * Rate Limiting Middleware for AirPay Integration
 * Protects against DDoS and brute force attacks
 */

// Payment initiation rate limiter
const paymentLimiter = rateLimit({
    store: new MongoStore({
        uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/payment-gateway',
        collectionName: 'rate_limit_payment',
        expireTimeMs: 15 * 60 * 1000, // 15 minutes
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 payment requests per windowMs
    message: {
        status: 'error',
        message: 'Too many payment requests',
        error: 'Rate limit exceeded. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for health checks
        return req.path.includes('/health');
    },
    keyGenerator: (req) => {
        // Use IP + user ID if available for more granular limiting
        return req.ip + (req.user?.id || '');
    }
});

// Status check rate limiter (more lenient)
const statusLimiter = rateLimit({
    store: new MongoStore({
        uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/payment-gateway',
        collectionName: 'rate_limit_status',
        expireTimeMs: 15 * 60 * 1000,
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Limit each IP to 200 status requests per windowMs
    message: {
        status: 'error',
        message: 'Too many status requests',
        error: 'Rate limit exceeded. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip + (req.user?.id || '');
    }
});

// Refund rate limiter (most restrictive)
const refundLimiter = rateLimit({
    store: new MongoStore({
        uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/payment-gateway',
        collectionName: 'rate_limit_refund',
        expireTimeMs: 60 * 60 * 1000, // 1 hour
    }),
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50, // Limit each IP to 50 refund requests per hour
    message: {
        status: 'error',
        message: 'Too many refund requests',
        error: 'Rate limit exceeded. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip + (req.user?.id || '');
    }
});

// General API rate limiter
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // Limit each IP to 1000 requests per windowMs
    message: {
        status: 'error',
        message: 'Too many requests',
        error: 'Rate limit exceeded. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Callback rate limiter (for webhooks)
const callbackLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 1000, // Allow many callbacks from AirPay
    message: {
        status: 'error',
        message: 'Too many callback requests',
        error: 'Rate limit exceeded.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    skip: (req) => {
        // Skip if request is from AirPay servers (implement IP whitelist)
        const airpayIPs = [
            '103.25.232.0/24',
            '103.25.233.0/24',
            // Add AirPay server IPs here
        ];
        
        // Simple IP check (implement proper CIDR matching in production)
        return airpayIPs.some(ip => req.ip.startsWith(ip.split('/')[0].substring(0, 10)));
    }
});

module.exports = {
    paymentLimiter,
    statusLimiter,
    refundLimiter,
    generalLimiter,
    callbackLimiter
};