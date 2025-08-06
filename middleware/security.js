const helmet = require('helmet');
const cors = require('cors');

/**
 * Security Middleware Configuration
 * Implements comprehensive security headers and CORS policy
 */

// Helmet configuration for security headers
const helmetConfig = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'", "https://payments.airpay.co.in", "https://kraken.airpay.co.in"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy: false, // Allow embedding for payment flows
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

// CORS configuration
const corsConfig = cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        // Define allowed origins
        const allowedOrigins = [
            process.env.FRONTEND_URL,
            process.env.ADMIN_URL,
            'https://payments.airpay.co.in',
            'https://kraken.airpay.co.in'
        ].filter(Boolean); // Remove undefined values
        
        // In development, allow localhost
        if (process.env.NODE_ENV === 'development') {
            allowedOrigins.push('http://localhost:3000', 'http://localhost:3001');
        }
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.warn('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-CSRF-Token'
    ],
    exposedHeaders: ['X-CSRF-Token'],
    maxAge: 86400 // 24 hours
});

// Request sanitization middleware
const sanitizeRequest = (req, res, next) => {
    // Remove null bytes from all string inputs
    const sanitizeObject = (obj) => {
        for (const key in obj) {
            if (typeof obj[key] === 'string') {
                obj[key] = obj[key].replace(/\0/g, '');
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitizeObject(obj[key]);
            }
        }
    };
    
    if (req.body) sanitizeObject(req.body);
    if (req.query) sanitizeObject(req.query);
    if (req.params) sanitizeObject(req.params);
    
    next();
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
    // Remove server information
    res.removeHeader('X-Powered-By');
    
    // Add custom security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    next();
};

// Request logging middleware for security monitoring
const securityLogger = (req, res, next) => {
    const startTime = Date.now();
    
    // Log security-relevant information
    const logData = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        contentLength: req.get('Content-Length'),
        contentType: req.get('Content-Type')
    };
    
    // Log suspicious patterns
    const suspiciousPatterns = [
        /\.\./,  // Directory traversal
        /<script/i,  // XSS attempts
        /union.*select/i,  // SQL injection
        /javascript:/i,  // JavaScript protocol
        /vbscript:/i,  // VBScript protocol
        /on\w+=/i  // Event handlers
    ];
    
    const urlAndBody = req.url + JSON.stringify(req.body || {});
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(urlAndBody));
    
    if (isSuspicious) {
        console.warn('Suspicious request detected:', logData);
    }
    
    // Log response time on finish
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        if (duration > 5000) { // Log slow requests
            console.warn('Slow request detected:', { ...logData, duration, status: res.statusCode });
        }
    });
    
    next();
};

module.exports = {
    helmetConfig,
    corsConfig,
    sanitizeRequest,
    securityHeaders,
    securityLogger
};