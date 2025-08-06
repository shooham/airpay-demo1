const crypto = require('crypto');

/**
 * CSRF Protection Middleware for AirPay Integration
 * Protects against Cross-Site Request Forgery attacks
 */

class CSRFProtection {
    constructor() {
        this.tokenStore = new Map(); // In production, use Redis or database
        this.tokenExpiry = 30 * 60 * 1000; // 30 minutes
        
        // Clean expired tokens every 10 minutes
        setInterval(() => {
            this.cleanExpiredTokens();
        }, 10 * 60 * 1000);
    }

    // Generate CSRF token
    generateToken(sessionId) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Date.now() + this.tokenExpiry;
        
        this.tokenStore.set(token, {
            sessionId: sessionId,
            expiry: expiry,
            used: false
        });
        
        return token;
    }

    // Validate CSRF token
    validateToken(token, sessionId) {
        if (!token || !sessionId) {
            return false;
        }

        const tokenData = this.tokenStore.get(token);
        
        if (!tokenData) {
            return false;
        }

        // Check if token is expired
        if (Date.now() > tokenData.expiry) {
            this.tokenStore.delete(token);
            return false;
        }

        // Check if token belongs to the session
        if (tokenData.sessionId !== sessionId) {
            return false;
        }

        // Check if token is already used (one-time use)
        if (tokenData.used) {
            return false;
        }

        // Mark token as used
        tokenData.used = true;
        
        return true;
    }

    // Clean expired tokens
    cleanExpiredTokens() {
        const now = Date.now();
        for (const [token, data] of this.tokenStore.entries()) {
            if (now > data.expiry) {
                this.tokenStore.delete(token);
            }
        }
    }

    // Middleware to generate CSRF token
    generateTokenMiddleware() {
        return (req, res, next) => {
            const sessionId = req.sessionID || req.ip + req.headers['user-agent'];
            const csrfToken = this.generateToken(sessionId);
            
            req.csrfToken = csrfToken;
            res.locals.csrfToken = csrfToken;
            
            next();
        };
    }

    // Middleware to validate CSRF token
    validateTokenMiddleware() {
        return (req, res, next) => {
            // Skip CSRF validation for GET requests and callbacks
            if (req.method === 'GET' || req.path.includes('/callback')) {
                return next();
            }

            const token = req.headers['x-csrf-token'] || req.body._csrf || req.query._csrf;
            const sessionId = req.sessionID || req.ip + req.headers['user-agent'];

            if (!this.validateToken(token, sessionId)) {
                return res.status(403).json({
                    status: 'error',
                    message: 'CSRF token validation failed',
                    error: 'Invalid or missing CSRF token',
                    code: 'CSRF_TOKEN_INVALID'
                });
            }

            next();
        };
    }
}

// Create singleton instance
const csrfProtection = new CSRFProtection();

module.exports = {
    generateToken: csrfProtection.generateTokenMiddleware(),
    validateToken: csrfProtection.validateTokenMiddleware(),
    csrfProtection
};