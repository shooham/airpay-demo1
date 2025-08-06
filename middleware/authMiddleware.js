const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Authentication Middleware for AirPay Integration
 * Provides JWT-based authentication and API key validation
 */

class AuthMiddleware {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || this.generateSecureSecret();
        this.apiKeys = new Map(); // In production, use Redis or database
        this.sessionStore = new Map(); // In production, use Redis
        
        // Load API keys from environment
        this.loadAPIKeys();
    }

    generateSecureSecret() {
        const secret = crypto.randomBytes(64).toString('hex');
        console.warn('⚠️  JWT_SECRET not set, using generated secret. Set JWT_SECRET in production!');
        return secret;
    }

    loadAPIKeys() {
        // Load API keys from environment variables
        if (process.env.API_KEYS) {
            const keys = process.env.API_KEYS.split(',');
            keys.forEach(key => {
                const [keyId, keyValue] = key.split(':');
                if (keyId && keyValue) {
                    this.apiKeys.set(keyValue, {
                        id: keyId,
                        permissions: ['payment', 'status', 'refund'],
                        createdAt: new Date(),
                        lastUsed: null,
                        usageCount: 0
                    });
                }
            });
        }
        
        // Default development API key
        if (process.env.NODE_ENV === 'development' && this.apiKeys.size === 0) {
            const devKey = 'dev_' + crypto.randomBytes(16).toString('hex');
            this.apiKeys.set(devKey, {
                id: 'development',
                permissions: ['payment', 'status', 'refund'],
                createdAt: new Date(),
                lastUsed: null,
                usageCount: 0
            });
            console.log(`🔑 Development API Key: ${devKey}`);
        }
    }

    // Generate JWT token
    generateToken(payload, expiresIn = '24h') {
        return jwt.sign(payload, this.jwtSecret, { 
            expiresIn,
            issuer: 'airpay-gateway',
            audience: 'payment-api'
        });
    }

    // Verify JWT token
    verifyToken(token) {
        try {
            return jwt.verify(token, this.jwtSecret, {
                issuer: 'airpay-gateway',
                audience: 'payment-api'
            });
        } catch (error) {
            throw new Error('Invalid or expired token');
        }
    }

    // JWT Authentication middleware
    protect(req, res, next) {
        try {
            let token;
            
            // Get token from header
            if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
                token = req.headers.authorization.split(' ')[1];
            } else if (req.headers['x-auth-token']) {
                token = req.headers['x-auth-token'];
            }
            
            if (!token) {
                return res.status(401).json({
                    status: 'error',
                    message: 'Access denied',
                    error: 'No token provided',
                    code: 'NO_TOKEN'
                });
            }
            
            // Verify token
            const decoded = this.verifyToken(token);
            req.user = decoded;
            
            // Log authentication
            console.log(`Authenticated user: ${decoded.id || decoded.email || 'unknown'}`);
            
            next();
        } catch (error) {
            console.error('Authentication error:', error.message);
            return res.status(401).json({
                status: 'error',
                message: 'Access denied',
                error: 'Invalid token',
                code: 'INVALID_TOKEN'
            });
        }
    }

    // API Key Authentication middleware
    apiKeyAuth(req, res, next) {
        try {
            const apiKey = req.headers['x-api-key'] || req.query.api_key;
            
            if (!apiKey) {
                return res.status(401).json({
                    status: 'error',
                    message: 'Access denied',
                    error: 'API key required',
                    code: 'NO_API_KEY'
                });
            }
            
            const keyData = this.apiKeys.get(apiKey);
            
            if (!keyData) {
                console.warn('Invalid API key attempt:', apiKey.substring(0, 8) + '...');
                return res.status(401).json({
                    status: 'error',
                    message: 'Access denied',
                    error: 'Invalid API key',
                    code: 'INVALID_API_KEY'
                });
            }
            
            // Update usage statistics
            keyData.lastUsed = new Date();
            keyData.usageCount += 1;
            
            // Add key info to request
            req.apiKey = {
                id: keyData.id,
                permissions: keyData.permissions
            };
            
            console.log(`API Key authenticated: ${keyData.id}`);
            next();
        } catch (error) {
            console.error('API Key authentication error:', error.message);
            return res.status(500).json({
                status: 'error',
                message: 'Authentication failed',
                error: 'Internal authentication error',
                code: 'AUTH_ERROR'
            });
        }
    }

    // Permission-based authorization
    requirePermission(permission) {
        return (req, res, next) => {
            // Check JWT user permissions
            if (req.user && req.user.permissions && req.user.permissions.includes(permission)) {
                return next();
            }
            
            // Check API key permissions
            if (req.apiKey && req.apiKey.permissions && req.apiKey.permissions.includes(permission)) {
                return next();
            }
            
            return res.status(403).json({
                status: 'error',
                message: 'Access denied',
                error: `Permission '${permission}' required`,
                code: 'INSUFFICIENT_PERMISSIONS'
            });
        };
    }

    // Optional authentication (for public endpoints with optional auth)
    optionalAuth(req, res, next) {
        try {
            let token;
            
            if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
                token = req.headers.authorization.split(' ')[1];
            } else if (req.headers['x-auth-token']) {
                token = req.headers['x-auth-token'];
            }
            
            if (token) {
                try {
                    const decoded = this.verifyToken(token);
                    req.user = decoded;
                } catch (error) {
                    // Token invalid, but continue without auth
                    console.warn('Invalid token in optional auth:', error.message);
                }
            }
            
            next();
        } catch (error) {
            // Continue without authentication
            next();
        }
    }

    // Session-based authentication
    sessionAuth(req, res, next) {
        const sessionId = req.headers['x-session-id'] || req.cookies?.sessionId;
        
        if (!sessionId) {
            return res.status(401).json({
                status: 'error',
                message: 'Access denied',
                error: 'Session required',
                code: 'NO_SESSION'
            });
        }
        
        const session = this.sessionStore.get(sessionId);
        
        if (!session || session.expiresAt < new Date()) {
            if (session) {
                this.sessionStore.delete(sessionId);
            }
            return res.status(401).json({
                status: 'error',
                message: 'Access denied',
                error: 'Session expired',
                code: 'SESSION_EXPIRED'
            });
        }
        
        // Extend session
        session.expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        req.session = session;
        
        next();
    }

    // Create session
    createSession(userId, userData = {}) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        const session = {
            id: sessionId,
            userId: userId,
            data: userData,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
        };
        
        this.sessionStore.set(sessionId, session);
        return sessionId;
    }

    // Destroy session
    destroySession(sessionId) {
        return this.sessionStore.delete(sessionId);
    }

    // Clean expired sessions
    cleanExpiredSessions() {
        const now = new Date();
        for (const [sessionId, session] of this.sessionStore.entries()) {
            if (session.expiresAt < now) {
                this.sessionStore.delete(sessionId);
            }
        }
    }

    // Admin authentication (stricter)
    adminAuth(req, res, next) {
        try {
            // First check regular authentication
            this.protect(req, res, (err) => {
                if (err) return;
                
                // Check if user has admin role
                if (!req.user || !req.user.role || req.user.role !== 'admin') {
                    return res.status(403).json({
                        status: 'error',
                        message: 'Access denied',
                        error: 'Admin access required',
                        code: 'ADMIN_REQUIRED'
                    });
                }
                
                next();
            });
        } catch (error) {
            return res.status(500).json({
                status: 'error',
                message: 'Authentication failed',
                error: 'Internal authentication error',
                code: 'AUTH_ERROR'
            });
        }
    }
}

// Create singleton instance
const authMiddleware = new AuthMiddleware();

// Clean expired sessions every 10 minutes
setInterval(() => {
    authMiddleware.cleanExpiredSessions();
}, 10 * 60 * 1000);

module.exports = {
    protect: authMiddleware.protect.bind(authMiddleware),
    apiKeyAuth: authMiddleware.apiKeyAuth.bind(authMiddleware),
    requirePermission: authMiddleware.requirePermission.bind(authMiddleware),
    optionalAuth: authMiddleware.optionalAuth.bind(authMiddleware),
    sessionAuth: authMiddleware.sessionAuth.bind(authMiddleware),
    adminAuth: authMiddleware.adminAuth.bind(authMiddleware),
    generateToken: authMiddleware.generateToken.bind(authMiddleware),
    createSession: authMiddleware.createSession.bind(authMiddleware),
    destroySession: authMiddleware.destroySession.bind(authMiddleware),
    authMiddleware
};