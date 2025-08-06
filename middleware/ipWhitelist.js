const { isIP } = require('net');

/**
 * IP Whitelisting Middleware for AirPay Integration
 * Provides comprehensive IP-based access control
 */

class IPWhitelist {
    constructor() {
        // AirPay official server IPs (get these from AirPay support)
        this.airpayIPs = [
            '103.25.232.0/24',
            '103.25.233.0/24',
            '202.131.96.0/24',
            '103.231.78.0/24',
            // Add more IPs as provided by AirPay
        ];
        
        // Load additional IPs from environment
        if (process.env.AIRPAY_WHITELIST_IPS) {
            const envIPs = process.env.AIRPAY_WHITELIST_IPS.split(',');
            this.airpayIPs.push(...envIPs);
        }
        
        // Admin/Internal IPs for management endpoints
        this.adminIPs = [
            '127.0.0.1',
            '::1',
            // Add your office/admin IPs
        ];
        
        if (process.env.ADMIN_WHITELIST_IPS) {
            const adminEnvIPs = process.env.ADMIN_WHITELIST_IPS.split(',');
            this.adminIPs.push(...adminEnvIPs);
        }
    }

    // Convert CIDR to range
    cidrToRange(cidr) {
        const [ip, prefixLength] = cidr.split('/');
        const prefix = parseInt(prefixLength, 10);
        
        if (!isIP(ip) || prefix < 0 || prefix > 32) {
            throw new Error(`Invalid CIDR: ${cidr}`);
        }
        
        const ipInt = this.ipToInt(ip);
        const mask = (0xffffffff << (32 - prefix)) >>> 0;
        const networkAddress = (ipInt & mask) >>> 0;
        const broadcastAddress = (networkAddress | (0xffffffff >>> prefix)) >>> 0;
        
        return {
            start: networkAddress,
            end: broadcastAddress
        };
    }

    // Convert IP to integer
    ipToInt(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    }

    // Check if IP is in CIDR range
    isIPInCIDR(ip, cidr) {
        try {
            if (!isIP(ip)) {
                return false;
            }
            
            // Handle single IP
            if (!cidr.includes('/')) {
                return ip === cidr;
            }
            
            const range = this.cidrToRange(cidr);
            const ipInt = this.ipToInt(ip);
            
            return ipInt >= range.start && ipInt <= range.end;
        } catch (error) {
            console.error('IP CIDR check error:', error.message);
            return false;
        }
    }

    // Check if IP is in whitelist
    isIPWhitelisted(ip, whitelist) {
        if (!ip || !isIP(ip)) {
            return false;
        }
        
        return whitelist.some(allowedIP => this.isIPInCIDR(ip, allowedIP.trim()));
    }

    // Get client IP from request
    getClientIP(req) {
        return req.ip || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress ||
               (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
               req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers['x-real-ip'];
    }

    // Middleware for AirPay webhook endpoints
    webhookIPWhitelist() {
        return (req, res, next) => {
            const clientIP = this.getClientIP(req);
            
            if (!clientIP) {
                console.error('Unable to determine client IP');
                return res.status(400).json({
                    status: 'error',
                    message: 'Unable to determine client IP',
                    code: 'IP_DETECTION_FAILED'
                });
            }
            
            // Check if IP is whitelisted
            if (!this.isIPWhitelisted(clientIP, this.airpayIPs)) {
                console.warn('Webhook blocked - Unauthorized IP:', clientIP);
                
                // Log security event
                console.error('SECURITY_ALERT: Webhook attempt from unauthorized IP:', {
                    ip: clientIP,
                    timestamp: new Date().toISOString(),
                    userAgent: req.headers['user-agent'],
                    url: req.url,
                    method: req.method
                });
                
                return res.status(403).json({
                    status: 'error',
                    message: 'Access denied',
                    code: 'IP_NOT_WHITELISTED'
                });
            }
            
            // Log successful webhook from whitelisted IP
            console.log('Webhook received from whitelisted AirPay IP:', clientIP);
            next();
        };
    }

    // Middleware for admin endpoints
    adminIPWhitelist() {
        return (req, res, next) => {
            const clientIP = this.getClientIP(req);
            
            if (!clientIP) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Unable to determine client IP',
                    code: 'IP_DETECTION_FAILED'
                });
            }
            
            if (!this.isIPWhitelisted(clientIP, this.adminIPs)) {
                console.warn('Admin access blocked - Unauthorized IP:', clientIP);
                
                return res.status(403).json({
                    status: 'error',
                    message: 'Admin access denied',
                    code: 'ADMIN_IP_NOT_WHITELISTED'
                });
            }
            
            next();
        };
    }

    // Flexible IP whitelist middleware
    createIPWhitelist(allowedIPs, errorMessage = 'Access denied') {
        return (req, res, next) => {
            const clientIP = this.getClientIP(req);
            
            if (!clientIP) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Unable to determine client IP',
                    code: 'IP_DETECTION_FAILED'
                });
            }
            
            if (!this.isIPWhitelisted(clientIP, allowedIPs)) {
                console.warn(`Access blocked - ${errorMessage}:`, clientIP);
                
                return res.status(403).json({
                    status: 'error',
                    message: errorMessage,
                    code: 'IP_ACCESS_DENIED'
                });
            }
            
            next();
        };
    }

    // Development mode bypass
    isDevelopmentMode() {
        return process.env.NODE_ENV === 'development' || process.env.BYPASS_IP_WHITELIST === 'true';
    }

    // Conditional IP whitelist (bypass in development)
    conditionalIPWhitelist(allowedIPs, errorMessage = 'Access denied') {
        return (req, res, next) => {
            // Bypass in development mode
            if (this.isDevelopmentMode()) {
                console.log('IP whitelist bypassed - Development mode');
                return next();
            }
            
            return this.createIPWhitelist(allowedIPs, errorMessage)(req, res, next);
        };
    }
}

// Create singleton instance
const ipWhitelist = new IPWhitelist();

module.exports = {
    webhookIPWhitelist: ipWhitelist.webhookIPWhitelist.bind(ipWhitelist),
    adminIPWhitelist: ipWhitelist.adminIPWhitelist.bind(ipWhitelist),
    createIPWhitelist: ipWhitelist.createIPWhitelist.bind(ipWhitelist),
    conditionalIPWhitelist: ipWhitelist.conditionalIPWhitelist.bind(ipWhitelist),
    ipWhitelist
};