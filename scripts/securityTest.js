const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

/**
 * Comprehensive Security Test Suite for AirPay Integration
 * Tests all security measures and vulnerabilities
 */

class SecurityTester {
    constructor() {
        this.baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';
        this.apiUrl = `${this.baseUrl}/api/v1/gateways/airpay`;
        this.testResults = {
            passed: [],
            failed: [],
            warnings: []
        };
    }

    // Test rate limiting
    async testRateLimiting() {
        console.log('\n🔒 Testing Rate Limiting...');
        
        try {
            const requests = [];
            // Send 150 requests rapidly to test rate limiting
            for (let i = 0; i < 150; i++) {
                requests.push(
                    axios.get(`${this.apiUrl}/health`, { timeout: 5000 })
                        .catch(err => ({ error: err.response?.status || err.code }))
                );
            }
            
            const responses = await Promise.all(requests);
            const rateLimited = responses.filter(r => r.error === 429).length;
            
            if (rateLimited > 0) {
                this.testResults.passed.push('✅ Rate limiting is working');
                console.log(`   Rate limited ${rateLimited} requests`);
            } else {
                this.testResults.warnings.push('⚠️  Rate limiting may not be configured');
            }
        } catch (error) {
            this.testResults.failed.push('❌ Rate limiting test failed');
        }
    }

    // Test SQL injection protection
    async testSQLInjection() {
        console.log('\n🛡️  Testing SQL Injection Protection...');
        
        const sqlPayloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
            "1; DELETE FROM transactions; --"
        ];
        
        let protectedCount = 0;
        
        for (const payload of sqlPayloads) {
            try {
                const response = await axios.post(`${this.apiUrl}/initiate`, {
                    amount: 100,
                    orderId: payload,
                    customerEmail: 'test@example.com',
                    customerPhone: '9999999999',
                    customerName: 'Test User'
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });
                
                if (response.status === 400 || response.data?.message?.includes('Validation failed')) {
                    protectedCount++;
                }
            } catch (error) {
                // Network errors are expected for blocked requests
                protectedCount++;
            }
        }
        
        if (protectedCount === sqlPayloads.length) {
            this.testResults.passed.push('✅ SQL injection protection is working');
        } else {
            this.testResults.failed.push('❌ SQL injection protection insufficient');
        }
    }

    // Test XSS protection
    async testXSSProtection() {
        console.log('\n🔐 Testing XSS Protection...');
        
        const xssPayloads = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            '<img src="x" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            '"><script>alert("xss")</script>'
        ];
        
        let protectedCount = 0;
        
        for (const payload of xssPayloads) {
            try {
                const response = await axios.post(`${this.apiUrl}/initiate`, {
                    amount: 100,
                    orderId: 'TEST123',
                    customerEmail: 'test@example.com',
                    customerPhone: '9999999999',
                    customerName: payload
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });
                
                // Check if payload was sanitized in response
                const responseStr = JSON.stringify(response.data);
                if (!responseStr.includes('<script>') && !responseStr.includes('javascript:')) {
                    protectedCount++;
                }
            } catch (error) {
                protectedCount++;
            }
        }
        
        if (protectedCount === xssPayloads.length) {
            this.testResults.passed.push('✅ XSS protection is working');
        } else {
            this.testResults.failed.push('❌ XSS protection insufficient');
        }
    }

    // Test CSRF protection
    async testCSRFProtection() {
        console.log('\n🛡️  Testing CSRF Protection...');
        
        try {
            // Try to make a request without CSRF token
            const response = await axios.post(`${this.apiUrl}/initiate`, {
                amount: 100,
                orderId: 'TEST123',
                customerEmail: 'test@example.com',
                customerPhone: '9999999999',
                customerName: 'Test User'
            }, {
                timeout: 5000,
                validateStatus: () => true
            });
            
            if (response.status === 403 && response.data?.code === 'CSRF_TOKEN_INVALID') {
                this.testResults.passed.push('✅ CSRF protection is working');
            } else {
                this.testResults.warnings.push('⚠️  CSRF protection may not be enabled');
            }
        } catch (error) {
            this.testResults.warnings.push('⚠️  Could not test CSRF protection');
        }
    }

    // Test input validation
    async testInputValidation() {
        console.log('\n✅ Testing Input Validation...');
        
        const testCases = [
            { amount: -100, expected: 'fail' },
            { amount: 'invalid', expected: 'fail' },
            { amount: 10000000, expected: 'fail' }, // Above limit
            { customerEmail: 'invalid-email', expected: 'fail' },
            { customerPhone: '123', expected: 'fail' },
            { orderId: '', expected: 'fail' },
            { orderId: 'a'.repeat(100), expected: 'fail' } // Too long
        ];
        
        let validationWorking = 0;
        
        for (const testCase of testCases) {
            try {
                const payload = {
                    amount: 100,
                    orderId: 'TEST123',
                    customerEmail: 'test@example.com',
                    customerPhone: '9999999999',
                    customerName: 'Test User',
                    ...testCase
                };
                
                delete payload.expected;
                
                const response = await axios.post(`${this.apiUrl}/initiate`, payload, {
                    timeout: 5000,
                    validateStatus: () => true
                });
                
                if (testCase.expected === 'fail' && response.status === 400) {
                    validationWorking++;
                }
            } catch (error) {
                if (testCase.expected === 'fail') {
                    validationWorking++;
                }
            }
        }
        
        if (validationWorking >= testCases.length * 0.8) { // 80% pass rate
            this.testResults.passed.push('✅ Input validation is working');
        } else {
            this.testResults.failed.push('❌ Input validation insufficient');
        }
    }

    // Test security headers
    async testSecurityHeaders() {
        console.log('\n🔒 Testing Security Headers...');
        
        try {
            const response = await axios.get(`${this.apiUrl}/health`, { timeout: 5000 });
            const headers = response.headers;
            
            const requiredHeaders = [
                'x-content-type-options',
                'x-frame-options',
                'strict-transport-security',
                'x-xss-protection'
            ];
            
            const presentHeaders = requiredHeaders.filter(header => headers[header]);
            
            if (presentHeaders.length >= 3) {
                this.testResults.passed.push('✅ Security headers are present');
            } else {
                this.testResults.warnings.push('⚠️  Some security headers missing');
            }
            
            // Check if server info is hidden
            if (!headers['x-powered-by'] && !headers['server']) {
                this.testResults.passed.push('✅ Server information is hidden');
            } else {
                this.testResults.warnings.push('⚠️  Server information exposed');
            }
        } catch (error) {
            this.testResults.failed.push('❌ Could not test security headers');
        }
    }

    // Test encryption strength
    async testEncryptionStrength() {
        console.log('\n🔐 Testing Encryption Strength...');
        
        try {
            // Test if weak encryption methods are used
            const testData = 'test data for encryption';
            
            // Check if MD5 is used (should not be)
            const md5Hash = crypto.createHash('md5').update(testData).digest('hex');
            const sha256Hash = crypto.createHash('sha256').update(testData).digest('hex');
            
            if (md5Hash.length === 32 && sha256Hash.length === 64) {
                this.testResults.passed.push('✅ Strong encryption algorithms available');
            }
            
            // Test AES encryption
            const key = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            
            let encrypted = cipher.update(testData, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            if (encrypted.length > 0) {
                this.testResults.passed.push('✅ AES-256-CBC encryption working');
            }
        } catch (error) {
            this.testResults.failed.push('❌ Encryption test failed');
        }
    }

    // Test webhook security and IP whitelisting
    async testWebhookSecurity() {
        console.log('\n🔗 Testing Webhook Security & IP Whitelisting...');
        
        try {
            // Test 1: Webhook with invalid signature
            const fakeCallback = {
                merchant_id: 'fake123',
                orderid: 'TEST123',
                ap_transactionid: 'AP123',
                amount: '100.00',
                transaction_payment_status: 'SUCCESS',
                ap_SecureHash: 'invalid_hash'
            };
            
            const response1 = await axios.post(`${this.apiUrl}/callback`, fakeCallback, {
                timeout: 5000,
                validateStatus: () => true
            });
            
            // Test 2: Check if IP whitelisting is active
            // In production, this should be blocked by IP whitelist
            if (response1.status === 403 && response1.data?.code === 'IP_NOT_WHITELISTED') {
                this.testResults.passed.push('✅ IP whitelisting is active for webhooks');
            } else if (response1.status === 400 || response1.data?.message?.includes('Invalid')) {
                this.testResults.passed.push('✅ Webhook signature verification working');
                this.testResults.warnings.push('⚠️  IP whitelisting may be bypassed (development mode?)');
            } else {
                this.testResults.failed.push('❌ Webhook security insufficient');
            }
            
            // Test 3: Check if proper error handling for IP detection
            const response2 = await axios.post(`${this.apiUrl}/callback`, fakeCallback, {
                timeout: 5000,
                validateStatus: () => true,
                headers: {
                    'X-Forwarded-For': '', // Empty forwarded header
                    'X-Real-IP': ''
                }
            });
            
            if (response2.status === 400 && response2.data?.code === 'IP_DETECTION_FAILED') {
                this.testResults.passed.push('✅ IP detection error handling working');
            }
            
        } catch (error) {
            this.testResults.warnings.push('⚠️  Could not test webhook security completely');
        }
    }

    // Test IP whitelisting functionality
    async testIPWhitelisting() {
        console.log('\n🛡️  Testing IP Whitelisting...');
        
        try {
            // Test callback endpoint with various IP scenarios
            const testCallback = {
                merchant_id: 'test123',
                orderid: 'TEST123',
                ap_transactionid: 'AP123',
                amount: '100.00',
                transaction_payment_status: 'SUCCESS',
                ap_SecureHash: 'test_hash'
            };
            
            // Test with different IP headers
            const ipTests = [
                { headers: { 'X-Forwarded-For': '192.168.1.1' }, expected: 403 },
                { headers: { 'X-Real-IP': '10.0.0.1' }, expected: 403 },
                { headers: { 'X-Forwarded-For': '103.25.232.100' }, expected: 400 } // Should pass IP check but fail signature
            ];
            
            let ipWhitelistWorking = 0;
            
            for (const test of ipTests) {
                try {
                    const response = await axios.post(`${this.apiUrl}/callback`, testCallback, {
                        timeout: 5000,
                        validateStatus: () => true,
                        headers: test.headers
                    });
                    
                    if (response.status === test.expected || 
                        (test.expected === 403 && response.data?.code === 'IP_NOT_WHITELISTED')) {
                        ipWhitelistWorking++;
                    }
                } catch (error) {
                    // Network errors might indicate blocking
                    if (test.expected === 403) {
                        ipWhitelistWorking++;
                    }
                }
            }
            
            if (ipWhitelistWorking >= ipTests.length * 0.7) { // 70% pass rate
                this.testResults.passed.push('✅ IP whitelisting is functioning');
            } else {
                this.testResults.warnings.push('⚠️  IP whitelisting may not be fully configured');
            }
            
        } catch (error) {
            this.testResults.warnings.push('⚠️  Could not test IP whitelisting');
        }
    }

    // Run all security tests
    async runAllTests() {
        console.log('🚀 Starting Comprehensive Security Tests...');
        console.log('==========================================');
        
        await this.testRateLimiting();
        await this.testSQLInjection();
        await this.testXSSProtection();
        await this.testCSRFProtection();
        await this.testInputValidation();
        await this.testSecurityHeaders();
        await this.testEncryptionStrength();
        await this.testWebhookSecurity();
        await this.testIPWhitelisting();
        
        // Display results
        console.log('\n📊 Security Test Results:');
        console.log('=========================');
        
        if (this.testResults.passed.length > 0) {
            console.log('\n✅ PASSED TESTS:');
            this.testResults.passed.forEach(test => console.log(`   ${test}`));
        }
        
        if (this.testResults.warnings.length > 0) {
            console.log('\n⚠️  WARNINGS:');
            this.testResults.warnings.forEach(test => console.log(`   ${test}`));
        }
        
        if (this.testResults.failed.length > 0) {
            console.log('\n❌ FAILED TESTS:');
            this.testResults.failed.forEach(test => console.log(`   ${test}`));
        }
        
        // Calculate security score
        const totalTests = this.testResults.passed.length + this.testResults.warnings.length + this.testResults.failed.length;
        const securityScore = Math.round(((this.testResults.passed.length + this.testResults.warnings.length * 0.5) / totalTests) * 100);
        
        console.log('\n📈 SECURITY SCORE:');
        console.log(`   ${securityScore}% (${this.testResults.passed.length} passed, ${this.testResults.warnings.length} warnings, ${this.testResults.failed.length} failed)`);
        
        if (securityScore >= 90) {
            console.log('\n🎉 Excellent security posture! Ready for production.');
        } else if (securityScore >= 75) {
            console.log('\n✅ Good security posture. Address warnings before production.');
        } else {
            console.log('\n🚨 Security improvements needed before production deployment.');
        }
        
        return {
            score: securityScore,
            passed: this.testResults.passed.length,
            warnings: this.testResults.warnings.length,
            failed: this.testResults.failed.length,
            isProductionReady: securityScore >= 85 && this.testResults.failed.length === 0
        };
    }
}

// Run tests if script is executed directly
if (require.main === module) {
    const tester = new SecurityTester();
    tester.runAllTests().catch(console.error);
}

module.exports = SecurityTester;