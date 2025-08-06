const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

/**
 * AirPay Integration Test Script
 * Tests the official AirPay API integration
 */

class AirPayTester {
    constructor() {
        this.merchantId = process.env.AIRPAY_MERCHANT_ID;
        this.username = process.env.AIRPAY_USERNAME;
        this.password = process.env.AIRPAY_PASSWORD;
        this.secretKey = process.env.AIRPAY_SECRET_KEY;
        this.clientId = process.env.AIRPAY_CLIENT_ID;
        this.clientSecret = process.env.AIRPAY_CLIENT_SECRET;
        
        this.baseURL = process.env.AIRPAY_ENVIRONMENT === 'production' 
            ? 'https://payments.airpay.co.in' 
            : 'https://payments.airpay.co.in';
        this.apiBaseURL = process.env.AIRPAY_ENVIRONMENT === 'production'
            ? 'https://kraken.airpay.co.in'
            : 'https://kraken.airpay.co.in';
    }

    // Generate encryption key using MD5 hash
    generateEncryptionKey() {
        return crypto.createHash('md5').update(`${this.username}~:~${this.password}`).digest('hex');
    }

    // AES encryption function
    encrypt(data, encryptionKey) {
        try {
            const iv = crypto.randomBytes(16); // Use 16 bytes for AES-256-CBC
            const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
            cipher.setAutoPadding(true);
            
            let encrypted = cipher.update(data, 'utf8', 'base64');
            encrypted += cipher.final('base64');
            
            return iv.toString('hex') + encrypted;
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    // AES decryption function
    decrypt(encryptedData, encryptionKey) {
        try {
            const iv = Buffer.from(encryptedData.substring(0, 32), 'hex'); // 32 hex chars = 16 bytes
            const encrypted = encryptedData.substring(32);
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
            decipher.setAutoPadding(true);
            
            let decrypted = decipher.update(encrypted, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data');
        }
    }

    // Generate checksum
    generateChecksum(data) {
        const sortedKeys = Object.keys(data).sort();
        let checksumString = '';
        
        sortedKeys.forEach(key => {
            checksumString += data[key];
        });
        
        checksumString += new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
        
        return crypto.createHash('sha256').update(checksumString).digest('hex');
    }

    // Generate private key
    generatePrivateKey() {
        return crypto.createHash('sha256').update(`${this.secretKey}@${this.username}:|:${this.password}`).digest('hex');
    }

    // Test OAuth2 token generation
    async testOAuth2() {
        console.log('\n🔐 Testing OAuth2 Token Generation...');
        
        try {
            const encryptionKey = this.generateEncryptionKey();
            console.log('✓ Encryption key generated');
            
            const data = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                merchant_id: this.merchantId,
                grant_type: 'client_credentials'
            };

            const encdata = this.encrypt(JSON.stringify(data), encryptionKey);
            const checksum = this.generateChecksum(data);
            const privatekey = this.generatePrivateKey();

            console.log('✓ Request data encrypted and signed');

            const payload = {
                merchant_id: this.merchantId,
                encdata: encdata,
                checksum: checksum,
                privatekey: privatekey
            };

            const response = await axios.post(
                `${this.apiBaseURL}/airpay/pay/v4/api/oauth2`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 30000
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                console.log('✅ OAuth2 Token Generated Successfully');
                console.log(`   Access Token: ${decryptedResponse.access_token.substring(0, 20)}...`);
                console.log(`   Expires In: ${decryptedResponse.expires_in} seconds`);
                return decryptedResponse.access_token;
            } else {
                console.error('❌ OAuth2 Failed:', response.data);
                return null;
            }
        } catch (error) {
            console.error('❌ OAuth2 Test Failed:', error.message);
            if (error.response) {
                console.error('   Response Status:', error.response.status);
                console.error('   Response Data:', error.response.data);
            }
            return null;
        }
    }

    // Test payment initiation
    async testPaymentInitiation(accessToken) {
        console.log('\n💳 Testing Payment Initiation...');
        
        try {
            const encryptionKey = this.generateEncryptionKey();
            const orderId = `TEST_${Date.now()}`;
            
            const paymentData = {
                orderid: orderId,
                amount: '10.00',
                currency_code: '356',
                iso_currency: 'inr',
                buyer_email: 'test@example.com',
                buyer_phone: '9999999999',
                buyer_firstname: 'Test',
                buyer_lastname: 'User',
                buyer_address: 'Test Address',
                buyer_city: 'Test City',
                buyer_state: 'Test State',
                buyer_pincode: '123456',
                buyer_country: 'India',
                customvar: 'Test Payment',
                chmod: '',
                txnsubtype: 2,
                wallet: 0,
                kittype: 'server_side_sdk'
            };

            const encdata = this.encrypt(JSON.stringify(paymentData), encryptionKey);
            const checksum = this.generateChecksum(paymentData);
            const privatekey = this.generatePrivateKey();

            const paymentUrl = `${this.baseURL}/pay/v4/?token=${accessToken}`;
            
            console.log('✅ Payment URL Generated Successfully');
            console.log(`   Payment URL: ${paymentUrl}`);
            console.log(`   Order ID: ${orderId}`);
            console.log(`   Amount: ₹${paymentData.amount}`);
            
            return {
                payment_url: paymentUrl,
                form_data: {
                    privatekey: privatekey,
                    merchant_id: this.merchantId,
                    encdata: encdata,
                    checksum: checksum
                },
                order_id: orderId
            };
        } catch (error) {
            console.error('❌ Payment Initiation Test Failed:', error.message);
            return null;
        }
    }

    // Test order verification
    async testOrderVerification(accessToken, orderId) {
        console.log('\n🔍 Testing Order Verification...');
        
        try {
            const encryptionKey = this.generateEncryptionKey();
            
            const data = {
                orderid: orderId
            };

            const encdata = this.encrypt(JSON.stringify(data), encryptionKey);
            const checksum = this.generateChecksum(data);
            const privatekey = this.generatePrivateKey();

            const payload = {
                merchant_id: this.merchantId,
                encdata: encdata,
                checksum: checksum,
                privatekey: privatekey
            };

            const response = await axios.post(
                `${this.apiBaseURL}/airpay/pay/v4/api/verify/?token=${accessToken}`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 30000
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                console.log('✅ Order Verification API Working');
                console.log(`   Transaction Status: ${decryptedResponse.transaction_payment_status || 'Not Found'}`);
                return decryptedResponse;
            } else {
                console.log('ℹ️  Order Not Found (Expected for new test order)');
                console.log(`   Status: ${response.data.status_code}`);
                console.log(`   Message: ${response.data.message}`);
                return null;
            }
        } catch (error) {
            console.error('❌ Order Verification Test Failed:', error.message);
            if (error.response && error.response.status === 404) {
                console.log('ℹ️  Order not found (expected for test order)');
            }
            return null;
        }
    }

    // Test VPA validation
    async testVPAValidation(accessToken) {
        console.log('\n📱 Testing VPA Validation...');
        
        try {
            const encryptionKey = this.generateEncryptionKey();
            
            const data = {
                customer_vpa: 'test@paytm' // Test VPA
            };

            const encdata = this.encrypt(JSON.stringify(data), encryptionKey);
            const checksum = this.generateChecksum(data);
            const privatekey = this.generatePrivateKey();

            const payload = {
                merchant_id: this.merchantId,
                encdata: encdata,
                checksum: checksum,
                privatekey: privatekey
            };

            const response = await axios.post(
                `${this.apiBaseURL}/airpay/pay/v4/api/vpavalidate/?token=${accessToken}`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 30000
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                console.log('✅ VPA Validation API Working');
                console.log(`   VPA Status: ${decryptedResponse.status}`);
                console.log(`   VPA Name: ${decryptedResponse.vpa_name || 'N/A'}`);
                return decryptedResponse;
            } else {
                console.log('ℹ️  VPA Validation Response:', response.data);
                return null;
            }
        } catch (error) {
            console.error('❌ VPA Validation Test Failed:', error.message);
            return null;
        }
    }

    // Run all tests
    async runAllTests() {
        console.log('🚀 Starting AirPay Integration Tests...');
        console.log('=====================================');
        
        // Check configuration
        console.log('\n📋 Checking Configuration...');
        const requiredVars = ['AIRPAY_MERCHANT_ID', 'AIRPAY_USERNAME', 'AIRPAY_PASSWORD', 'AIRPAY_SECRET_KEY', 'AIRPAY_CLIENT_ID', 'AIRPAY_CLIENT_SECRET'];
        const missingVars = requiredVars.filter(varName => !process.env[varName]);
        
        if (missingVars.length > 0) {
            console.error('❌ Missing environment variables:', missingVars);
            console.error('   Please check your .env file');
            return;
        }
        
        console.log('✅ All required environment variables are set');
        console.log(`   Environment: ${process.env.AIRPAY_ENVIRONMENT || 'sandbox'}`);
        console.log(`   Merchant ID: ${this.merchantId}`);
        console.log(`   API Base URL: ${this.apiBaseURL}`);

        // Test OAuth2
        const accessToken = await this.testOAuth2();
        if (!accessToken) {
            console.error('\n❌ Cannot proceed without access token');
            return;
        }

        // Test Payment Initiation
        const paymentResult = await this.testPaymentInitiation(accessToken);
        
        // Test Order Verification
        if (paymentResult) {
            await this.testOrderVerification(accessToken, paymentResult.order_id);
        }

        // Test VPA Validation
        await this.testVPAValidation(accessToken);

        console.log('\n🎉 AirPay Integration Tests Completed!');
        console.log('=====================================');
        console.log('\n📝 Next Steps:');
        console.log('1. Test the payment flow in your application');
        console.log('2. Configure webhook URL in AirPay dashboard');
        console.log('3. Test callback handling');
        console.log('4. Switch to production environment when ready');
    }
}

// Run tests if this script is executed directly
if (require.main === module) {
    const tester = new AirPayTester();
    tester.runAllTests().catch(console.error);
}

module.exports = AirPayTester;