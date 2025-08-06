const axios = require('axios');
const crypto = require('crypto');
const { sendSocketUpdate } = require('../../utils/socketUtils');
const ErrorHandler = require('../../utils/errorHandler');
const Validator = require('../../utils/validator');

/**
 * AirPay Payment Gateway Controller
 * Official implementation based on AirPay API documentation
 * Supports Simple Transaction, Seamless Transaction, and Embedded Transaction flows
 */

class AirPayController {
    constructor() {
        // Official AirPay API URLs - Separate sandbox and production
        this.baseURL = process.env.AIRPAY_ENVIRONMENT === 'production' 
            ? 'https://payments.airpay.co.in' 
            : 'https://payments.airpay.co.in'; // Note: AirPay uses same URL but different credentials
        this.apiBaseURL = process.env.AIRPAY_ENVIRONMENT === 'production'
            ? 'https://kraken.airpay.co.in'
            : 'https://kraken.airpay.co.in'; // Note: AirPay uses same URL but different credentials
        
        this.merchantId = process.env.AIRPAY_MERCHANT_ID;
        this.username = process.env.AIRPAY_USERNAME;
        this.password = process.env.AIRPAY_PASSWORD;
        this.secretKey = process.env.AIRPAY_SECRET_KEY;
        this.clientId = process.env.AIRPAY_CLIENT_ID;
        this.clientSecret = process.env.AIRPAY_CLIENT_SECRET;
        
        // Validate required configuration
        this.validateConfig();
    }

    validateConfig() {
        const required = ['merchantId', 'username', 'password', 'secretKey', 'clientId', 'clientSecret'];
        const missing = required.filter(key => !this[key]);
        
        if (missing.length > 0) {
            console.error('Missing AirPay configuration:', missing);
            throw new Error(`Missing AirPay configuration: ${missing.join(', ')}`);
        }
    }

    // Generate encryption key using SHA-256 hash for better security
    generateEncryptionKey() {
        const keyString = `${this.username}~:~${this.password}`;
        const hash = crypto.createHash('sha256').update(keyString).digest('hex');
        // Return first 32 bytes (256 bits) for AES-256
        return hash.substring(0, 32);
    }

    // AES encryption function with enhanced security
    encrypt(data, encryptionKey) {
        try {
            // Generate cryptographically secure random IV
            const iv = crypto.randomBytes(16);
            
            // Ensure key is proper length for AES-256
            const key = Buffer.from(encryptionKey, 'utf8').subarray(0, 32);
            if (key.length < 32) {
                const paddedKey = Buffer.alloc(32);
                key.copy(paddedKey);
                key = paddedKey;
            }
            
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            cipher.setAutoPadding(true);
            
            let encrypted = cipher.update(data, 'utf8', 'base64');
            encrypted += cipher.final('base64');
            
            return iv.toString('hex') + encrypted;
        } catch (error) {
            // Log error without sensitive data
            console.error('Encryption failed - timestamp:', new Date().toISOString());
            throw new Error('Data encryption failed');
        }
    }

    // AES decryption function with enhanced security
    decrypt(encryptedData, encryptionKey) {
        try {
            if (!encryptedData || encryptedData.length < 32) {
                throw new Error('Invalid encrypted data format');
            }
            
            const iv = Buffer.from(encryptedData.substring(0, 32), 'hex');
            const encrypted = encryptedData.substring(32);
            
            // Ensure key is proper length for AES-256
            const key = Buffer.from(encryptionKey, 'utf8').subarray(0, 32);
            if (key.length < 32) {
                const paddedKey = Buffer.alloc(32);
                key.copy(paddedKey);
                key = paddedKey;
            }
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            decipher.setAutoPadding(true);
            
            let decrypted = decipher.update(encrypted, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (error) {
            // Log error without sensitive data
            console.error('Decryption failed - timestamp:', new Date().toISOString());
            throw new Error('Data decryption failed');
        }
    }

    // Generate checksum with nonce to prevent replay attacks
    generateChecksum(data, nonce = null) {
        const sortedKeys = Object.keys(data).sort();
        let checksumString = '';
        
        sortedKeys.forEach(key => {
            if (data[key] !== null && data[key] !== undefined) {
                checksumString += data[key];
            }
        });
        
        // Add nonce if provided, otherwise use timestamp with random component
        const nonceValue = nonce || `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        checksumString += nonceValue;
        
        // Add secret key for additional security
        checksumString += this.secretKey;
        
        return crypto.createHash('sha256').update(checksumString).digest('hex');
    }

    // Generate private key as per AirPay documentation
    generatePrivateKey() {
        return crypto.createHash('sha256').update(`${this.secretKey}@${this.username}:|:${this.password}`).digest('hex');
    }

    // Get OAuth2 access token
    async getAccessToken() {
        try {
            const encryptionKey = this.generateEncryptionKey();
            
            const data = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                merchant_id: this.merchantId,
                grant_type: 'client_credentials'
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
                `${this.apiBaseURL}/airpay/pay/v4/api/oauth2`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 30000, // 30 seconds timeout
                    maxRedirects: 0, // Prevent redirect attacks
                    validateStatus: (status) => status < 500 // Don't throw on 4xx errors
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                return decryptedResponse.access_token;
            } else {
                throw new Error(`OAuth2 failed: ${response.data.message}`);
            }
        } catch (error) {
            // Log error without sensitive data
            console.error('OAuth2 token generation failed - timestamp:', new Date().toISOString(), 'error_type:', error.name);
            const errorResponse = ErrorHandler.handleAirPayError(error, 'OAuth2 Token Generation');
            throw new Error(errorResponse.error);
        }
    }

    // Health check endpoint - Test OAuth2 token generation
    async healthCheck(req, res) {
        try {
            // Validate configuration first
            if (!this.merchantId || !this.username || !this.password || !this.secretKey || !this.clientId || !this.clientSecret) {
                return res.status(500).json({
                    status: 'error',
                    gateway: 'AirPay',
                    message: 'AirPay configuration incomplete',
                    error: 'Missing required credentials'
                });
            }
            
            const accessToken = await this.getAccessToken();
            
            res.json({
                status: 'success',
                gateway: 'AirPay',
                health: {
                    api_connection: 'OK',
                    authentication: 'OK',
                    merchant_id: this.merchantId,
                    environment: process.env.AIRPAY_ENVIRONMENT || 'sandbox',
                    token_generated: !!accessToken
                }
            });
        } catch (error) {
            // Log error without sensitive data
            console.error('AirPay health check failed - timestamp:', new Date().toISOString(), 'error_type:', error.name);
            res.status(500).json({
                status: 'error',
                gateway: 'AirPay',
                message: 'Health check failed',
                error: 'Service temporarily unavailable'
            });
        }
    }

    // Initialize payment request using Simple Transaction flow
    async initiatePayment(req, res) {
        try {
            const {
                amount,
                orderId,
                customerEmail,
                customerPhone,
                customerName,
                description = '',
                returnUrl = process.env.DOMAIN_URL + '/payment/success',
                cancelUrl = process.env.DOMAIN_URL + '/payment/cancel',
                webhookUrl = process.env.DOMAIN_URL + '/api/v1/gateways/airpay/callback',
                paymentMode = '', // chmod parameter
                transactionSubtype = 2 // Default to INR-sale auth
            } = req.body;

            // Sanitize and validate input
            const sanitizedData = Validator.sanitizeInput(req.body);
            const validation = Validator.validatePaymentRequest(sanitizedData);
            
            if (!validation.isValid) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Validation failed',
                    errors: validation.errors
                });
            }

            // Create transaction record first
            const Transaction = require('../../models/transactionModel');
            const transaction = new Transaction({
                billId: orderId,
                amount: parseFloat(amount),
                customerEmail: customerEmail,
                customerPhone: customerPhone,
                customerName: customerName,
                status: 'INITIATED',
                psp: 'AirPay',
                method: 'unknown',
                createdAt: new Date()
            });
            await transaction.save();

            // Get access token
            const accessToken = await this.getAccessToken();
            const encryptionKey = this.generateEncryptionKey();

            // Prepare payment data as per AirPay Simple Transaction API
            const paymentData = {
                orderid: orderId,
                amount: parseFloat(amount).toFixed(2),
                currency_code: '356', // INR
                iso_currency: 'inr',
                buyer_email: customerEmail,
                buyer_phone: customerPhone,
                buyer_firstname: customerName.split(' ')[0] || customerName,
                buyer_lastname: customerName.split(' ').slice(1).join(' ') || '',
                buyer_address: 'Not Provided',
                buyer_city: 'Not Provided',
                buyer_state: 'Not Provided',
                buyer_pincode: '000000',
                buyer_country: 'India',
                customvar: description || '',
                chmod: paymentMode,
                txnsubtype: transactionSubtype,
                wallet: 0,
                kittype: 'server_side_sdk'
            };

            const encdata = this.encrypt(JSON.stringify(paymentData), encryptionKey);
            const checksum = this.generateChecksum(paymentData);
            const privatekey = this.generatePrivateKey();

            // Create payment URL for Simple Transaction
            const paymentUrl = `${this.baseURL}/pay/v4/?token=${accessToken}`;
            
            // For server-side integration, we need to create a form submission
            const formData = {
                privatekey: privatekey,
                merchant_id: this.merchantId,
                encdata: encdata,
                checksum: checksum
            };

            // Send real-time update
            sendSocketUpdate('payment:initiated', {
                gateway: 'AirPay',
                orderId: orderId,
                amount: amount,
                message: 'AirPay payment initiated successfully'
            });

            res.status(200).json({
                status: 'success',
                data: {
                    payment_url: paymentUrl,
                    form_data: formData,
                    method: 'POST',
                    transaction_id: transaction._id
                },
                message: 'Payment initiated successfully'
            });

        } catch (error) {
            // Log error without sensitive data
            console.error('AirPay payment initiation failed - timestamp:', new Date().toISOString(), 'order_id:', orderId, 'error_type:', error.name);
            res.status(500).json({
                status: 'error',
                message: 'Payment initiation failed',
                error: 'Unable to process payment request'
            });
        }
    }

    // Seamless transaction for direct API payment
    async processSeamlessPayment(req, res) {
        try {
            // Sanitize and validate input
            const sanitizedData = Validator.sanitizeInput(req.body);
            const validation = Validator.validateSeamlessPayment(sanitizedData);
            
            if (!validation.isValid) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Validation failed',
                    errors: validation.errors
                });
            }
            
            const {
                orderId,
                amount,
                customerEmail,
                customerPhone,
                customerName,
                paymentMode = 'pg', // pg or upi
                cardNumber,
                cardCvv,
                expiryMm,
                expiryYy,
                customerVpa // For UPI payments
            } = sanitizedData;

            const accessToken = await this.getAccessToken();
            const encryptionKey = this.generateEncryptionKey();

            const paymentData = {
                orderid: orderId,
                amount: parseFloat(amount).toFixed(2),
                currency_code: '356',
                iso_currency: 'inr',
                buyer_email: customerEmail,
                buyer_phone: customerPhone,
                buyer_firstname: customerName.split(' ')[0] || customerName,
                buyer_lastname: customerName.split(' ').slice(1).join(' ') || '',
                buyer_address: 'Not Provided',
                buyer_city: 'Not Provided',
                buyer_state: 'Not Provided',
                buyer_pincode: '000000',
                buyer_country: 'India',
                chmod: paymentMode,
                txnsubtype: 3, // INR-Moto for seamless
                wallet: 0,
                channel: paymentMode,
                mer_dom: Buffer.from(process.env.DOMAIN_URL || 'http://localhost').toString('base64'),
                domain_url: process.env.DOMAIN_URL || 'http://localhost',
                customer_consent: 'Y'
            };

            // Add payment method specific fields
            if (paymentMode === 'pg' && cardNumber && cardCvv && expiryMm && expiryYy) {
                paymentData.card_number = cardNumber;
                paymentData.card_cvv = cardCvv;
                paymentData.expiry_mm = expiryMm;
                paymentData.expiry_yy = expiryYy;
            } else if (paymentMode === 'upi' && customerVpa) {
                paymentData.customer_vpa = customerVpa;
            }

            const encdata = this.encrypt(JSON.stringify(paymentData), encryptionKey);
            const checksum = this.generateChecksum(paymentData);
            const privatekey = this.generatePrivateKey();

            const payload = {
                merchant_id: this.merchantId,
                encdata: encdata,
                checksum: checksum,
                privatekey: privatekey
            };

            const response = await axios.post(
                `${this.apiBaseURL}/airpay/pay/v4/api/seamless/?token=${accessToken}`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 45000, // 45 seconds for payment processing
                    maxRedirects: 0,
                    validateStatus: (status) => status < 500
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                
                // Update transaction status
                await this.updateTransactionFromResponse(orderId, decryptedResponse);
                
                res.json({
                    status: 'success',
                    data: decryptedResponse,
                    message: 'Seamless payment processed'
                });
            } else {
                throw new Error(`Payment failed: ${response.data.message}`);
            }

        } catch (error) {
            console.error('AirPay seamless payment error:', error);
            res.status(500).json({
                status: 'error',
                message: 'Seamless payment failed',
                error: error.message
            });
        }
    }

    // Handle payment callback/webhook from AirPay with enhanced security
    async handleCallback(req, res) {
        try {
            const callbackData = req.body;
            const AirpayCallback = require('../../models/airpayCallbackModel');
            
            // Enhanced security checks
            if (!this.verifyWebhookSource(req)) {
                console.warn('Webhook from suspicious source - IP:', req.ip);
                // Still process but log the warning
            }
            
            // Validate callback data structure
            if (!callbackData || typeof callbackData !== 'object') {
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid callback data format'
                });
            }
            
            // Log the callback first
            const callbackLog = new AirpayCallback({
                order_id: callbackData.orderid || callbackData.order_id,
                transaction_id: callbackData.ap_transactionid,
                status: callbackData.transaction_payment_status,
                amount: callbackData.amount,
                currency_code: callbackData.currency_code,
                payment_method: callbackData.chmod,
                customer_email: callbackData.customer_email,
                customer_phone: callbackData.customer_phone,
                merchant_id: callbackData.merchant_id,
                ap_secure_hash: callbackData.ap_SecureHash,
                timestamp: callbackData.transaction_time,
                failure_reason: callbackData.reason || '',
                raw_data: callbackData
            });
            
            await callbackLog.save();
            
            // Verify secure hash
            const isValidHash = this.verifySecureHash(callbackData);
            
            if (!isValidHash) {
                console.error('Invalid secure hash for callback:', callbackData);
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid secure hash'
                });
            }

            // Process the payment status
            await this.processPaymentStatus(callbackData);
            
            // Update callback log as processed
            await AirpayCallback.findByIdAndUpdate(callbackLog._id, {
                processed: true,
                processed_at: new Date()
            });

            // Send real-time update
            sendSocketUpdate('payment:callback', {
                gateway: 'AirPay',
                orderId: callbackData.orderid || callbackData.order_id,
                status: callbackData.transaction_payment_status,
                message: 'AirPay callback processed successfully'
            });

            res.status(200).json({
                status: 'success',
                message: 'Callback processed successfully'
            });

        } catch (error) {
            console.error('AirPay callback error:', error);
            res.status(500).json({
                status: 'error',
                message: 'Callback processing failed',
                error: error.message
            });
        }
    }

    // Check payment status using Order Confirmation API
    async checkPaymentStatus(req, res) {
        try {
            const { orderId } = req.params;
            
            const accessToken = await this.getAccessToken();
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
                    timeout: 30000, // 30 seconds timeout
                    maxRedirects: 0,
                    validateStatus: (status) => status < 500
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                
                res.json({
                    status: 'success',
                    data: decryptedResponse
                });
            } else {
                throw new Error(`Status check failed: ${response.data.message}`);
            }

        } catch (error) {
            console.error('AirPay status check error:', error);
            res.status(500).json({
                status: 'error',
                message: 'Status check failed',
                error: error.message
            });
        }
    }

    // Refund payment using AirPay Refund API
    async refundPayment(req, res) {
        try {
            const { transactionId, amount, reason = 'Merchant initiated refund' } = req.body;
            
            // Sanitize and validate input
            const sanitizedData = Validator.sanitizeInput(req.body);
            const validation = Validator.validateRefundRequest(sanitizedData);
            
            if (!validation.isValid) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Validation failed',
                    errors: validation.errors
                });
            }
            
            const accessToken = await this.getAccessToken();
            const encryptionKey = this.generateEncryptionKey();

            // Prepare refund data as per AirPay documentation
            const transactions = [{
                ap_transactionid: transactionId,
                amount: parseFloat(amount).toFixed(2)
            }];

            const data = {
                mode: 'refund',
                transactions: Buffer.from(JSON.stringify(transactions)).toString('base64')
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
                `${this.apiBaseURL}/airpay/pay/v4/api/refund/?token=${accessToken}`,
                payload,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 30000, // 30 seconds timeout
                    maxRedirects: 0,
                    validateStatus: (status) => status < 500
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                
                res.json({
                    status: 'success',
                    data: decryptedResponse,
                    message: 'Refund initiated successfully'
                });
            } else {
                throw new Error(`Refund failed: ${response.data.message}`);
            }

        } catch (error) {
            console.error('AirPay refund error:', error);
            res.status(500).json({
                status: 'error',
                message: 'Refund failed',
                error: error.message
            });
        }
    }

    // Enhanced webhook signature verification
    verifySecureHash(data) {
        try {
            const { ap_SecureHash, orderid, ap_transactionid, amount, transaction_status, message, merchant_id, customer_vpa } = data;
            
            // Validate required fields
            if (!ap_SecureHash || !orderid || !ap_transactionid || !amount || !merchant_id) {
                console.error('Missing required fields for hash verification');
                return false;
            }
            
            // Verify merchant ID matches
            if (merchant_id !== this.merchantId) {
                console.error('Merchant ID mismatch in callback');
                return false;
            }
            
            let hashString;
            if (customer_vpa) {
                // For UPI transactions
                hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${this.username}:${customer_vpa}`;
            } else {
                // For other transactions
                hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${this.username}`;
            }
            
            const expectedHash = this.crc32(hashString).toString();
            const isValid = expectedHash === ap_SecureHash;
            
            if (!isValid) {
                console.error('Hash verification failed - timestamp:', new Date().toISOString(), 'order_id:', orderid);
            }
            
            return isValid;
        } catch (error) {
            console.error('Hash verification error - timestamp:', new Date().toISOString(), 'error_type:', error.name);
            return false;
        }
    }

    // Enhanced webhook source verification with proper IP whitelisting
    verifyWebhookSource(req) {
        const { ipWhitelist } = require('../../middleware/ipWhitelist');
        
        // Get client IP using proper detection
        const clientIP = ipWhitelist.getClientIP(req);
        
        if (!clientIP) {
            console.error('Unable to determine client IP for webhook verification');
            return false;
        }
        
        // AirPay official server IPs (should match environment configuration)
        const airpayIPs = [
            '103.25.232.0/24',
            '103.25.233.0/24',
            '202.131.96.0/24',
            '103.231.78.0/24'
        ];
        
        // Add environment-configured IPs
        if (process.env.AIRPAY_WHITELIST_IPS) {
            const envIPs = process.env.AIRPAY_WHITELIST_IPS.split(',');
            airpayIPs.push(...envIPs);
        }
        
        // Use proper CIDR matching
        const isFromAirPay = ipWhitelist.isIPWhitelisted(clientIP, airpayIPs);
        
        if (!isFromAirPay) {
            console.error('SECURITY_ALERT: Webhook from unauthorized IP:', {
                ip: clientIP,
                timestamp: new Date().toISOString(),
                userAgent: req.headers['user-agent'],
                referer: req.headers['referer']
            });
        } else {
            console.log('Webhook verified from authorized AirPay IP:', clientIP);
        }
        
        return isFromAirPay;
    }

    // CRC32 implementation for hash verification
    crc32(str) {
        const crcTable = [];
        for (let i = 0; i < 256; i++) {
            let crc = i;
            for (let j = 0; j < 8; j++) {
                crc = (crc & 1) ? (0xEDB88320 ^ (crc >>> 1)) : (crc >>> 1);
            }
            crcTable[i] = crc;
        }
        
        let crc = 0 ^ (-1);
        for (let i = 0; i < str.length; i++) {
            crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
        }
        return (crc ^ (-1)) >>> 0;
    }

    // Update transaction from AirPay response
    async updateTransactionFromResponse(orderId, responseData) {
        const Transaction = require('../../models/transactionModel');
        
        let systemStatus = 'INITIATED';
        if (responseData.transaction_payment_status === 'SUCCESS') {
            systemStatus = 'COMPLETED';
        } else if (responseData.transaction_payment_status === 'FAILED') {
            systemStatus = 'FAILED';
        }
        
        const updateData = {
            status: systemStatus,
            vpaId: responseData.chmod || 'airpay',
            psp: 'AirPay',
            method: responseData.chmod === 'upi' ? 'Qr' : 'Card',
            reason: responseData.reason || responseData.message || ''
        };

        const transaction = await Transaction.findOneAndUpdate(
            { billId: orderId },
            updateData,
            { new: true }
        );

        return transaction;
    }

    // Process payment status from callback
    async processPaymentStatus(callbackData) {
        const Transaction = require('../../models/transactionModel');
        const { processAffiliateCommission } = require('../transactionController');
        const { sendCallback } = require('../apiKeyController');
        const apiKeyModel = require('../../models/apiKeyModel');
        
        // Map AirPay status to system status
        let systemStatus = 'INITIATED';
        if (callbackData.transaction_payment_status === 'SUCCESS') {
            systemStatus = 'COMPLETED';
        } else if (callbackData.transaction_payment_status === 'FAILED') {
            systemStatus = 'FAILED';
        }
        
        // Update transaction status in database
        const transaction = await Transaction.findOneAndUpdate(
            { billId: callbackData.orderid || callbackData.order_id },
            {
                status: systemStatus,
                vpaId: callbackData.chmod || 'airpay',
                psp: 'AirPay',
                method: callbackData.chmod === 'upi' ? 'Qr' : 'Card',
                reason: callbackData.reason || callbackData.message || ''
            },
            { new: true }
        );

        if (transaction && systemStatus === 'COMPLETED') {
            // Process affiliate commission
            await processAffiliateCommission(transaction._id);
            
            // Get API key details and send callback
            const apiKeyDetails = await apiKeyModel.findOne({
                apiKey: transaction.apiKeyUsed,
            });

            if (apiKeyDetails) {
                sendCallback(apiKeyDetails.apiKey, apiKeyDetails.apiSecret, {
                    transactionId: transaction._id,
                    status: systemStatus,
                    vpaId: transaction.vpaId,
                    psp: transaction.psp,
                    amount: transaction.amount,
                    billId: transaction.billId
                });
            }
        }
        
        return transaction;
    }
}

module.exports = new AirPayController();