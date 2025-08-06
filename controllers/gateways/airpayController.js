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
        // Official AirPay API URLs
        this.baseURL = process.env.AIRPAY_ENVIRONMENT === 'production' 
            ? 'https://payments.airpay.co.in' 
            : 'https://payments.airpay.co.in';
        this.apiBaseURL = process.env.AIRPAY_ENVIRONMENT === 'production'
            ? 'https://kraken.airpay.co.in'
            : 'https://kraken.airpay.co.in';
        
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

    // Generate encryption key using MD5 hash as per AirPay documentation
    generateEncryptionKey() {
        return crypto.createHash('md5').update(`${this.username}~:~${this.password}`).digest('hex');
    }

    // AES encryption function as per AirPay documentation
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

    // AES decryption function as per AirPay documentation
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

    // Generate checksum as per AirPay documentation
    generateChecksum(data) {
        const sortedKeys = Object.keys(data).sort();
        let checksumString = '';
        
        sortedKeys.forEach(key => {
            checksumString += data[key];
        });
        
        checksumString += new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
        
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
                    }
                }
            );

            if (response.data.status_code === '200') {
                const decryptedResponse = this.decrypt(response.data.response, encryptionKey);
                return decryptedResponse.access_token;
            } else {
                throw new Error(`OAuth2 failed: ${response.data.message}`);
            }
        } catch (error) {
            console.error('OAuth2 token generation failed:', error);
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
            console.error('AirPay health check failed:', error);
            res.status(500).json({
                status: 'error',
                gateway: 'AirPay',
                message: 'Health check failed',
                error: error.message
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
            console.error('AirPay payment initiation error:', error);
            res.status(500).json({
                status: 'error',
                message: 'Payment initiation failed',
                error: error.message
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
                    }
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

    // Handle payment callback/webhook from AirPay
    async handleCallback(req, res) {
        try {
            const callbackData = req.body;
            const AirpayCallback = require('../../models/airpayCallbackModel');
            
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
                    }
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
                    }
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

    // Verify AirPay secure hash
    verifySecureHash(data) {
        try {
            const { ap_SecureHash, orderid, ap_transactionid, amount, transaction_status, message, merchant_id, customer_vpa } = data;
            
            let hashString;
            if (customer_vpa) {
                // For UPI transactions
                hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${this.username}:${customer_vpa}`;
            } else {
                // For other transactions
                hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${this.username}`;
            }
            
            const expectedHash = this.crc32(hashString).toString();
            return expectedHash === ap_SecureHash;
        } catch (error) {
            console.error('Hash verification error:', error);
            return false;
        }
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