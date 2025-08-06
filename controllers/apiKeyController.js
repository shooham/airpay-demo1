/**
 * API Key Controller for Webhook Management
 * Handles API key operations and webhook callbacks
 */

const crypto = require('crypto');
const axios = require('axios');

class APIKeyController {
    constructor() {
        this.webhookEndpoints = new Map();
        this.loadWebhookEndpoints();
    }

    // Load webhook endpoints from environment
    loadWebhookEndpoints() {
        if (process.env.WEBHOOK_ENDPOINTS) {
            const endpoints = process.env.WEBHOOK_ENDPOINTS.split(',');
            endpoints.forEach(endpoint => {
                const [name, url] = endpoint.split('=');
                if (name && url) {
                    this.webhookEndpoints.set(name.trim(), url.trim());
                }
            });
        }
        
        // Default webhook endpoint
        if (process.env.MERCHANT_WEBHOOK_URL) {
            this.webhookEndpoints.set('merchant', process.env.MERCHANT_WEBHOOK_URL);
        }
    }

    // Send webhook callback to merchant
    async sendCallback(transaction, eventType = 'payment_update') {
        try {
            const webhookUrl = this.webhookEndpoints.get('merchant');
            
            if (!webhookUrl) {
                console.warn('No webhook URL configured for merchant callbacks');
                return { success: false, error: 'No webhook URL configured' };
            }
            
            // Prepare webhook payload
            const payload = {
                event: eventType,
                timestamp: new Date().toISOString(),
                data: {
                    order_id: transaction.billId,
                    transaction_id: transaction.ap_transactionid,
                    amount: transaction.amount,
                    currency: transaction.currency,
                    status: transaction.status,
                    payment_method: transaction.method,
                    customer_email: transaction.customerEmail,
                    customer_phone: transaction.customerPhone,
                    created_at: transaction.createdAt,
                    completed_at: transaction.completed_at,
                    failure_reason: transaction.failure_reason
                }
            };
            
            // Generate webhook signature
            const signature = this.generateWebhookSignature(payload);
            
            // Send webhook
            const response = await axios.post(webhookUrl, payload, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Webhook-Signature': signature,
                    'X-Webhook-Event': eventType,
                    'User-Agent': 'AirPay-Gateway-Webhook/1.0'
                },
                timeout: 30000,
                maxRedirects: 0
            });
            
            console.log(`Webhook sent successfully: ${eventType} - ${transaction.billId}`);
            
            return {
                success: true,
                status: response.status,
                response: response.data
            };
        } catch (error) {
            console.error('Webhook delivery failed:', {
                error: error.message,
                transaction: transaction.billId,
                event: eventType
            });
            
            return {
                success: false,
                error: error.message,
                status: error.response?.status
            };
        }
    }

    // Generate webhook signature
    generateWebhookSignature(payload) {
        const secret = process.env.WEBHOOK_SECRET || 'default_webhook_secret';
        const payloadString = JSON.stringify(payload);
        
        return crypto
            .createHmac('sha256', secret)
            .update(payloadString)
            .digest('hex');
    }

    // Verify webhook signature
    verifyWebhookSignature(payload, signature) {
        const expectedSignature = this.generateWebhookSignature(payload);
        return crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    }
}

module.exports = new APIKeyController();