const express = require('express');
const router = express.Router();
const airpayController = require('../../controllers/gateways/airpayController');
const { protect } = require('../../middleware/authMiddleware');
const { paymentLimiter, statusLimiter, refundLimiter, callbackLimiter } = require('../../middleware/rateLimiter');
const { generateToken, validateToken } = require('../../middleware/csrfProtection');
const { webhookIPWhitelist, conditionalIPWhitelist } = require('../../middleware/ipWhitelist');

/**
 * AirPay Gateway Routes
 * Official AirPay API integration routes
 */

// GET /api/v1/gateways/airpay/health - Health check
router.get('/health', airpayController.healthCheck);

// POST /api/v1/gateways/airpay/initiate - Initiate payment (Simple Transaction)
router.post('/initiate', paymentLimiter, protect, generateToken, validateToken, airpayController.initiatePayment);

// POST /api/v1/gateways/airpay/seamless - Process seamless payment
router.post('/seamless', paymentLimiter, protect, generateToken, validateToken, airpayController.processSeamlessPayment);

// POST /api/v1/gateways/airpay/callback - Handle payment callback/webhook (IP whitelisted)
router.post('/callback', callbackLimiter, webhookIPWhitelist, airpayController.handleCallback);

// GET /api/v1/gateways/airpay/status/:orderId - Check payment status
router.get('/status/:orderId', statusLimiter, protect, airpayController.checkPaymentStatus);

// POST /api/v1/gateways/airpay/refund - Refund payment
router.post('/refund', refundLimiter, protect, generateToken, validateToken, airpayController.refundPayment);

module.exports = router;