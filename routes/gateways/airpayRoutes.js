const express = require('express');
const router = express.Router();
const airpayController = require('../../controllers/gateways/airpayController');
const { protect } = require('../../middleware/authMiddleware');

/**
 * AirPay Gateway Routes
 * Official AirPay API integration routes
 */

// GET /api/v1/gateways/airpay/health - Health check
router.get('/health', airpayController.healthCheck);

// POST /api/v1/gateways/airpay/initiate - Initiate payment (Simple Transaction)
router.post('/initiate', protect, airpayController.initiatePayment);

// POST /api/v1/gateways/airpay/seamless - Process seamless payment
router.post('/seamless', protect, airpayController.processSeamlessPayment);

// POST /api/v1/gateways/airpay/callback - Handle payment callback/webhook
router.post('/callback', airpayController.handleCallback);

// GET /api/v1/gateways/airpay/status/:orderId - Check payment status
router.get('/status/:orderId', protect, airpayController.checkPaymentStatus);

// POST /api/v1/gateways/airpay/refund - Refund payment
router.post('/refund', protect, airpayController.refundPayment);

module.exports = router;