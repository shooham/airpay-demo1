# 🚀 AirPay Integration Guide

## Quick Integration Steps

### 1. Copy Files to Your Backend

```bash
# Copy the essential files to your existing backend
cp -r send-to-customer/controllers/gateways/ your-backend/controllers/
cp -r send-to-customer/middleware/ your-backend/
cp -r send-to-customer/utils/ your-backend/
cp -r send-to-customer/models/ your-backend/
cp send-to-customer/routes/gateways/airpayRoutes.js your-backend/routes/gateways/
```

### 2. Update Dependencies

Add to your existing `package.json`:
```json
{
  "dependencies": {
    "jsonwebtoken": "^9.0.2"
  }
}
```

Run: `npm install`

### 3. Environment Variables

Add to your `.env` file:
```bash
# AirPay Official API v4 Credentials
AIRPAY_ENVIRONMENT=sandbox
AIRPAY_MERCHANT_ID=your_merchant_id
AIRPAY_USERNAME=your_username
AIRPAY_PASSWORD=your_password
AIRPAY_SECRET_KEY=your_secret_key
AIRPAY_CLIENT_ID=your_client_id
AIRPAY_CLIENT_SECRET=your_client_secret

# Security
JWT_SECRET=your_64_character_random_secret_key_here
WEBHOOK_SECRET=your_webhook_secret_key_here

# IP Whitelisting (AirPay server IPs)
AIRPAY_WHITELIST_IPS=103.25.232.0/24,103.25.233.0/24,202.131.96.0/24
BYPASS_IP_WHITELIST=false
```

### 4. Update Your Routes

In your main `app.js`, replace the existing AirPay route:
```javascript
// Replace this line:
app.use("/api/v1/gateways/airpay", airpayRoutes);

// With enhanced version:
const airpayRoutes = require('./routes/gateways/airpayRoutes');
app.use("/api/v1/gateways/airpay", airpayRoutes);
```

### 5. Test the Integration

```bash
# Test AirPay connection
node scripts/testAirPayIntegration.js

# Test security features
node scripts/securityTest.js
```

## API Endpoints

### Initiate Payment
```bash
POST /api/v1/gateways/airpay/initiate
Authorization: Bearer <your_jwt_token>
Content-Type: application/json

{
  "amount": 100.00,
  "orderId": "ORDER123",
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe"
}
```

### Check Status
```bash
GET /api/v1/gateways/airpay/status/ORDER123
Authorization: Bearer <your_jwt_token>
```

### Webhook Callback
```bash
POST /api/v1/gateways/airpay/callback
# Automatically handles AirPay callbacks with IP whitelisting
```

## Security Features

- ✅ **IP Whitelisting**: Only AirPay servers can send callbacks
- ✅ **Rate Limiting**: Prevents abuse and DDoS attacks  
- ✅ **Input Validation**: Protects against XSS and SQL injection
- ✅ **CSRF Protection**: Prevents cross-site request forgery
- ✅ **AES-256 Encryption**: Secure data transmission
- ✅ **JWT Authentication**: Secure API access

## Health Check

```bash
GET /health
# Returns system health status
```

That's it! Your AirPay integration is now production-ready with enterprise-grade security.