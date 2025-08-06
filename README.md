# AirPay Payment Gateway Integration

Official AirPay payment gateway integration for Node.js applications. This integration provides a complete, production-ready implementation of the AirPay API v4.

## 🚀 Features

- **Complete API Coverage**: Supports all AirPay API v4 endpoints
- **Multiple Payment Flows**: Simple Transaction, Seamless Transaction, and Embedded Transaction
- **Secure Implementation**: AES-256-CBC encryption, hash verification, and OAuth2 authentication
- **Production Ready**: Comprehensive error handling, logging, and monitoring
- **Real-time Updates**: WebSocket integration for payment status updates
- **Comprehensive Testing**: Full test suite with sandbox environment support

## 📋 Prerequisites

- Node.js 14+ 
- MongoDB database
- AirPay merchant account with API credentials
- SSL certificate (required for production)

## 🛠️ Installation

### Step 1: Quick Setup

```bash
# Install dependencies (crypto is built-in)
npm install axios mongoose express dotenv

# Run database setup
node scripts/addAirPayGateway.js

# Test integration
node scripts/testAirPayIntegration.js
```

### Step 2: Environment Configuration

Create/update your `.env` file:

```env
# AirPay Configuration
AIRPAY_ENVIRONMENT=sandbox
AIRPAY_MERCHANT_ID=your_merchant_id_here
AIRPAY_USERNAME=your_username_here
AIRPAY_PASSWORD=your_password_here
AIRPAY_SECRET_KEY=your_secret_key_here
AIRPAY_CLIENT_ID=your_client_id_here
AIRPAY_CLIENT_SECRET=your_client_secret_here
DOMAIN_URL=https://yourdomain.com
```

### Step 3: Integration

Add to your main app.js:

```javascript
const airpayRoutes = require('./routes/gateways/airpayRoutes');
app.use('/api/v1/gateways/airpay', airpayRoutes);
```

## 🔧 API Endpoints

### Health Check
```http
GET /api/v1/gateways/airpay/health
```

### Payment Initiation
```http
POST /api/v1/gateways/airpay/initiate
Content-Type: application/json
Authorization: Bearer <token>

{
  "amount": 100.00,
  "orderId": "ORDER123",
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe"
}
```

### Seamless Payment
```http
POST /api/v1/gateways/airpay/seamless
Content-Type: application/json
Authorization: Bearer <token>

{
  "orderId": "ORDER123",
  "amount": 100.00,
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe",
  "paymentMode": "pg",
  "cardNumber": "4111111111111111",
  "cardCvv": "123",
  "expiryMm": "12",
  "expiryYy": "25"
}
```

### Payment Status
```http
GET /api/v1/gateways/airpay/status/ORDER123
Authorization: Bearer <token>
```

### Refund
```http
POST /api/v1/gateways/airpay/refund
Content-Type: application/json
Authorization: Bearer <token>

{
  "transactionId": "AP123456789",
  "amount": 50.00,
  "reason": "Customer request"
}
```

## 🔐 Security Features

- **AES-256-CBC Encryption**: All API requests are encrypted
- **Hash Verification**: Callback data integrity verification
- **OAuth2 Authentication**: Secure API access token management
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: Built-in API rate limiting protection

## 🧪 Testing

### Run Integration Tests
```bash
node scripts/testAirPayIntegration.js
```

### Test Cards (Sandbox)
- **Success**: 4111111111111111
- **Failure**: 4000000000000002
- **CVV**: Any 3 digits
- **Expiry**: Any future date

### Test UPI IDs (Sandbox)
- **Success**: success@paytm
- **Failure**: failure@paytm

## 📱 Payment Flows

### 1. Simple Transaction (Redirect)
User is redirected to AirPay's hosted payment page:

```javascript
// Frontend integration
const response = await fetch('/api/v1/gateways/airpay/initiate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify(paymentData)
});

const data = await response.json();
// Redirect user to data.data.payment_url with form_data
```

### 2. Seamless Transaction (API)
Payment processed directly through API:

```javascript
const response = await fetch('/api/v1/gateways/airpay/seamless', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify(paymentData)
});

const result = await response.json();
// Handle payment result directly
```

### 3. Webhook Handling
Automatic payment status updates:

```javascript
// Webhook endpoint: /api/v1/gateways/airpay/callback
// Automatically processes payment status updates from AirPay
```

## 🔄 Payment Status Flow

```
INITIATED → TRANSACTION IN PROCESS → SUCCESS/FAILED
                                  ↓
                              COMPLETED/FAILED
```

## 📊 Monitoring & Analytics

- Real-time payment status updates via WebSocket
- Comprehensive transaction logging
- Payment success/failure analytics
- Error tracking and alerting

## 🌐 Production Deployment

### 1. Environment Setup
```env
AIRPAY_ENVIRONMENT=production
```

### 2. SSL Certificate
Ensure your domain has a valid SSL certificate.

### 3. Webhook Configuration
Configure webhook URL in AirPay dashboard:
```
https://yourdomain.com/api/v1/gateways/airpay/callback
```

### 4. Monitoring
Set up monitoring for:
- Payment success rates
- API response times
- Error rates
- Transaction volumes

## 🛡️ Compliance

This integration ensures compliance with:
- PCI DSS requirements
- RBI guidelines
- Data protection laws
- AirPay terms of service

## 📚 Documentation

- [Installation Guide](INSTALLATION-GUIDE.md) - Detailed setup instructions
- [API Documentation](API-DOCUMENTATION.md) - Complete API reference
- [Configuration Guide](config-changes/) - Configuration details

## 🔧 Configuration Files

- `controllers/gateways/airpayController.js` - Main controller
- `routes/gateways/airpayRoutes.js` - API routes
- `models/airpayCallbackModel.js` - Callback data model
- `scripts/addAirPayGateway.js` - Database setup
- `scripts/testAirPayIntegration.js` - Integration tests

## 🚨 Troubleshooting

### Common Issues

1. **OAuth2 Token Generation Fails**
   ```bash
   # Check credentials
   node scripts/testAirPayIntegration.js
   ```

2. **Payment Initiation Fails**
   ```bash
   # Verify environment variables
   echo $AIRPAY_MERCHANT_ID
   ```

3. **Callback Not Received**
   - Check webhook URL configuration
   - Verify SSL certificate
   - Check firewall settings

### Debug Mode
```env
DEBUG=airpay:*
```

## 📈 Performance

- **OAuth2 Token Caching**: Automatic token refresh
- **Connection Pooling**: Optimized HTTP connections
- **Error Retry Logic**: Automatic retry for transient failures
- **Rate Limiting**: Built-in protection against API abuse

## 🤝 Support

For technical support:
1. Check the documentation
2. Review integration logs
3. Run test scripts
4. Contact AirPay support team

## 📄 License

This integration is provided as-is for AirPay merchant integration purposes.

## 🔄 Updates

This integration uses AirPay API v4. Keep your integration updated with the latest API changes.

---

**✅ Production Ready**: This is a complete, tested, and production-ready AirPay integration that follows all official AirPay API specifications and security requirements.