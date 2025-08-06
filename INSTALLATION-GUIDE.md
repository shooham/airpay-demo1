# AirPay Integration Installation Guide

This guide will help you integrate the official AirPay payment gateway into your Node.js payment system.

## Prerequisites

- Node.js 14+ installed
- MongoDB database
- AirPay merchant account with API credentials
- SSL certificate for production (required by AirPay)

## Step 1: Install Dependencies

```bash
npm install axios crypto
```

## Step 2: Environment Configuration

Add the following environment variables to your `.env` file:

```env
# AirPay Configuration (Official API)
AIRPAY_ENVIRONMENT=sandbox
AIRPAY_MERCHANT_ID=your_merchant_id_here
AIRPAY_USERNAME=your_username_here
AIRPAY_PASSWORD=your_password_here
AIRPAY_SECRET_KEY=your_secret_key_here
AIRPAY_CLIENT_ID=your_client_id_here
AIRPAY_CLIENT_SECRET=your_client_secret_here
DOMAIN_URL=https://yourdomain.com
```

## Step 3: Database Setup

Run the database setup script to add AirPay to your PSP list:

```bash
node scripts/addAirPayGateway.js
```

This script will:
- Add AirPay to your PSP list
- Set up the gateway configuration
- Create necessary database indexes

## Step 4: File Integration

### 4.1 Copy Controller
Copy the AirPay controller to your project:
```bash
cp controllers/gateways/airpayController.js /path/to/your/project/controllers/gateways/
```

### 4.2 Copy Routes
Copy the AirPay routes to your project:
```bash
cp routes/gateways/airpayRoutes.js /path/to/your/project/routes/gateways/
```

### 4.3 Copy Models
Copy the callback model to your project:
```bash
cp models/airpayCallbackModel.js /path/to/your/project/models/
```

### 4.4 Update Main App File

Add the AirPay routes to your main app.js file:

```javascript
// Add this line with other route imports
const airpayRoutes = require('./routes/gateways/airpayRoutes');

// Add this line with other route registrations
app.use('/api/v1/gateways/airpay', airpayRoutes);
```

## Step 5: Test the Integration

Run the test script to verify your integration:

```bash
node scripts/testAirPayIntegration.js
```

This will test:
- OAuth2 token generation
- Payment initiation
- Order verification
- VPA validation

## Step 6: Configure Webhooks

1. Log into your AirPay merchant dashboard
2. Navigate to webhook settings
3. Set your webhook URL to: `https://yourdomain.com/api/v1/gateways/airpay/callback`
4. Enable the webhook for payment status updates

## Step 7: API Endpoints

After installation, the following endpoints will be available:

### Health Check
```
GET /api/v1/gateways/airpay/health
```

### Initiate Payment (Simple Transaction)
```
POST /api/v1/gateways/airpay/initiate
Content-Type: application/json

{
  "amount": 100.00,
  "orderId": "ORDER123",
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe",
  "description": "Test Payment",
  "paymentMode": "pg"
}
```

### Seamless Payment
```
POST /api/v1/gateways/airpay/seamless
Content-Type: application/json

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

### Check Payment Status
```
GET /api/v1/gateways/airpay/status/ORDER123
```

### Refund Payment
```
POST /api/v1/gateways/airpay/refund
Content-Type: application/json

{
  "transactionId": "AP123456789",
  "amount": 50.00,
  "reason": "Customer request"
}
```

### Webhook Callback (Automatic)
```
POST /api/v1/gateways/airpay/callback
```

## Step 8: Frontend Integration

### Simple Transaction Flow (Redirect)
```javascript
// Make API call to initiate payment
const response = await fetch('/api/v1/gateways/airpay/initiate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify({
    amount: 100.00,
    orderId: 'ORDER123',
    customerEmail: 'customer@example.com',
    customerPhone: '9999999999',
    customerName: 'John Doe'
  })
});

const data = await response.json();

// Create form and submit to AirPay
const form = document.createElement('form');
form.method = 'POST';
form.action = data.data.payment_url;

Object.keys(data.data.form_data).forEach(key => {
  const input = document.createElement('input');
  input.type = 'hidden';
  input.name = key;
  input.value = data.data.form_data[key];
  form.appendChild(input);
});

document.body.appendChild(form);
form.submit();
```

### Seamless Transaction Flow (API)
```javascript
const response = await fetch('/api/v1/gateways/airpay/seamless', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify({
    orderId: 'ORDER123',
    amount: 100.00,
    customerEmail: 'customer@example.com',
    customerPhone: '9999999999',
    customerName: 'John Doe',
    paymentMode: 'pg',
    cardNumber: '4111111111111111',
    cardCvv: '123',
    expiryMm: '12',
    expiryYy: '25'
  })
});

const result = await response.json();
// Handle payment result
```

## Step 9: Production Deployment

1. **Update Environment**: Change `AIRPAY_ENVIRONMENT=production`
2. **SSL Certificate**: Ensure your domain has a valid SSL certificate
3. **Webhook URL**: Update webhook URL in AirPay dashboard to production URL
4. **Test Thoroughly**: Test all payment flows in production environment
5. **Monitor Logs**: Set up proper logging and monitoring

## Troubleshooting

### Common Issues

1. **OAuth2 Token Generation Fails**
   - Check your credentials in .env file
   - Verify merchant account is active
   - Check network connectivity

2. **Payment Initiation Fails**
   - Verify access token is valid
   - Check encryption/decryption functions
   - Validate request data format

3. **Callback Not Received**
   - Check webhook URL configuration
   - Verify SSL certificate
   - Check firewall settings

4. **Hash Verification Fails**
   - Verify secret key is correct
   - Check hash calculation logic
   - Ensure data integrity

### Debug Mode

Enable debug logging by setting:
```env
DEBUG=airpay:*
```

### Support

For technical support:
1. Check AirPay documentation: [Official Docs]
2. Contact AirPay support team
3. Review integration logs

## Security Considerations

1. **Environment Variables**: Never commit credentials to version control
2. **HTTPS Only**: Always use HTTPS in production
3. **Input Validation**: Validate all input data
4. **Hash Verification**: Always verify callback hashes
5. **Rate Limiting**: Implement rate limiting on API endpoints
6. **Logging**: Log all transactions for audit purposes

## Testing

### Test Cards (Sandbox)
- **Success**: 4111111111111111
- **Failure**: 4000000000000002
- **CVV**: Any 3 digits
- **Expiry**: Any future date

### Test UPI IDs (Sandbox)
- **Success**: success@paytm
- **Failure**: failure@paytm

## Monitoring

Monitor these metrics:
- Payment success rate
- API response times
- Callback processing time
- Error rates
- Transaction volumes

## Compliance

Ensure compliance with:
- PCI DSS requirements
- RBI guidelines
- Data protection laws
- AirPay terms of service

---

**Note**: This integration uses the official AirPay API v4. Make sure to keep your integration updated with the latest API changes.