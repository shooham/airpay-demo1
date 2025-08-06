# AirPay Gateway API Documentation

This document describes the AirPay payment gateway integration API endpoints and their usage.

## Base URL
```
https://yourdomain.com/api/v1/gateways/airpay
```

## Authentication
All endpoints (except callback) require Bearer token authentication:
```
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### 1. Health Check

Check the health and connectivity of the AirPay integration.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "success",
  "gateway": "AirPay",
  "health": {
    "api_connection": "OK",
    "authentication": "OK",
    "merchant_id": "123456",
    "environment": "sandbox",
    "token_generated": true
  }
}
```

### 2. Initiate Payment (Simple Transaction)

Initiate a payment using AirPay's Simple Transaction flow. This redirects the user to AirPay's payment page.

**Endpoint:** `POST /initiate`

**Request Body:**
```json
{
  "amount": 100.00,
  "orderId": "ORDER_123456",
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe",
  "description": "Product purchase",
  "paymentMode": "pg",
  "transactionSubtype": 2
}
```

**Parameters:**
- `amount` (required): Payment amount in INR
- `orderId` (required): Unique order identifier
- `customerEmail` (required): Customer email address
- `customerPhone` (required): Customer phone number
- `customerName` (required): Customer full name
- `description` (optional): Payment description
- `paymentMode` (optional): Payment mode filter (pg, nb, upi, etc.)
- `transactionSubtype` (optional): Transaction subtype (default: 2)

**Response:**
```json
{
  "status": "success",
  "data": {
    "payment_url": "https://payments.airpay.co.in/pay/v4/?token=abc123",
    "form_data": {
      "privatekey": "hash_value",
      "merchant_id": "123456",
      "encdata": "encrypted_data",
      "checksum": "checksum_value"
    },
    "method": "POST",
    "transaction_id": "64f1a2b3c4d5e6f7g8h9i0j1"
  },
  "message": "Payment initiated successfully"
}
```

**Usage:**
Create a form with the returned form_data and submit it to payment_url to redirect user to AirPay.

### 3. Seamless Payment

Process payment directly through API without redirecting user to AirPay page.

**Endpoint:** `POST /seamless`

**Request Body:**
```json
{
  "orderId": "ORDER_123456",
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

**For UPI Payments:**
```json
{
  "orderId": "ORDER_123456",
  "amount": 100.00,
  "customerEmail": "customer@example.com",
  "customerPhone": "9999999999",
  "customerName": "John Doe",
  "paymentMode": "upi",
  "customerVpa": "customer@paytm"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "transaction_payment_status": "SUCCESS",
    "merchant_id": "123456",
    "orderid": "ORDER_123456",
    "ap_transactionid": "AP123456789",
    "amount": "100.00",
    "currency_code": "356",
    "transaction_status": 200,
    "message": "Success",
    "bank_response_msg": "Success",
    "customer_name": "John Doe",
    "customer_phone": "9999999999",
    "customer_email": "customer@example.com",
    "transaction_type": 320,
    "card_scheme": "visa",
    "bank_name": "HDFC BANK"
  },
  "message": "Seamless payment processed"
}
```

### 4. Check Payment Status

Check the status of a payment using order ID.

**Endpoint:** `GET /status/:orderId`

**Parameters:**
- `orderId`: The order ID to check status for

**Response:**
```json
{
  "status": "success",
  "data": {
    "transaction_payment_status": "SUCCESS",
    "merchant_id": "123456",
    "orderid": "ORDER_123456",
    "ap_transactionid": "AP123456789",
    "amount": "100.00",
    "currency_code": "356",
    "transaction_status": 200,
    "message": "Success",
    "customer_name": "John Doe",
    "customer_phone": "9999999999",
    "customer_email": "customer@example.com",
    "transaction_time": "30-11-2023 12:32:59",
    "bank_name": "HDFC BANK",
    "card_scheme": "visa"
  }
}
```

### 5. Refund Payment

Initiate a refund for a completed payment.

**Endpoint:** `POST /refund`

**Request Body:**
```json
{
  "transactionId": "AP123456789",
  "amount": 50.00,
  "reason": "Customer request"
}
```

**Parameters:**
- `transactionId` (required): AirPay transaction ID (ap_transactionid)
- `amount` (required): Refund amount (can be partial)
- `reason` (optional): Reason for refund

**Response:**
```json
{
  "status": "success",
  "data": {
    "transactions": [
      {
        "ap_transactionid": "AP123456789",
        "amount": "50.00",
        "success": "true",
        "message": "Transaction accepted for refund",
        "refund_id": "RF123456"
      }
    ]
  },
  "message": "Refund initiated successfully"
}
```

### 6. Payment Callback (Webhook)

This endpoint receives payment status updates from AirPay. Configure this URL in your AirPay dashboard.

**Endpoint:** `POST /callback`

**Webhook URL:** `https://yourdomain.com/api/v1/gateways/airpay/callback`

**Request Body (from AirPay):**
```json
{
  "merchant_id": "123456",
  "ap_transactionid": "AP123456789",
  "orderid": "ORDER_123456",
  "amount": "100.00",
  "transaction_payment_status": "SUCCESS",
  "currency_code": "356",
  "transaction_status": 200,
  "message": "Success",
  "customer_name": "John Doe",
  "customer_phone": "9999999999",
  "customer_email": "customer@example.com",
  "transaction_type": 320,
  "chmod": "pg",
  "bank_name": "HDFC BANK",
  "card_scheme": "visa",
  "transaction_time": "30-11-2023 12:32:59",
  "ap_SecureHash": "1490948220"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Callback processed successfully"
}
```

## Payment Status Values

### Transaction Payment Status
- `SUCCESS`: Payment completed successfully
- `FAILED`: Payment failed
- `TRANSACTION IN PROCESS`: Payment is being processed
- `DROPPED`: Transaction was dropped
- `CANCEL`: Payment was cancelled
- `INCOMPLETE`: Payment incomplete
- `BOUNCED`: Payment bounced
- `NO RECORDS`: No records found

### Transaction Status Codes
- `200`: Success
- `400`: Failed
- `401`: Dropped
- `402`: Cancel
- `403`: Incomplete
- `405`: Bounced
- `503`: No Records

### Transaction Types
- `310`: Authorization
- `320`: Sale
- `330`: Capture
- `340`: Refund
- `350`: Chargeback
- `360`: Reversal
- `370`: Sale Complete

## Payment Modes (chmod)

- `pg`: Payment Gateway (Credit/Debit Cards)
- `nb`: Net Banking
- `upi`: UPI
- `ppc`: Prepaid Card
- `cash`: Cash
- `emi`: EMI
- `rtgs`: RTGS
- `btqr`: Bharat QR
- `payltr`: Pay Later
- `va`: Virtual Account
- `enach`: eNACH
- `remit`: Remittance

## Error Handling

All endpoints return errors in the following format:

```json
{
  "status": "error",
  "message": "Error description",
  "error": "Detailed error message"
}
```

### Common Error Codes

- `400`: Bad Request - Invalid input data
- `401`: Unauthorized - Invalid or missing authentication
- `404`: Not Found - Resource not found
- `500`: Internal Server Error - Server-side error

## Security

### Hash Verification
All callbacks from AirPay include an `ap_SecureHash` field that must be verified:

```javascript
// For UPI transactions
const hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${username}:${customer_vpa}`;

// For other transactions
const hashString = `${orderid}:${ap_transactionid}:${amount}:${transaction_status}:${message}:${merchant_id}:${username}`;

const expectedHash = crc32(hashString).toString();
const isValid = expectedHash === ap_SecureHash;
```

### Encryption
All API requests to AirPay are encrypted using AES-256-CBC with PKCS5 padding.

## Rate Limits

- Payment initiation: 100 requests per minute
- Status check: 200 requests per minute
- Refund: 50 requests per minute

## Testing

### Test Environment
Set `AIRPAY_ENVIRONMENT=sandbox` for testing.

### Test Cards
- **Success**: 4111111111111111
- **Failure**: 4000000000000002
- **CVV**: Any 3 digits
- **Expiry**: Any future date

### Test UPI IDs
- **Success**: success@paytm
- **Failure**: failure@paytm

## Webhook Configuration

1. Login to AirPay merchant dashboard
2. Navigate to webhook settings
3. Set webhook URL: `https://yourdomain.com/api/v1/gateways/airpay/callback`
4. Enable payment status notifications
5. Save configuration

## Integration Examples

### Frontend Integration (Simple Transaction)

```javascript
async function initiatePayment() {
  const response = await fetch('/api/v1/gateways/airpay/initiate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({
      amount: 100.00,
      orderId: 'ORDER_' + Date.now(),
      customerEmail: 'customer@example.com',
      customerPhone: '9999999999',
      customerName: 'John Doe'
    })
  });

  const data = await response.json();
  
  if (data.status === 'success') {
    // Create and submit form to redirect to AirPay
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
  }
}
```

### Backend Integration (Node.js)

```javascript
const axios = require('axios');

async function checkPaymentStatus(orderId) {
  try {
    const response = await axios.get(
      `https://yourdomain.com/api/v1/gateways/airpay/status/${orderId}`,
      {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Payment status check failed:', error);
    throw error;
  }
}
```

## Support

For technical support and integration assistance:
1. Check this documentation
2. Review AirPay official documentation
3. Contact AirPay support team
4. Check integration logs for debugging

---

**Note**: This API uses AirPay API v4. Ensure your integration stays updated with the latest API changes.