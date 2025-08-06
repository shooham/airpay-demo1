# Environment Variables for AirPay Integration

Add these variables to your `.env` file:

```env
# AirPay Configuration (Official API)
# Environment: sandbox or production
AIRPAY_ENVIRONMENT=sandbox

# AirPay Merchant Credentials (Required)
AIRPAY_MERCHANT_ID=your_merchant_id_here
AIRPAY_USERNAME=your_username_here
AIRPAY_PASSWORD=your_password_here
AIRPAY_SECRET_KEY=your_secret_key_here

# OAuth2 Credentials (Required)
AIRPAY_CLIENT_ID=your_client_id_here
AIRPAY_CLIENT_SECRET=your_client_secret_here

# Domain URL for payment processing (Required)
DOMAIN_URL=https://yourdomain.com

# Optional: Custom API URLs (use defaults if not specified)
# AIRPAY_PAYMENT_URL=https://payments.airpay.co.in
# AIRPAY_API_URL=https://kraken.airpay.co.in

# Webhook Configuration (if not already present)
WEBHOOK_BASE_URL=https://your-domain.com
```

## How to Get AirPay Credentials:

1. **Sign up** at AirPay merchant dashboard
2. **Complete KYC** verification process
3. **Get credentials** from AirPay dashboard:
   - Merchant ID
   - Username
   - Password
   - Secret Key
   - Client ID
   - Client Secret
4. **Configure webhook URL** in AirPay dashboard:
   - Webhook URL: `https://your-domain.com/api/v1/gateways/airpay/callback`

## Credential Details:

### Required Credentials:
- **AIRPAY_MERCHANT_ID**: Your unique merchant identifier
- **AIRPAY_USERNAME**: API access username
- **AIRPAY_PASSWORD**: API access password
- **AIRPAY_SECRET_KEY**: Secret key for encryption/decryption
- **AIRPAY_CLIENT_ID**: OAuth2 client ID
- **AIRPAY_CLIENT_SECRET**: OAuth2 client secret

### Environment Settings:
- **AIRPAY_ENVIRONMENT**: Set to `sandbox` for testing, `production` for live
- **DOMAIN_URL**: Your domain URL (used in payment processing)

## Security Notes:
- Keep these credentials secure and never commit them to version control
- Use different credentials for development and production environments
- Regularly rotate your API keys for security
- The secret key is used for AES encryption/decryption of API requests
- OAuth2 credentials are used for API authentication

## API Endpoints Used:
- **Payment URL**: `https://payments.airpay.co.in/pay/v4/`
- **API URL**: `https://kraken.airpay.co.in/airpay/pay/v4/api/`
- **OAuth2**: `/oauth2`
- **Simple Transaction**: `/pay/v4/?token=<access_token>`
- **Seamless Transaction**: `/api/seamless/?token=<access_token>`
- **Order Verification**: `/api/verify/?token=<access_token>`
- **Refund**: `/api/refund/?token=<access_token>`