const mongoose = require('mongoose');
require('dotenv').config();

// Note: This script assumes pspListModel exists in your project
// Copy the model from your main project or create it based on the schema provided
let pspListModel;
try {
    pspListModel = require('../../models/pspListModel');
} catch (error) {
    console.error('❌ pspListModel not found. Please ensure the model exists in your project.');
    console.error('   Expected path: ../../models/pspListModel.js');
    console.error('   You can copy it from your main backend project.');
    process.exit(1);
}

/**
 * Script to add AirPay gateway to database
 * Official AirPay API v4 integration
 * Run: node scripts/addAirPayGateway.js
 */

async function addAirPayGateway() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/payment-gateway');
    console.log('✅ Connected to MongoDB');

    // Check if AirPay gateway already exists
    const existingGateway = await pspListModel.findOne({ pspName: 'AirPay' });
    
    if (existingGateway) {
      console.log('⚠️  AirPay gateway already exists, updating configuration...');
      
      // Update existing gateway with new configuration
      await pspListModel.updateOne(
        { pspName: 'AirPay' },
        {
          $set: {
            provider: 'airpay',
            credentials: {
              merchantId: process.env.AIRPAY_MERCHANT_ID || 'your_merchant_id',
              username: process.env.AIRPAY_USERNAME || 'your_username',
              password: process.env.AIRPAY_PASSWORD || 'your_password',
              secretKey: process.env.AIRPAY_SECRET_KEY || 'your_secret_key',
              clientId: process.env.AIRPAY_CLIENT_ID || 'your_client_id',
              clientSecret: process.env.AIRPAY_CLIENT_SECRET || 'your_client_secret',
              environment: process.env.AIRPAY_ENVIRONMENT || 'sandbox',
              additionalConfig: {
                supportedMethods: ['card', 'netbanking', 'upi', 'wallet', 'emi', 'paylater'],
                currency: 'INR',
                country: 'IN',
                paymentUrl: 'https://payments.airpay.co.in',
                apiUrl: 'https://kraken.airpay.co.in',
                webhookUrl: (process.env.WEBHOOK_BASE_URL || process.env.DOMAIN_URL) + '/api/v1/gateways/airpay/callback'
              }
            },
            priority: 1, // High priority for AirPay
            limits: {
              dailyLimit: 10000000, // 1 Crore
              monthlyLimit: 300000000, // 30 Crore
              perTransactionLimit: 1000000 // 10 Lakh
            },
            status: 'Active',
            healthStatus: 'unknown',
            description: 'AirPay Payment Gateway - Official API v4 Integration with Cards, Net Banking, UPI, Wallets, EMI, and Pay Later',
            isActive: true,
            isDeleted: false,
            updatedAt: new Date()
          }
        }
      );
      
      console.log('✅ AirPay gateway configuration updated successfully');
    } else {
      // Create new AirPay gateway entry
      const airpayGateway = new pspListModel({
        handle: '@airpay', // Handle format consistent with other PSPs
        pspName: 'AirPay',
        provider: 'airpay',
        credentials: {
          merchantId: process.env.AIRPAY_MERCHANT_ID || 'your_merchant_id',
          username: process.env.AIRPAY_USERNAME || 'your_username',
          password: process.env.AIRPAY_PASSWORD || 'your_password',
          secretKey: process.env.AIRPAY_SECRET_KEY || 'your_secret_key',
          clientId: process.env.AIRPAY_CLIENT_ID || 'your_client_id',
          clientSecret: process.env.AIRPAY_CLIENT_SECRET || 'your_client_secret',
          environment: process.env.AIRPAY_ENVIRONMENT || 'sandbox',
          additionalConfig: {
            supportedMethods: ['card', 'netbanking', 'upi', 'wallet', 'emi', 'paylater'],
            currency: 'INR',
            country: 'IN',
            paymentUrl: 'https://payments.airpay.co.in',
            apiUrl: 'https://kraken.airpay.co.in',
            webhookUrl: (process.env.WEBHOOK_BASE_URL || process.env.DOMAIN_URL) + '/api/v1/gateways/airpay/callback'
          }
        },
        priority: 1, // High priority for AirPay
        limits: {
          dailyLimit: 10000000, // 1 Crore
          monthlyLimit: 300000000, // 30 Crore
          perTransactionLimit: 1000000 // 10 Lakh
        },
        status: 'Active',
        healthStatus: 'unknown',
        description: 'AirPay Payment Gateway - Official API v4 Integration with Cards, Net Banking, UPI, Wallets, EMI, and Pay Later',
        isActive: true,
        isDeleted: false
      });

      await airpayGateway.save();
      console.log('✅ AirPay gateway added successfully');
    }

    // Display current configuration
    const airpayConfig = await pspListModel.findOne({ pspName: 'AirPay' });
    console.log('\n📋 Current AirPay Configuration:');
    console.log(`   Gateway ID: ${airpayConfig._id}`);
    console.log(`   PSP Name: ${airpayConfig.pspName}`);
    console.log(`   Provider: ${airpayConfig.provider}`);
    console.log(`   Status: ${airpayConfig.status}`);
    console.log(`   Priority: ${airpayConfig.priority}`);
    console.log(`   Environment: ${airpayConfig.credentials.environment}`);
    console.log(`   Merchant ID: ${airpayConfig.credentials.merchantId}`);
    console.log(`   Username: ${airpayConfig.credentials.username}`);
    console.log(`   Supported Methods: ${airpayConfig.credentials.additionalConfig.supportedMethods.join(', ')}`);
    console.log(`   Payment URL: ${airpayConfig.credentials.additionalConfig.paymentUrl}`);
    console.log(`   API URL: ${airpayConfig.credentials.additionalConfig.apiUrl}`);
    console.log(`   Webhook URL: ${airpayConfig.credentials.additionalConfig.webhookUrl}`);
    console.log(`   Daily Limit: ₹${airpayConfig.limits.dailyLimit.toLocaleString()}`);
    console.log(`   Per Transaction Limit: ₹${airpayConfig.limits.perTransactionLimit.toLocaleString()}`);

    // Check for missing credentials
    const requiredCredentials = ['merchantId', 'username', 'password', 'secretKey', 'clientId', 'clientSecret'];
    const missingCredentials = requiredCredentials.filter(cred => 
      !airpayConfig.credentials[cred] || airpayConfig.credentials[cred].startsWith('your_')
    );

    if (missingCredentials.length > 0) {
      console.log('\n⚠️  Warning: Missing or placeholder credentials detected!');
      console.log('   Please update your .env file with actual AirPay credentials:');
      missingCredentials.forEach(cred => {
        const envVar = `AIRPAY_${cred.toUpperCase().replace(/([A-Z])/g, '_$1')}`;
        console.log(`   ${envVar}=your_actual_${cred.toLowerCase()}_here`);
      });
      console.log('\n📖 How to get credentials:');
      console.log('   1. Sign up at AirPay merchant dashboard');
      console.log('   2. Complete KYC verification');
      console.log('   3. Get credentials from dashboard settings');
      console.log('   4. Configure webhook URL in AirPay dashboard');
    } else {
      console.log('\n✅ All required credentials are configured');
      console.log('\n🚀 Next steps:');
      console.log('   1. Test integration: node scripts/testAirPayIntegration.js');
      console.log('   2. Configure webhook URL in AirPay dashboard');
      console.log('   3. Test payment flows in your application');
      console.log('   4. Switch to production when ready');
    }

    // Create indexes for callback model if it exists
    try {
      const AirpayCallback = require('../models/airpayCallbackModel');
      await AirpayCallback.createIndexes();
      console.log('✅ Database indexes created for AirPay callback model');
    } catch (indexError) {
      console.log('ℹ️  Callback model indexes will be created when first used');
    }

    console.log('\n🎉 AirPay gateway setup completed!');

  } catch (error) {
    console.error('❌ Error setting up AirPay gateway:', error);
    
    if (error.name === 'MongooseError' || error.name === 'MongoError') {
      console.error('   Please check your MongoDB connection string in .env file');
      console.error('   MONGODB_URI should be set to your MongoDB connection string');
    }
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
}

// Run the script
if (require.main === module) {
  addAirPayGateway();
}

module.exports = addAirPayGateway;