const mongoose = require('mongoose');

const airpayCallbackSchema = new mongoose.Schema({
  order_id: {
    type: String,
    required: true,
    index: true
  },
  transaction_id: {
    type: String,
    required: false // For backward compatibility
  },
  ap_transactionid: {
    type: String,
    required: false, // Made optional as it might not be present in all callbacks
    index: true
  },
  status: {
    type: String,
    required: true,
    enum: ['SUCCESS', 'FAILED', 'PENDING', 'CANCELLED', 'TRANSACTION IN PROCESS', 'DROPPED', 'CANCEL', 'INCOMPLETE', 'BOUNCED', 'NO RECORDS']
  },
  amount: {
    type: Number,
    required: true
  },
  currency_code: {
    type: String,
    default: '356' // INR currency code
  },
  payment_method: {
    type: String,
    required: false, // Made optional as it might not be present in all callbacks
    index: true
  },
  customer_email: {
    type: String,
    required: true
  },
  customer_phone: {
    type: String,
    required: true
  },
  customer_name: {
    type: String,
    default: null
  },
  merchant_id: {
    type: String,
    required: true
  },
  ap_secure_hash: {
    type: String,
    required: true // ap_SecureHash from AirPay
  },
  transaction_time: {
    type: String,
    default: null
  },
  transaction_type: {
    type: Number,
    default: null
  },
  transaction_status: {
    type: Number,
    default: null
  },
  bank_name: {
    type: String,
    default: null
  },
  card_scheme: {
    type: String,
    default: null
  },
  card_number: {
    type: String,
    default: null
  },
  card_type: {
    type: String,
    default: null
  },
  card_country: {
    type: String,
    default: null
  },
  bank_response_msg: {
    type: String,
    default: null
  },
  failure_reason: {
    type: String,
    default: null
  },
  risk: {
    type: String,
    default: '0'
  },
  billed_amount: {
    type: Number,
    default: null
  },
  surcharge_amount: {
    type: Number,
    default: null
  },
  token: {
    type: String,
    default: null
  },
  card_unique_code: {
    type: String,
    default: null
  },
  custom_var: {
    type: String,
    default: null
  },
  txn_mode: {
    type: String,
    default: null
  },
  message: {
    type: String,
    default: null
  },
  // Legacy fields for backward compatibility
  currency: {
    type: String,
    default: 'INR'
  },
  signature: {
    type: String,
    default: null
  },
  timestamp: {
    type: String,
    default: null
  },
  gateway_response: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  processed: {
    type: Boolean,
    default: false
  },
  processed_at: {
    type: Date,
    default: null
  },
  raw_data: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  }
}, {
  timestamps: true
});

// Index for efficient querying
airpayCallbackSchema.index({ order_id: 1, ap_transactionid: 1 });
airpayCallbackSchema.index({ order_id: 1, transaction_id: 1 }); // Legacy support
airpayCallbackSchema.index({ processed: 1 });
airpayCallbackSchema.index({ createdAt: -1 });
airpayCallbackSchema.index({ merchant_id: 1 });
airpayCallbackSchema.index({ status: 1 });

const AirpayCallback = mongoose.model('AirpayCallback', airpayCallbackSchema);

module.exports = AirpayCallback;