const mongoose = require('mongoose');

/**
 * Transaction Model for AirPay Integration
 * Stores all payment transaction data with proper indexing
 */

const transactionSchema = new mongoose.Schema({
    billId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        trim: true,
        maxlength: 50
    },
    amount: {
        type: Number,
        required: true,
        min: 0.01,
        max: 10000000,
        validate: {
            validator: function(v) {
                return v > 0 && Number.isFinite(v);
            },
            message: 'Amount must be a positive finite number'
        }
    },
    customerEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        maxlength: 254,
        validate: {
            validator: function(v) {
                return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(v);
            },
            message: 'Invalid email format'
        }
    },
    customerPhone: {
        type: String,
        required: true,
        trim: true,
        validate: {
            validator: function(v) {
                const cleanPhone = v.replace(/\D/g, '');
                return /^[6-9]\d{9}$/.test(cleanPhone);
            },
            message: 'Invalid phone number format'
        }
    },
    customerName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100,
        validate: {
            validator: function(v) {
                return v && v.length >= 2;
            },
            message: 'Customer name must be at least 2 characters'
        }
    },
    status: {
        type: String,
        enum: ['INITIATED', 'SUCCESS', 'FAILED', 'PENDING', 'CANCELLED', 'REFUNDED', 'PARTIAL_REFUND'],
        default: 'INITIATED',
        index: true
    },
    psp: {
        type: String,
        default: 'AirPay',
        index: true
    },
    method: {
        type: String,
        default: 'unknown',
        enum: ['unknown', 'card', 'netbanking', 'upi', 'wallet', 'emi', 'paylater']
    },
    ap_transactionid: {
        type: String,
        index: true,
        sparse: true // Allow null values but index non-null ones
    },
    gateway_response: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    refund_amount: {
        type: Number,
        default: 0,
        min: 0
    },
    refund_status: {
        type: String,
        enum: ['NONE', 'INITIATED', 'SUCCESS', 'FAILED'],
        default: 'NONE'
    },
    failure_reason: {
        type: String,
        default: null,
        maxlength: 500
    },
    payment_mode: {
        type: String,
        default: null
    },
    bank_name: {
        type: String,
        default: null
    },
    card_type: {
        type: String,
        default: null
    },
    transaction_fee: {
        type: Number,
        default: 0,
        min: 0
    },
    net_amount: {
        type: Number,
        default: function() {
            return this.amount - this.transaction_fee;
        }
    },
    currency: {
        type: String,
        default: 'INR',
        enum: ['INR']
    },
    currency_code: {
        type: String,
        default: '356'
    },
    webhook_received: {
        type: Boolean,
        default: false,
        index: true
    },
    webhook_verified: {
        type: Boolean,
        default: false
    },
    retry_count: {
        type: Number,
        default: 0,
        min: 0,
        max: 5
    },
    last_retry_at: {
        type: Date,
        default: null
    },
    completed_at: {
        type: Date,
        default: null,
        index: true
    },
    expires_at: {
        type: Date,
        default: function() {
            return new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
        },
        index: true
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    ip_address: {
        type: String,
        default: null
    },
    user_agent: {
        type: String,
        default: null,
        maxlength: 500
    }
}, {
    timestamps: true,
    versionKey: false
});

// Compound indexes for efficient querying
transactionSchema.index({ billId: 1, status: 1 });
transactionSchema.index({ customerEmail: 1, createdAt: -1 });
transactionSchema.index({ status: 1, createdAt: -1 });
transactionSchema.index({ ap_transactionid: 1, status: 1 });
transactionSchema.index({ psp: 1, status: 1, createdAt: -1 });
transactionSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 }); // TTL index

// Virtual for formatted amount
transactionSchema.virtual('formattedAmount').get(function() {
    return `₹${this.amount.toFixed(2)}`;
});

// Virtual for transaction age
transactionSchema.virtual('ageInMinutes').get(function() {
    return Math.floor((Date.now() - this.createdAt.getTime()) / (1000 * 60));
});

// Instance methods
transactionSchema.methods.markAsSuccess = function(gatewayResponse = {}) {
    this.status = 'SUCCESS';
    this.completed_at = new Date();
    this.gateway_response = { ...this.gateway_response, ...gatewayResponse };
    this.webhook_received = true;
    this.webhook_verified = true;
    return this.save();
};

transactionSchema.methods.markAsFailed = function(reason = 'Unknown error', gatewayResponse = {}) {
    this.status = 'FAILED';
    this.failure_reason = reason;
    this.completed_at = new Date();
    this.gateway_response = { ...this.gateway_response, ...gatewayResponse };
    this.webhook_received = true;
    this.webhook_verified = true;
    return this.save();
};

transactionSchema.methods.incrementRetry = function() {
    this.retry_count += 1;
    this.last_retry_at = new Date();
    return this.save();
};

transactionSchema.methods.isExpired = function() {
    return this.expires_at < new Date();
};

// Static methods
transactionSchema.statics.findByOrderId = function(orderId) {
    return this.findOne({ billId: orderId });
};

transactionSchema.statics.findPendingTransactions = function() {
    return this.find({ 
        status: { $in: ['INITIATED', 'PENDING'] },
        expires_at: { $gt: new Date() }
    });
};

transactionSchema.statics.findExpiredTransactions = function() {
    return this.find({ 
        status: { $in: ['INITIATED', 'PENDING'] },
        expires_at: { $lt: new Date() }
    });
};

// Pre-save middleware
transactionSchema.pre('save', function(next) {
    // Calculate net amount
    this.net_amount = this.amount - this.transaction_fee;
    
    // Set completed_at for final statuses
    if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(this.status) && !this.completed_at) {
        this.completed_at = new Date();
    }
    
    next();
});

// Post-save middleware for logging
transactionSchema.post('save', function(doc) {
    if (doc.isNew) {
        console.log(`Transaction created: ${doc.billId} - ₹${doc.amount}`);
    } else if (doc.isModified('status')) {
        console.log(`Transaction status updated: ${doc.billId} - ${doc.status}`);
    }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;