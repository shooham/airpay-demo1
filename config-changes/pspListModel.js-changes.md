# Changes to models/pspListModel.js

Replace your existing `pspListSchema` with this updated version:

## Updated Schema:
```javascript
const pspListSchema = new mongoose.Schema(
  {
    handle: {
      type: String,
      require:[true, 'A psp must have handle'],
    },
    pspName: {
        type: String,
        require:[true, 'A psp must have name'],
    },
    provider: {
      type: String,
      required: true,
      enum: ['razorpay', 'payu', 'easebuzz', 'cashfree', 'airpay', 'other']
    },
    credentials: {
      merchantId: String,
      apiKey: String,
      secretKey: String,
      // AirPay specific fields
      sanctumUrl: {
        type: String,
        default: 'https://sanctum.airpay.co.in'
      },
      // Other provider specific fields can be added here
      additionalConfig: mongoose.Schema.Types.Mixed
    },
    priority: {
      type: Number,
      default: 1
    },
    limits: {
      dailyLimit: {
        type: Number,
        default: 1000000 // 10 Lakh
      },
      monthlyLimit: {
        type: Number,
        default: 30000000 // 3 Crore
      },
      perTransactionLimit: {
        type: Number,
        default: 100000 // 1 Lakh
      }
    },
    status: {
      type: String,
      enum: ['Active', 'Inactive', 'Maintenance'],
      default: 'Active'
    },
    healthStatus: {
      type: String,
      enum: ['healthy', 'unhealthy', 'unknown'],
      default: 'unknown'
    },
    lastHealthCheck: Date,
    lastError: String,
    description: String,
    assignedClients: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Client'
    }],
    isActive: {
      type: Boolean,
      default:true
    },
    isDeleted: {
      type: Boolean,
      default:false
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  {
    timestamps: true,
  }
);
```

## Key Changes:
- Added `provider` field with 'airpay' enum value
- Added `credentials` object with AirPay specific fields
- Added `priority`, `limits`, `status`, `healthStatus` fields
- Added audit fields (`createdBy`, `updatedBy`)
- Added `assignedClients` for client management