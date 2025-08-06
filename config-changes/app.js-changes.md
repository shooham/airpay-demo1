# Changes to app.js

Add these lines to your `app.js` file:

## 1. Add Import (around line 32, with other route imports)
```javascript
// 💳 GATEWAY SPECIFIC ROUTES
const airpayRoutes = require('./routes/gateways/airpayRoutes');
```

## 2. Add Route Registration (around line 130, with other route registrations)
```javascript
// 💳 GATEWAY SPECIFIC ROUTES
app.use("/api/v1/gateways/airpay", airpayRoutes);
```

## Complete Context:
The import should be added after:
```javascript
// 🔌 SDK ROUTES
const sdkRoutes = require('./routes/sdk/sdkRoutes');
```

The route registration should be added after:
```javascript
// 🔌 SDK ROUTES
app.use("/sdk", sdkRoutes);
```