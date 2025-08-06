# Changes to routes/callbackRoute.js

Add these lines to your `routes/callbackRoute.js` file:

## 1. Add Import (at the top with other imports)
```javascript
const airpayController = require("../controllers/gateways/airpayController");
```

## 2. Add Routes (at the bottom before module.exports)
```javascript
// AirPay callback routes
router.route("/airpay").post(airpayController.handleCallback);
router.route("/airpay").get(airpayController.handleCallback);
```

## Complete Context:
The import should be added after:
```javascript
const { easeBuzzTransactionCallback } = require("../controllers/easeBuzzController");
```

The routes should be added before:
```javascript
module.exports = router;
```