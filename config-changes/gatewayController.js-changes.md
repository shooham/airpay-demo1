# Changes to controllers/admin/gatewayController.js

Add these changes to your `controllers/admin/gatewayController.js` file:

## 1. Add AirPay Test Case (in the testGateway function, around line 150)
```javascript
        case 'airpay':
          testResult = await testAirpayConnection(gateway, testResult);
          break;
```

This should be added in the switch statement after:
```javascript
        case 'cashfree':
          testResult = await testCashfreeConnection(gateway, testResult);
          break;
```

## 2. Add AirPay Test Function (at the bottom of the file, after other test functions)
```javascript
async function testAirpayConnection(gateway, testResult) {
  try {
    const axios = require('axios');
    
    // Test AirPay API connectivity
    const response = await axios.get(
      `${gateway.credentials.sanctumUrl}/api/v1/health`,
      {
        headers: {
          'Authorization': `Bearer ${gateway.credentials.apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );
    
    if (response.status === 200) {
      testResult.status = 'success';
    } else {
      testResult.status = 'failed';
      testResult.error = `HTTP ${response.status}`;
    }
  } catch (error) {
    testResult.status = 'failed';
    testResult.error = error.message;
  }
  
  return testResult;
}
```

This should be added after the existing test functions like `testCashfreeConnection`.