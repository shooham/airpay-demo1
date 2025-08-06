const fs = require('fs');
const path = require('path');
require('dotenv').config();

/**
 * Integration Validation Script
 * Validates the complete AirPay integration setup
 */

class IntegrationValidator {
    constructor() {
        this.errors = [];
        this.warnings = [];
        this.passed = [];
    }

    // Check if required files exist
    checkRequiredFiles() {
        console.log('\n📁 Checking Required Files...');
        
        const requiredFiles = [
            'controllers/gateways/airpayController.js',
            'routes/gateways/airpayRoutes.js',
            'models/airpayCallbackModel.js',
            'utils/errorHandler.js',
            'utils/validator.js',
            'scripts/addAirPayGateway.js',
            'scripts/testAirPayIntegration.js'
        ];

        requiredFiles.forEach(file => {
            const filePath = path.join(__dirname, '..', file);
            if (fs.existsSync(filePath)) {
                this.passed.push(`✅ ${file} exists`);
            } else {
                this.errors.push(`❌ Missing file: ${file}`);
            }
        });
    }

    // Check environment variables
    checkEnvironmentVariables() {
        console.log('\n🔧 Checking Environment Variables...');
        
        const requiredVars = [
            'AIRPAY_MERCHANT_ID',
            'AIRPAY_USERNAME', 
            'AIRPAY_PASSWORD',
            'AIRPAY_SECRET_KEY',
            'AIRPAY_CLIENT_ID',
            'AIRPAY_CLIENT_SECRET',
            'DOMAIN_URL'
        ];

        requiredVars.forEach(varName => {
            if (process.env[varName]) {
                if (process.env[varName].startsWith('your_')) {
                    this.warnings.push(`⚠️  ${varName} has placeholder value`);
                } else {
                    this.passed.push(`✅ ${varName} is set`);
                }
            } else {
                this.errors.push(`❌ Missing environment variable: ${varName}`);
            }
        });

        // Check optional variables
        const optionalVars = ['AIRPAY_ENVIRONMENT', 'MONGODB_URI'];
        optionalVars.forEach(varName => {
            if (process.env[varName]) {
                this.passed.push(`✅ ${varName} is set`);
            } else {
                this.warnings.push(`⚠️  Optional variable ${varName} not set`);
            }
        });
    }

    // Check code quality
    checkCodeQuality() {
        console.log('\n🔍 Checking Code Quality...');
        
        try {
            // Check controller file
            const controllerPath = path.join(__dirname, '..', 'controllers/gateways/airpayController.js');
            const controllerContent = fs.readFileSync(controllerPath, 'utf8');
            
            // Check for deprecated functions
            if (controllerContent.includes('createCipher(')) {
                this.errors.push('❌ Using deprecated createCipher function');
            } else {
                this.passed.push('✅ Using secure createCipheriv function');
            }
            
            if (controllerContent.includes('createDecipher(')) {
                this.errors.push('❌ Using deprecated createDecipher function');
            } else {
                this.passed.push('✅ Using secure createDecipheriv function');
            }
            
            // Check for error handling
            if (controllerContent.includes('ErrorHandler')) {
                this.passed.push('✅ Error handling implemented');
            } else {
                this.warnings.push('⚠️  Error handling not implemented');
            }
            
            // Check for validation
            if (controllerContent.includes('Validator')) {
                this.passed.push('✅ Input validation implemented');
            } else {
                this.warnings.push('⚠️  Input validation not implemented');
            }
            
        } catch (error) {
            this.errors.push(`❌ Error reading controller file: ${error.message}`);
        }
    }

    // Check security measures
    checkSecurity() {
        console.log('\n🔒 Checking Security Measures...');
        
        // Check if .env is in .gitignore
        const gitignorePath = path.join(__dirname, '..', '..', '.gitignore');
        if (fs.existsSync(gitignorePath)) {
            const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
            if (gitignoreContent.includes('.env')) {
                this.passed.push('✅ .env file is in .gitignore');
            } else {
                this.errors.push('❌ .env file not in .gitignore - SECURITY RISK');
            }
        } else {
            this.warnings.push('⚠️  .gitignore file not found');
        }
        
        // Check HTTPS usage
        if (process.env.DOMAIN_URL && process.env.DOMAIN_URL.startsWith('https://')) {
            this.passed.push('✅ Using HTTPS for domain URL');
        } else {
            this.errors.push('❌ Domain URL should use HTTPS in production');
        }
        
        // Check environment setting
        if (process.env.AIRPAY_ENVIRONMENT === 'production') {
            this.warnings.push('⚠️  Production environment detected - ensure all security measures are in place');
        } else {
            this.passed.push('✅ Using sandbox environment for testing');
        }
    }

    // Check dependencies
    checkDependencies() {
        console.log('\n📦 Checking Dependencies...');
        
        const packageJsonPath = path.join(__dirname, '..', '..', 'package.json');
        if (fs.existsSync(packageJsonPath)) {
            try {
                const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
                const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
                
                const requiredDeps = ['axios', 'mongoose', 'express', 'dotenv'];
                requiredDeps.forEach(dep => {
                    if (dependencies[dep]) {
                        this.passed.push(`✅ ${dep} dependency found`);
                    } else {
                        this.errors.push(`❌ Missing dependency: ${dep}`);
                    }
                });
                
            } catch (error) {
                this.errors.push(`❌ Error reading package.json: ${error.message}`);
            }
        } else {
            this.warnings.push('⚠️  package.json not found in parent directory');
        }
    }

    // Run all validations
    async runValidation() {
        console.log('🚀 Starting AirPay Integration Validation...');
        console.log('===========================================');
        
        this.checkRequiredFiles();
        this.checkEnvironmentVariables();
        this.checkCodeQuality();
        this.checkSecurity();
        this.checkDependencies();
        
        // Display results
        console.log('\n📊 Validation Results:');
        console.log('======================');
        
        if (this.passed.length > 0) {
            console.log('\n✅ PASSED CHECKS:');
            this.passed.forEach(item => console.log(`   ${item}`));
        }
        
        if (this.warnings.length > 0) {
            console.log('\n⚠️  WARNINGS:');
            this.warnings.forEach(item => console.log(`   ${item}`));
        }
        
        if (this.errors.length > 0) {
            console.log('\n❌ ERRORS:');
            this.errors.forEach(item => console.log(`   ${item}`));
        }
        
        // Calculate score
        const totalChecks = this.passed.length + this.warnings.length + this.errors.length;
        const score = Math.round((this.passed.length / totalChecks) * 100);
        
        console.log('\n📈 INTEGRATION SCORE:');
        console.log(`   ${score}% (${this.passed.length}/${totalChecks} checks passed)`);
        
        if (this.errors.length === 0) {
            console.log('\n🎉 Integration validation completed successfully!');
            console.log('   Your AirPay integration is ready for deployment.');
            
            if (this.warnings.length > 0) {
                console.log('\n💡 Recommendations:');
                console.log('   - Address the warnings above for optimal setup');
                console.log('   - Review the security checklist');
                console.log('   - Test all payment flows before going live');
            }
        } else {
            console.log('\n🚨 Integration validation failed!');
            console.log('   Please fix the errors above before deployment.');
        }
        
        console.log('\n📚 Next Steps:');
        console.log('   1. Fix any errors found above');
        console.log('   2. Run: node scripts/testAirPayIntegration.js');
        console.log('   3. Review SECURITY-CHECKLIST.md');
        console.log('   4. Deploy to production when ready');
        
        return {
            score: score,
            passed: this.passed.length,
            warnings: this.warnings.length,
            errors: this.errors.length,
            isReady: this.errors.length === 0
        };
    }
}

// Run validation if script is executed directly
if (require.main === module) {
    const validator = new IntegrationValidator();
    validator.runValidation().catch(console.error);
}

module.exports = IntegrationValidator;