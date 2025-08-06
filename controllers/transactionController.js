/**
 * Transaction Controller for Business Logic
 * Handles transaction-related business operations
 */

const Transaction = require('../models/transactionModel');
const { sendSocketUpdate } = require('../utils/socketUtils');

class TransactionController {
    // Get all transactions with pagination
    async getAllTransactions(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;
            const skip = (page - 1) * limit;
            
            const filter = {};
            
            // Add filters
            if (req.query.status) {
                filter.status = req.query.status;
            }
            
            if (req.query.psp) {
                filter.psp = req.query.psp;
            }
            
            if (req.query.from && req.query.to) {
                filter.createdAt = {
                    $gte: new Date(req.query.from),
                    $lte: new Date(req.query.to)
                };
            }
            
            const transactions = await Transaction.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean();
            
            const total = await Transaction.countDocuments(filter);
            
            res.json({
                status: 'success',
                data: {
                    transactions,
                    pagination: {
                        page,
                        limit,
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });
        } catch (error) {
            console.error('Error getting transactions:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to get transactions',
                error: 'Internal server error'
            });
        }
    }

    // Get single transaction
    async getTransaction(req, res) {
        try {
            const { id } = req.params;
            
            let transaction;
            if (id.length === 24) {
                // MongoDB ObjectId
                transaction = await Transaction.findById(id);
            } else {
                // Order ID
                transaction = await Transaction.findByOrderId(id);
            }
            
            if (!transaction) {
                return res.status(404).json({
                    status: 'error',
                    message: 'Transaction not found',
                    code: 'TRANSACTION_NOT_FOUND'
                });
            }
            
            res.json({
                status: 'success',
                data: transaction
            });
        } catch (error) {
            console.error('Error getting transaction:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to get transaction',
                error: 'Internal server error'
            });
        }
    }

    // Update transaction status
    async updateTransactionStatus(req, res) {
        try {
            const { id } = req.params;
            const { status, reason } = req.body;
            
            const transaction = await Transaction.findById(id);
            if (!transaction) {
                return res.status(404).json({
                    status: 'error',
                    message: 'Transaction not found',
                    code: 'TRANSACTION_NOT_FOUND'
                });
            }
            
            const oldStatus = transaction.status;
            transaction.status = status;
            
            if (reason) {
                transaction.failure_reason = reason;
            }
            
            if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(status)) {
                transaction.completed_at = new Date();
            }
            
            await transaction.save();
            
            // Send real-time update
            sendSocketUpdate('transaction:status-updated', {
                transactionId: transaction._id,
                orderId: transaction.billId,
                oldStatus,
                newStatus: status,
                message: `Transaction status updated from ${oldStatus} to ${status}`
            });
            
            res.json({
                status: 'success',
                message: 'Transaction status updated',
                data: transaction
            });
        } catch (error) {
            console.error('Error updating transaction status:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to update transaction status',
                error: 'Internal server error'
            });
        }
    }

    // Get transaction statistics
    async getTransactionStats(req, res) {
        try {
            const { period = '7d' } = req.query;
            
            let startDate;
            switch (period) {
                case '1d':
                    startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
                    break;
                case '7d':
                    startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                    break;
                case '30d':
                    startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
                    break;
                default:
                    startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            }
            
            const stats = await Transaction.aggregate([
                {
                    $match: {
                        createdAt: { $gte: startDate }
                    }
                },
                {
                    $group: {
                        _id: '$status',
                        count: { $sum: 1 },
                        totalAmount: { $sum: '$amount' },
                        avgAmount: { $avg: '$amount' }
                    }
                }
            ]);
            
            const totalStats = await Transaction.aggregate([
                {
                    $match: {
                        createdAt: { $gte: startDate }
                    }
                },
                {
                    $group: {
                        _id: null,
                        totalTransactions: { $sum: 1 },
                        totalAmount: { $sum: '$amount' },
                        avgAmount: { $avg: '$amount' },
                        successfulTransactions: {
                            $sum: { $cond: [{ $eq: ['$status', 'SUCCESS'] }, 1, 0] }
                        },
                        failedTransactions: {
                            $sum: { $cond: [{ $eq: ['$status', 'FAILED'] }, 1, 0] }
                        }
                    }
                }
            ]);
            
            const dailyStats = await Transaction.aggregate([
                {
                    $match: {
                        createdAt: { $gte: startDate }
                    }
                },
                {
                    $group: {
                        _id: {
                            year: { $year: '$createdAt' },
                            month: { $month: '$createdAt' },
                            day: { $dayOfMonth: '$createdAt' }
                        },
                        count: { $sum: 1 },
                        amount: { $sum: '$amount' },
                        successful: {
                            $sum: { $cond: [{ $eq: ['$status', 'SUCCESS'] }, 1, 0] }
                        }
                    }
                },
                {
                    $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
                }
            ]);
            
            const successRate = totalStats[0] ? 
                (totalStats[0].successfulTransactions / totalStats[0].totalTransactions * 100).toFixed(2) : 0;
            
            res.json({
                status: 'success',
                data: {
                    period,
                    summary: totalStats[0] || {},
                    success_rate: parseFloat(successRate),
                    status_breakdown: stats,
                    daily_stats: dailyStats,
                    generated_at: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Error getting transaction stats:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to get transaction statistics',
                error: 'Internal server error'
            });
        }
    }

    // Process affiliate commission (placeholder)
    async processAffiliateCommission(transaction) {
        try {
            // This is a placeholder for affiliate commission processing
            // Implement your business logic here
            
            console.log(`Processing affiliate commission for transaction: ${transaction.billId}`);
            
            // Example logic:
            // 1. Check if transaction has affiliate data
            // 2. Calculate commission based on amount and rate
            // 3. Create commission record
            // 4. Send notification to affiliate
            
            const commissionRate = 0.02; // 2%
            const commissionAmount = transaction.amount * commissionRate;
            
            console.log(`Commission calculated: ₹${commissionAmount.toFixed(2)}`);
            
            // Here you would typically:
            // - Save commission record to database
            // - Update affiliate balance
            // - Send notification
            
            return {
                success: true,
                commission: commissionAmount,
                rate: commissionRate
            };
        } catch (error) {
            console.error('Error processing affiliate commission:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Retry failed transactions
    async retryFailedTransaction(req, res) {
        try {
            const { id } = req.params;
            
            const transaction = await Transaction.findById(id);
            if (!transaction) {
                return res.status(404).json({
                    status: 'error',
                    message: 'Transaction not found',
                    code: 'TRANSACTION_NOT_FOUND'
                });
            }
            
            if (transaction.status !== 'FAILED') {
                return res.status(400).json({
                    status: 'error',
                    message: 'Only failed transactions can be retried',
                    code: 'INVALID_STATUS'
                });
            }
            
            if (transaction.retry_count >= 5) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Maximum retry attempts reached',
                    code: 'MAX_RETRIES_REACHED'
                });
            }
            
            // Reset transaction for retry
            transaction.status = 'INITIATED';
            transaction.failure_reason = null;
            transaction.completed_at = null;
            await transaction.incrementRetry();
            
            res.json({
                status: 'success',
                message: 'Transaction queued for retry',
                data: {
                    transaction_id: transaction._id,
                    retry_count: transaction.retry_count
                }
            });
        } catch (error) {
            console.error('Error retrying transaction:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to retry transaction',
                error: 'Internal server error'
            });
        }
    }

    // Export transactions to CSV
    async exportTransactions(req, res) {
        try {
            const { format = 'json', ...filters } = req.query;
            
            const query = {};
            
            if (filters.status) query.status = filters.status;
            if (filters.psp) query.psp = filters.psp;
            if (filters.from && filters.to) {
                query.createdAt = {
                    $gte: new Date(filters.from),
                    $lte: new Date(filters.to)
                };
            }
            
            const transactions = await Transaction.find(query)
                .sort({ createdAt: -1 })
                .limit(10000) // Limit for performance
                .lean();
            
            if (format === 'csv') {
                // Convert to CSV format
                const csvHeaders = [
                    'Order ID', 'Amount', 'Status', 'Customer Email', 
                    'Customer Phone', 'Payment Method', 'Created At', 'Completed At'
                ];
                
                const csvRows = transactions.map(t => [
                    t.billId,
                    t.amount,
                    t.status,
                    t.customerEmail,
                    t.customerPhone,
                    t.method,
                    t.createdAt.toISOString(),
                    t.completed_at ? t.completed_at.toISOString() : ''
                ]);
                
                const csvContent = [csvHeaders, ...csvRows]
                    .map(row => row.map(field => `"${field}"`).join(','))
                    .join('\n');
                
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename=transactions.csv');
                res.send(csvContent);
            } else {
                res.json({
                    status: 'success',
                    data: {
                        transactions,
                        count: transactions.length,
                        exported_at: new Date().toISOString()
                    }
                });
            }
        } catch (error) {
            console.error('Error exporting transactions:', error);
            res.status(500).json({
                status: 'error',
                message: 'Failed to export transactions',
                error: 'Internal server error'
            });
        }
    }
}

module.exports = new TransactionController();