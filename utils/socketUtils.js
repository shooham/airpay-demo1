/**
 * Socket Utilities for Real-time Updates
 * Provides WebSocket functionality for payment status updates
 */

class SocketManager {
    constructor() {
        this.io = null;
        this.connections = new Map();
        this.rooms = new Map();
    }

    // Initialize Socket.IO
    initialize(server) {
        if (!server) {
            console.warn('⚠️  Socket.IO server not provided, using mock implementation');
            return;
        }

        try {
            const { Server } = require('socket.io');
            this.io = new Server(server, {
                cors: {
                    origin: process.env.FRONTEND_URL || "http://localhost:3000",
                    methods: ["GET", "POST"],
                    credentials: true
                },
                transports: ['websocket', 'polling']
            });

            this.setupEventHandlers();
            console.log('✅ Socket.IO initialized successfully');
        } catch (error) {
            console.error('❌ Failed to initialize Socket.IO:', error.message);
            console.log('📝 Install socket.io: npm install socket.io');
        }
    }

    // Setup event handlers
    setupEventHandlers() {
        if (!this.io) return;

        this.io.on('connection', (socket) => {
            console.log(`🔌 Client connected: ${socket.id}`);
            
            // Store connection
            this.connections.set(socket.id, {
                socket: socket,
                connectedAt: new Date(),
                userId: null,
                rooms: new Set()
            });

            // Handle authentication
            socket.on('authenticate', (data) => {
                this.handleAuthentication(socket, data);
            });

            // Handle joining payment room
            socket.on('join-payment', (orderId) => {
                this.joinPaymentRoom(socket, orderId);
            });

            // Handle leaving payment room
            socket.on('leave-payment', (orderId) => {
                this.leavePaymentRoom(socket, orderId);
            });

            // Handle disconnect
            socket.on('disconnect', (reason) => {
                console.log(`🔌 Client disconnected: ${socket.id} - ${reason}`);
                this.handleDisconnect(socket);
            });

            // Send welcome message
            socket.emit('connected', {
                message: 'Connected to AirPay Gateway',
                timestamp: new Date().toISOString()
            });
        });
    }

    // Handle client authentication
    handleAuthentication(socket, data) {
        try {
            const { userId, token } = data;
            
            // In production, verify the token here
            if (token && userId) {
                const connection = this.connections.get(socket.id);
                if (connection) {
                    connection.userId = userId;
                    socket.emit('authenticated', { success: true, userId });
                    console.log(`🔐 Client authenticated: ${socket.id} - User: ${userId}`);
                }
            } else {
                socket.emit('authentication-error', { error: 'Invalid credentials' });
            }
        } catch (error) {
            console.error('Authentication error:', error);
            socket.emit('authentication-error', { error: 'Authentication failed' });
        }
    }

    // Join payment-specific room
    joinPaymentRoom(socket, orderId) {
        if (!orderId) return;

        const roomName = `payment:${orderId}`;
        socket.join(roomName);

        const connection = this.connections.get(socket.id);
        if (connection) {
            connection.rooms.add(roomName);
        }

        console.log(`📱 Client ${socket.id} joined payment room: ${orderId}`);
        socket.emit('joined-payment', { orderId, room: roomName });
    }

    // Leave payment room
    leavePaymentRoom(socket, orderId) {
        if (!orderId) return;

        const roomName = `payment:${orderId}`;
        socket.leave(roomName);

        const connection = this.connections.get(socket.id);
        if (connection) {
            connection.rooms.delete(roomName);
        }

        console.log(`📱 Client ${socket.id} left payment room: ${orderId}`);
    }

    // Handle client disconnect
    handleDisconnect(socket) {
        const connection = this.connections.get(socket.id);
        if (connection) {
            // Leave all rooms
            connection.rooms.forEach(room => {
                socket.leave(room);
            });
            
            // Remove connection
            this.connections.delete(socket.id);
        }
    }

    // Send update to specific payment room
    sendPaymentUpdate(orderId, event, data) {
        if (!this.io) {
            console.log(`📡 Mock socket update - ${event}:`, { orderId, ...data });
            return;
        }

        const roomName = `payment:${orderId}`;
        const updateData = {
            event,
            orderId,
            timestamp: new Date().toISOString(),
            ...data
        };

        this.io.to(roomName).emit('payment-update', updateData);
        console.log(`📡 Payment update sent to room ${roomName}:`, event);
    }

    // Send update to all connected clients
    sendGlobalUpdate(event, data) {
        if (!this.io) {
            console.log(`📡 Mock global update - ${event}:`, data);
            return;
        }

        const updateData = {
            event,
            timestamp: new Date().toISOString(),
            ...data
        };

        this.io.emit('global-update', updateData);
        console.log(`📡 Global update sent:`, event);
    }

    // Send update to specific user
    sendUserUpdate(userId, event, data) {
        if (!this.io) {
            console.log(`📡 Mock user update - ${event}:`, { userId, ...data });
            return;
        }

        // Find user's socket connections
        const userSockets = [];
        this.connections.forEach((connection, socketId) => {
            if (connection.userId === userId) {
                userSockets.push(socketId);
            }
        });

        if (userSockets.length > 0) {
            const updateData = {
                event,
                userId,
                timestamp: new Date().toISOString(),
                ...data
            };

            userSockets.forEach(socketId => {
                this.io.to(socketId).emit('user-update', updateData);
            });

            console.log(`📡 User update sent to ${userSockets.length} connections:`, event);
        }
    }

    // Get connection statistics
    getStats() {
        return {
            totalConnections: this.connections.size,
            authenticatedConnections: Array.from(this.connections.values()).filter(c => c.userId).length,
            rooms: this.rooms.size,
            uptime: process.uptime()
        };
    }

    // Broadcast system status
    broadcastSystemStatus(status) {
        this.sendGlobalUpdate('system-status', {
            status,
            message: `System is ${status}`,
            timestamp: new Date().toISOString()
        });
    }
}

// Create singleton instance
const socketManager = new SocketManager();

// Utility functions for backward compatibility
const sendSocketUpdate = (event, data) => {
    if (event.includes(':')) {
        const [type, action] = event.split(':');
        
        if (type === 'payment' && data.orderId) {
            socketManager.sendPaymentUpdate(data.orderId, action, data);
        } else {
            socketManager.sendGlobalUpdate(event, data);
        }
    } else {
        socketManager.sendGlobalUpdate(event, data);
    }
};

const sendPaymentUpdate = (orderId, status, data = {}) => {
    socketManager.sendPaymentUpdate(orderId, 'status-change', {
        status,
        ...data
    });
};

const sendUserNotification = (userId, message, type = 'info') => {
    socketManager.sendUserUpdate(userId, 'notification', {
        message,
        type,
        timestamp: new Date().toISOString()
    });
};

// Health check for socket connections
const getSocketHealth = () => {
    const stats = socketManager.getStats();
    return {
        status: socketManager.io ? 'connected' : 'disconnected',
        ...stats
    };
};

module.exports = {
    socketManager,
    sendSocketUpdate,
    sendPaymentUpdate,
    sendUserNotification,
    getSocketHealth,
    
    // Initialize function for app.js
    initializeSocket: (server) => {
        socketManager.initialize(server);
        return socketManager;
    }
};