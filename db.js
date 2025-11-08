import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './models/User.js';
dotenv.config();

class DatabaseConnection {
    static instance;

    constructor() {
        if (!DatabaseConnection.instance) {
            this.init();
            DatabaseConnection.instance = this;
        }
        return DatabaseConnection.instance;
    }

    init = async () => {
        try {
            // MongoDB Connection with HA configuration
            const mongoOptions = {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                retryWrites: true,
                w: 'majority',
                readPreference: 'secondaryPreferred',
                maxPoolSize: 10,
                minPoolSize: 5,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 60000,
                family: 4,
                // Replica Set configuration
                replicaSet: process.env.MONGO_REPLICA_SET || undefined,
                // Auto-reconnect settings
                autoIndex: false,
                connectTimeoutMS: 10000,
            };

            // Connection event handlers for monitoring
            mongoose.connection.on('connected', () => {
                console.log('✅ MongoDB connected successfully');
            });

            mongoose.connection.on('error', (err) => {
                console.error('❌ MongoDB connection error:', err);
            });

            mongoose.connection.on('disconnected', () => {
                console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
            });

            mongoose.connection.on('reconnected', () => {
                console.log('✅ MongoDB reconnected successfully');
            });

            // Graceful shutdown handler
            process.on('SIGINT', async () => {
                try {
                    await mongoose.connection.close();
                    console.log('MongoDB connection closed through app termination');
                    process.exit(0);
                } catch (err) {
                    console.error('Error during MongoDB shutdown:', err);
                    process.exit(1);
                }
            });

            this.db = await mongoose.connect(process.env.MONGODB_URI, mongoOptions);
            console.log('MongoDB initialized with HA configuration');

            // Initialize repositories
            this.repositories = {
                user: User
            };


        } catch (error) {
            console.error('Failed to initialize database:', error);
            // Retry connection after 5 seconds
            setTimeout(() => this.init(), 5000);
        }
    };

    getDB = () => {
        if (!this.db) {
            throw new Error('Database not initialized');
        }
        return this.db;
    };

    getRepository = (repositoryName) => {
        if (!this.repositories[repositoryName]) {
            throw new Error(`Repository ${repositoryName} not found`);
        }
        return this.repositories[repositoryName];
    };

    // Health check method for MongoDB
    isHealthy = async () => {
        try {
            const state = mongoose.connection.readyState;
            // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
            if (state === 1) {
                await mongoose.connection.db.admin().ping();
                return true;
            }
            return false;
        } catch (error) {
            console.error('Health check failed:', error);
            return false;
        }
    };

    // Graceful close method
    close = async () => {
        try {
            await mongoose.connection.close();
            console.log('Database connection closed gracefully');
        } catch (error) {
            console.error('Error closing database connection:', error);
            throw error;
        }
    };
}

const appAuth = new DatabaseConnection();
export default appAuth;