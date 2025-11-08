import dotenv from 'dotenv';
import express  from 'express';
import mongoose  from 'express';
import cors  from 'cors';
import helmet  from 'helmet';
import rateLimit  from 'express-rate-limit';
import mongoSanitize  from 'express-mongo-sanitize';
import compression  from 'compression';

dotenv.config();

import authRoutes  from './routes/auth';
import projectRoutes  from './routes/projects';
import taskRoutes  from './routes/projects';
import teamRoutes  from '../routes/team';

const app = express();

app.use(helmet());

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true
}))

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.' 
});

app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 *1000,
    max: 5,
    message: 'Too many authentication attempts, please try again later.'
});

app.use('/api/auth/login', authLimiter)
app.use('/api/auth/register', authLimiter);

app.use(express.json({limit: '10mb'}))
app.use(express.urlencoded({extended: true, limit: '10mb'}));

app.use(mongoSanitize());
app.use(compression());



