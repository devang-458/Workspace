import { Router } from "express";
import authController from '../controller/authController.js'
import {
    refreshTokenMiddleware
} from '../middleware/auth.js'

const router = Router();


router.post('/auth/auth', authController.register);

export default router;

