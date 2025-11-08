import jwt from "jsonwebtoken";
import User from '../models/User.js'
import appAuth from "../db.js";
import * as CONSTANTS from "../utils/constants.js";


export const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

export const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ error: 'Not authorized to access this route' });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await User.findById(decoded.id).select('-password');

      if (!req.user || !req.user.isActive) {
        return res.status(401).json({ error: 'User no longer exists or is inactive' });
      }

      next();
    } catch (err) {
      return res.status(401).json({ error: 'Not authorized, token failed' });
    }
  } catch (error) {
    next(error);
  }
};

export const checkOrganization = async (req, res, next) => {
  try {
    const organizationId = req.params.organizationId || req.body.organization;

    if (req.user.organization.toString() !== organizationId) {
      return res.status(403).json({ error: 'Not authorized to access this organization' });
    }

    next();
  } catch (error) {
    next(error);
  }
};

export const  authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

export const refreshTokenMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.split(' ')[1];

    try {
      jwt.verify(token, process.env.JWT_SECRET);
      return next();
    } catch (jwtError) {
      if (jwtError.name !== 'TokenExpriedError') {
        return next();
      }
    }

    const refreshToken = req.headers['x-refresh-token'];

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'token expired and no refresh token provided',
        response: null,
        errorCode: 'auth/token-expired'
      })
    }

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const User = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
      const user = await User.findById(decoded.uid);

      if (!User || user.refreshToken !== refreshToken || user.isDeleted) {
        return res.status(401).json({
          success: false,
          message: 'Invalid refresh token',
          response: 'auth/invalid-refresh-token'
        })
      }

      const newAccessToken = jwt.sign(
        { uid: user._id.toString(), email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.setHeader('X-New-Access-Token', newAccessToken);
      req.user = { uid: user._id.toString(), email: user.email }

    } catch (refreshError) {
      return res.status(401).json({
        success: false,
        message: 'Failed to refresh token',
        response: null,
        errorCode: 'auth/refresh-failed'
      });
    }
  } catch (err) {

  }
}


