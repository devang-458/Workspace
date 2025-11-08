import appAuth from "../db.js";
import commonUtils from "../utils/commonUtils.js";
import * as CONSTANTS from '../utils/constants.js';
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import Organization from "../models/Organization.js";
import { generateToken } from "../middleware/auth.js";


const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
    tls: {
        ciphers: 'SSLv3'
    }
});

class authController {
    register = async (req, res) => {
        try {
            const {
                email,
                password,
                name,
                organizationName,
            } = req.body;


            if (await commonUtils.checkIsNullOrUndefined(email) || await commonUtils.checkIsNullOrUndefined(password)) {
                return res.status(400).json({
                    success: false,
                    message: 'BAD REQUEST',
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                })
            }


            const minLength = 6;
            const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/;
            if (password.length < minLength || !regex.test(password)) {
                return res.status(400).json({
                    success: false,
                    message: 'Weak password. Must include uppercase, lowercase, number and special character.',
                    response: null,
                    errorCode: 'auth/weak-password'
                })
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const checkUser = await userRepo.findOne({ email });

            if (checkUser) {
                return res.status(409).json({
                    success: false,
                    message: CONSTANTS.DUPLICATE_USER,
                    response: null,
                    errorCode: 'auth/email-already-in-use'
                })
            }

            const hashedPassword = await bcrypt.hash(password, 12);

            const verificationToken = crypto.pseudoRandomBytes(32).toString('hex');
            const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

            const organization = await Organization.create({
                name: organizationName,
                owner: null
            });


            const userData = {
                email,
                password: hashedPassword,
                name: name,
                organizationName: organizationName,
                organization: organization._id,
                role: 'admin',
                createdAt: new Date().toISOString(),
                modifiedAt: new Date().toISOString(),
                isDeleted: false,
                isSubscribed: false,
                emailVerified: false,
                verificationToken,
                verificationExpiry,

            };

            const user = await userRepo.create(userData);

            organization.owner = user._id;
            organization.members.push(user._id);
            await organization.save();

            // Generate token
            const token = generateToken(user._id);

            // Send verification email
            const verificationUrl = `${process.env.APP_URL}/auth/v1/verify-email?token=${verificationToken}`;
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verify Your Email',
                html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email.</p>`
            });

            const { password: _, verificationToken: __, ...userResponse } = savedUser;

            return res.status(200).json({
                success: true,
                message: "User registered successfully, verification email sent",
                token: token,
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    organization: organization
                },
                errorCode: null
            });
        } catch (error) {
            console.error("Server-side registration failed:", error);
            let errorCode = "unknown_error";
            let errorMessage = "An error occurred while processing your request.";

            if (error.code === 11000) {
                errorCode = "auth/email-already-in-use";
                errorMessage = "This email is already in use.";
            }

            return res.status(500).json({
                success: false,
                message: errorMessage,
                response: null,
                errorCode: errorCode
            });
        }
    };

    verifyEmail = async (req, resp) => {
        try {
            const { token } = req.query;

            if (!token) {
                return resp.status(400).json({
                    success: false,
                    message: "Verification token is required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findOne({
                verificationToken: token,
                verificationExpiry: { $gt: new Date() }
            });

            if (!user) {
                return resp.status(400).json({
                    success: false,
                    message: "Invalid or expired verification token",
                    response: null,
                    errorCode: "auth/invalid-token"
                });
            }

            user.emailVerified = true;
            user.verificationToken = null;
            user.verificationExpiry = null;
            user.modifiedAt = new Date().toISOString();

            await user.save();

            return resp.status(200).json({
                success: true,
                message: "Email verified successfully",
                response: null,
                errorCode: null
            });
        } catch (error) {
            console.error("Email verification failed:", error);
            return resp.status(500).json({
                success: false,
                message: "An error occurred during email verification",
                response: null,
                errorCode: "verification_error"
            });
        }
    };

    updateUser = async (req, resp) => {
        try {
            const { id, name, organizationName, } = req.body;

            if (await commonUtils.checkIsNullOrUndefined(id)) {
                return resp.status(400).json({
                    success: false,
                    message: "BAD REQUEST: User ID is required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const existingUser = await userRepo.findById(id);

            if (!existingUser || existingUser.isDeleted) {
                return resp.status(404).json({
                    success: false,
                    message: "User not found",
                    response: null,
                    errorCode: "auth/user-not-found"
                });
            }


            const updatedUser = {
                ...existingUser,
                name: name || existingUser.name,
                organizationName: organizationName || existingUser.organizationName,
                modifiedAt: new Date().toISOString()
            };

            await userRepo.update(id, updatedUser);

            const { password, verificationToken, ...userResponse } = updatedUser;

            return resp.status(200).json({
                success: true,
                message: "User updated successfully",
                response: userResponse,
                errorCode: null
            });
        } catch (error) {
            console.error("User update failed:", error);
            return resp.status(500).json({
                success: false,
                message: "An error occurred while updating user information.",
                response: null,
                errorCode: "update_error"
            });
        }
    };


    login = async (req, resp) => {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return resp.status(400).json({
                    success: false,
                    message: "Email and password are required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findOne({ email })
            .select('+password')
            .populate('organization');

            if (!user || user.isDeleted) {
                return resp.status(401).json({
                    success: false,
                    message: "Invalid credentials",
                    response: null,
                    errorCode: "auth/invalid-credential"
                });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                return resp.status(401).json({
                    success: false,
                    message: "Invalid credentials",
                    response: null,
                    errorCode: "auth/invalid-credential"
                });
            }

            const accessToken = jwt.sign(
                { uid: user._id, email: user.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            const refreshToken = jwt.sign(
                { uid: user._id },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: '7d' }
            );

            user.refreshToken = refreshToken;
            user.modifiedAt = new Date().toISOString();
            await user.save();

            return resp.status(200).json({
                success: true,
                message: "Login Successful.",
                response: {
                    uid: user._id,
                    email: user.email,
                    accessToken,
                    refreshToken,
                    emailVerified: user.emailVerified,
                    isSubscribed: user.isSubscribed,
                    organizationName: user.organizationName,
                    name: user.name
                },
                errorCode: null
            });
        } catch (error) {
            console.error("Login failed:", error);
            return resp.status(500).json({
                success: false,
                message: "Authentication failed",
                response: null,
                errorCode: CONSTANTS.INTERNAL_SERVER_ERROR
            });
        }
    };

    logout = async (req, resp) => {
        try {
            const { uid } = req.user;
            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findById(uid);

            if (user) {
                user.refreshToken = null;
                user.modifiedAt = new Date().toISOString();
                await user.save();
            }

            return resp.status(200).json({
                success: true,
                message: "Logged out Successfully",
                response: null,
                errorCode: null
            });
        } catch (error) {
            console.error("Logout failed:", error);

            if (resp.headersSent) {
                console.warn("Headers already sent, suppressing error response.");
                return;
            }
            return resp.status(500).json({
                success: false,
                message: "Failed to Logout",
                response: null,
                errorCode: CONSTANTS.INTERNAL_SERVER_ERROR
            });
        }
    };

    refreshToken = async (req, resp) => {
        try {
            const { refreshToken } = req.body;

            if (!refreshToken) {
                return resp.status(400).json({
                    success: false,
                    message: "Refresh token is required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findById(decoded.uid);

            if (!user || user.refreshToken !== refreshToken || user.isDeleted) {
                return resp.status(401).json({
                    success: false,
                    message: "Invalid refresh token",
                    response: null,
                    errorCode: "auth/invalid-token"
                });
            }

            const newAccessToken = jwt.sign(
                { uid: user._id, email: user.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            return resp.status(200).json({
                success: true,
                message: "Token refreshed successfully",
                response: { accessToken: newAccessToken },
                errorCode: null
            });
        } catch (error) {
            console.error("Token refresh failed:", error);
            return resp.status(401).json({
                success: false,
                message: "Invalid or expired refresh token",
                response: null,
                errorCode: "auth/invalid-token"
            });
        }
    };


    deleteUser = async (req, resp) => {
        try {
            const { uid } = req.body;

            if (!uid) {
                return resp.status(400).json({
                    success: false,
                    message: "User ID is required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findById(uid);

            if (!user) {
                return resp.status(404).json({
                    success: false,
                    message: "User not found",
                    response: null,
                    errorCode: CONSTANTS.NOT_FOUND
                });
            }

            user.isDeleted = true;
            user.modifiedAt = new Date().toISOString();
            user.refreshToken = null;
            await userRepo.update(uid, user);

            return resp.status(200).json({
                success: true,
                message: "User account deleted",
                response: null,
                errorCode: null
            });
        } catch (error) {
            console.error("User deletion failed:", error);
            return resp.status(500).json({
                success: false,
                message: error.message,
                response: null,
                errorCode: CONSTANTS.INTERNAL_SERVER_ERROR
            });
        }
    };

    resendEmailVerification = async (req, resp) => {
        try {
            const { email } = req.body;

            if (!email) {
                return resp.status(400).json({
                    success: false,
                    message: "Email is required",
                    response: null,
                    errorCode: CONSTANTS.BAD_REQUEST
                });
            }

            const userRepo = appAuth.getRepository(CONSTANTS.USER_REPOSITORY);
            const user = await userRepo.findOne({ email });

            if (!user || user.isDeleted) {
                return resp.status(404).json({
                    success: false,
                    message: "User not found",
                    response: null,
                    errorCode: CONSTANTS.NOT_FOUND
                });
            }

            if (user.emailVerified) {
                return resp.status(400).json({
                    success: false,
                    message: "Email already verified",
                    response: null,
                    errorCode: "auth/email-already-verified"
                });
            }

            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

            user.verificationToken = verificationToken;
            user.verificationExpiry = verificationExpiry;
            user.modifiedAt = new Date().toISOString();
            await userRepo.update(user._id, user);

            const verificationUrl = `${process.env.APP_URL}/api/auth/v1/verify-email?token=${verificationToken}`;
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verify Your Email',
                html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email.</p>`
            });

            return resp.status(200).json({
                success: true,
                message: "Verification email sent successfully",
                response: null,
                errorCode: null
            });
        } catch (error) {
            console.error("Resend verification failed:", error);
            return resp.status(500).json({
                success: false,
                message: "An error occurred while resending the verification email",
                response: null,
                errorCode: CONSTANTS.INTERNAL_SERVER_ERROR
            });
        }
    };

}

export default new authController();