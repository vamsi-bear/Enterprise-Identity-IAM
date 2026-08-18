
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import pool from "../config/database.js";
import { logAudit } from "../utils/auditLogger.js";

// ============================================
// REGISTER
// ============================================

export const register = async (req, res) => {

    try {

        const {
            username,
            email,
            password,
            firstName,
            lastName
        } = req.body;

        // -------------------------------
        // Validation
        // -------------------------------

        if (!username || !email || !password) {

            return res.status(400).json({
                success: false,
                message: "Username, email and password are required"
            });

        }

        if (password.length < 8) {

            return res.status(400).json({
                success: false,
                message: "Password must contain at least 8 characters"
            });

        }

        // -------------------------------
        // Check existing user
        // -------------------------------

        const existingUser = await pool.query(
            `
            SELECT id
            FROM users
            WHERE email = $1
               OR username = $2
            `,
            [email, username]
        );

        if (existingUser.rows.length > 0) {

            return res.status(409).json({
                success: false,
                message: "Username or email already exists"
            });

        }

        // -------------------------------
        // Hash password
        // -------------------------------

        const passwordHash = await bcrypt.hash(password, 12);

        // -------------------------------
        // Create user
        // -------------------------------

        const result = await pool.query(
            `
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                first_name,
                last_name
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id,
                username,
                email,
                first_name,
                last_name,
                created_at
            `,
            [
                username,
                email,
                passwordHash,
                firstName || null,
                lastName || null
            ]
        );

        const user = result.rows[0];

        // -------------------------------
        // Audit registration
        // -------------------------------

        await logAudit({
            userId: user.id,
            action: "USER_REGISTER",
            resource: "USER",
            resourceId: user.id,
            result: "SUCCESS",
            riskLevel: "LOW",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                username: user.username,
                email: user.email
            }
        });

        // -------------------------------
        // Response
        // -------------------------------

        return res.status(201).json({

            success: true,

            message: "User registered successfully",

            user

        });

    } catch (error) {

        console.error("Registration error:", error);

        return res.status(500).json({

            success: false,

            message: "Internal server error"

        });

    }

};


// ============================================
// LOGIN
// ============================================

export const login = async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        // -------------------------------
        // Validation
        // -------------------------------

        if (!email || !password) {

            return res.status(400).json({

                success: false,

                message: "Email and password are required"

            });

        }

        // -------------------------------
        // Find user
        // -------------------------------

        const result = await pool.query(
            `
            SELECT *
            FROM users
            WHERE email = $1
            `,
            [email]
        );

        if (result.rows.length === 0) {

            await logAudit({
                userId: null,
                action: "LOGIN_FAILED",
                resource: "AUTHENTICATION",
                resourceId: null,
                result: "FAILURE",
                riskLevel: "MEDIUM",
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
                metadata: {
                    email,
                    reason: "USER_NOT_FOUND"
                }
            });

            return res.status(401).json({

                success: false,

                message: "Invalid email or password"

            });

        }

        const user = result.rows[0];

        // -------------------------------
        // Account status
        // -------------------------------

        if (!user.is_active) {

            await logAudit({
                userId: user.id,
                action: "LOGIN_BLOCKED",
                resource: "AUTHENTICATION",
                resourceId: user.id,
                result: "FAILURE",
                riskLevel: "HIGH",
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
                metadata: {
                    email: user.email,
                    reason: "ACCOUNT_DISABLED"
                }
            });

            return res.status(403).json({

                success: false,

                message: "Account is disabled"

            });

        }

        if (user.is_locked) {

            await logAudit({
                userId: user.id,
                action: "LOGIN_BLOCKED",
                resource: "AUTHENTICATION",
                resourceId: user.id,
                result: "FAILURE",
                riskLevel: "HIGH",
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
                metadata: {
                    email: user.email,
                    reason: "ACCOUNT_LOCKED"
                }
            });

            return res.status(403).json({

                success: false,

                message: "Account is locked"

            });

        }

        // -------------------------------
        // Verify password
        // -------------------------------

        const passwordValid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordValid) {

            await pool.query(
                `
                UPDATE users
                SET failed_login_attempts =
                    failed_login_attempts + 1
                WHERE id = $1
                `,
                [user.id]
            );

            await logAudit({
                userId: user.id,
                action: "LOGIN_FAILED",
                resource: "AUTHENTICATION",
                resourceId: user.id,
                result: "FAILURE",
                riskLevel: "MEDIUM",
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
                metadata: {
                    email: user.email,
                    reason: "INVALID_PASSWORD"
                }
            });

            return res.status(401).json({

                success: false,

                message: "Invalid email or password"

            });

        }

        // -------------------------------
        // Check MFA
        // -------------------------------

        const mfaResult = await pool.query(
            `
            SELECT user_id
            FROM mfa_credentials
            WHERE user_id = $1
            `,
            [user.id]
        );

        const mfaEnabled = mfaResult.rows.length > 0;

        // -------------------------------
        // MFA REQUIRED
        // -------------------------------

        if (mfaEnabled) {

            /*
             * This token is NOT the final authentication token.
             * It only allows the user to complete MFA.
             */

            const mfaToken = jwt.sign(

                {
                    userId: user.id,
                    email: user.email,
                    mfaPending: true
                },

                process.env.JWT_SECRET,

                {
                    expiresIn: "5m"
                }

            );

            await logAudit({
                userId: user.id,
                action: "LOGIN_MFA_REQUIRED",
                resource: "AUTHENTICATION",
                resourceId: user.id,
                result: "SUCCESS",
                riskLevel: "MEDIUM",
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
                metadata: {
                    email: user.email
                }
            });

            return res.status(200).json({

                success: true,

                mfaRequired: true,

                message: "MFA verification required",

                mfaToken

            });

        }

        // -------------------------------
        // No MFA
        // -------------------------------

        await pool.query(
            `
            UPDATE users
            SET
                failed_login_attempts = 0,
                last_login_at = CURRENT_TIMESTAMP
            WHERE id = $1
            `,
            [user.id]
        );

        // -------------------------------
        // Generate final JWT
        // -------------------------------

        const token = jwt.sign(

            {
                userId: user.id,
                email: user.email,
                mfaVerified: false
            },

            process.env.JWT_SECRET,

            {
                expiresIn: process.env.JWT_EXPIRES_IN || "1h"
            }

        );
console.log("========== LOGIN DEBUG ==========");
console.log("USER:", user);
console.log("TOKEN:", token);
console.log("TOKEN EXISTS:", !!token);
console.log("=================================");
        // -------------------------------
        // Audit successful login
        // -------------------------------

        await logAudit({
            userId: user.id,
            action: "LOGIN",
            resource: "AUTHENTICATION",
            resourceId: user.id,
            result: "SUCCESS",
            riskLevel: "LOW",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                email: user.email,
                mfa: false
            }
        });

        // -------------------------------
        // Response
        // -------------------------------

        return res.json({

            success: true,

            mfaRequired: false,

            message: "Login successful",

            token,

            user: {

                id: user.id,

                username: user.username,

                email: user.email,

                firstName: user.first_name,

                lastName: user.last_name

            }

        });

    } catch (error) {

        console.error("Login error:", error);

        return res.status(500).json({

            success: false,

            message: "Internal server error"

        });

    }

};
