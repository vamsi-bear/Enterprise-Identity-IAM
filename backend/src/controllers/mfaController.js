
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import jwt from "jsonwebtoken";

import pool from "../config/database.js";
import { logAudit } from "../utils/auditLogger.js";


// ============================================================
// SETUP MFA + GENERATE QR CODE
// ============================================================

export const setupMFA = async (req, res) => {

    try {

        const userId = req.user.id;


        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "User authentication required"
            });
        }

        console.log("🔐 Starting MFA setup for:", {
            userId,
            email: req.user.email
        });


        // ------------------------------------------------------
        // Generate TOTP secret
        // ------------------------------------------------------

        const generatedSecret = speakeasy.generateSecret({
            name: `SecureSphere IAM (${req.user.email || "User"})`,
            issuer: "SecureSphere IAM",
            length: 32
        });

        const secret = generatedSecret.base32;


        // ------------------------------------------------------
        // Store MFA secret
        // ------------------------------------------------------

        await pool.query(
            `
            INSERT INTO mfa_credentials
            (
                user_id,
                secret_encrypted,
                algorithm,
                digits,
                period
            )
            VALUES ($1, $2, $3, $4, $5)

            ON CONFLICT (user_id)

            DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                algorithm = EXCLUDED.algorithm,
                digits = EXCLUDED.digits,
                period = EXCLUDED.period
            `,
            [
                userId,
                secret,
                "SHA1",
                6,
                30
            ]
        );

        // A newly generated secret is pending until the user proves that
        // their authenticator app can generate a valid TOTP code for it.
        await pool.query(
            `
            UPDATE users
            SET mfa_enabled = FALSE
            WHERE id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Generate QR code
        // ------------------------------------------------------

        const qrCode = await QRCode.toDataURL(
            generatedSecret.otpauth_url
        );


        console.log("✅ MFA QR code generated");


        // ------------------------------------------------------
        // Audit
        // ------------------------------------------------------

        await logAudit({
            userId,
            action: "MFA_SETUP",
            resource: "MFA",
            resourceId: userId,
            result: "SUCCESS",
            riskLevel: "MEDIUM",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                email: req.user.email
            }
        });


        // ------------------------------------------------------
        // Return QR code
        // ------------------------------------------------------

        return res.status(200).json({

            success: true,

            message: "MFA setup generated successfully",

            qrCode,

            // Useful for manual setup if QR scanning fails
            secret

        });


    } catch (error) {

        console.error("❌ MFA setup error:", error);

        return res.status(500).json({

            success: false,

            message: "Unable to setup MFA"

        });

    }

};



// ============================================================
// VERIFY MFA FOR ALREADY AUTHENTICATED USER
// ============================================================

export const verifyMFA = async (req, res) => {

    try {

        const { token: mfaCode } = req.body;

        const userId = req.user.id;


        if (!userId) {

            return res.status(401).json({

                success: false,

                message: "User authentication required"

            });

        }


        console.log("🔐 MFA verification started:", {

            userId,

            email: req.user.email,

            codeLength:
                mfaCode
                    ? String(mfaCode).length
                    : 0

        });


        // ------------------------------------------------------
        // Validate MFA code
        // ------------------------------------------------------

        if (
            !mfaCode ||
            !/^\d{6}$/.test(String(mfaCode))
        ) {

            return res.status(400).json({

                success: false,

                message: "MFA code must contain exactly 6 digits"

            });

        }


        // ------------------------------------------------------
        // Get MFA credentials
        // ------------------------------------------------------

        const result = await pool.query(
            `
            SELECT
                secret_encrypted,
                algorithm,
                digits,
                period
            FROM mfa_credentials
            WHERE user_id = $1
            `,
            [userId]
        );


        if (result.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message: "MFA is not configured"

            });

        }


        const mfa = result.rows[0];


        // ------------------------------------------------------
        // Verify TOTP
        // ------------------------------------------------------

        const verified = speakeasy.totp.verify({

            secret: mfa.secret_encrypted,

            encoding: "base32",

            token: String(mfaCode),

            algorithm:
                mfa.algorithm || "SHA1",

            digits:
                Number(mfa.digits) || 6,

            step:
                Number(mfa.period) || 30,

            window: 1

        });


        console.log("🔐 TOTP verification:", verified);


        if (!verified) {

            await logAudit({

                userId,

                action: "MFA_VERIFY",

                resource: "MFA",

                resourceId: userId,

                result: "FAILURE",

                riskLevel: "MEDIUM",

                ipAddress: req.ip,

                userAgent: req.get("user-agent"),

                metadata: {

                    email: req.user.email,

                    reason: "INVALID_TOTP"

                }

            });


            return res.status(401).json({

                success: false,

                message: "Invalid MFA code"

            });

        }


        // ------------------------------------------------------
        // Update last used
        // ------------------------------------------------------

        await pool.query(
            `
            UPDATE mfa_credentials
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
            `,
            [userId]
        );

        await pool.query(
            `
            UPDATE users
            SET mfa_enabled = TRUE
            WHERE id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Audit successful verification
        // ------------------------------------------------------

        await logAudit({

            userId,

            action: "MFA_VERIFY",

            resource: "MFA",

            resourceId: userId,

            result: "SUCCESS",

            riskLevel: "LOW",

            ipAddress: req.ip,

            userAgent: req.get("user-agent"),

            metadata: {

                email: req.user.email

            }

        });


        return res.status(200).json({

            success: true,

            message: "MFA verification successful"

        });


    } catch (error) {

        console.error(
            "❌ MFA verification error:",
            error
        );

        return res.status(500).json({

            success: false,

            message: "Unable to verify MFA"

        });

    }

};



// ============================================================
// VERIFY MFA DURING LOGIN
//
// Uses temporary mfaToken
// Generates FINAL JWT
// ============================================================

export const verifyLoginMFA = async (req, res) => {

    try {

        const { token: mfaCode } = req.body;


        // ------------------------------------------------------
        // Get temporary MFA JWT
        // ------------------------------------------------------

        const authHeader =
            req.headers.authorization;


        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {

            return res.status(401).json({

                success: false,

                message: "MFA login token is required"

            });

        }


        const mfaToken =
            authHeader.split(" ")[1];


        console.log(
            "🔐 MFA login token received:",
            !!mfaToken
        );


        // ------------------------------------------------------
        // Verify temporary MFA JWT
        // ------------------------------------------------------

        let decoded;

        try {

            decoded = jwt.verify(
                mfaToken,
                process.env.JWT_SECRET
            );

        } catch (error) {

            console.error(
                "❌ Invalid MFA login token:",
                error.message
            );

            return res.status(401).json({

                success: false,

                message: "Invalid or expired MFA login token"

            });

        }


        console.log(
            "🔐 MFA token decoded:",
            decoded
        );


        // ------------------------------------------------------
        // Get user ID
        // ------------------------------------------------------

        const userId =
            decoded.userId ||
            decoded.id ||
            decoded.user_id;


        if (!userId) {

            return res.status(401).json({

                success: false,

                message: "Invalid MFA token: user ID missing"

            });

        }


        // ------------------------------------------------------
        // Validate MFA code
        // ------------------------------------------------------

        if (
            !mfaCode ||
            !/^\d{6}$/.test(String(mfaCode))
        ) {

            return res.status(400).json({

                success: false,

                message: "MFA code must contain exactly 6 digits"

            });

        }


        // ------------------------------------------------------
        // Get MFA credentials
        // ------------------------------------------------------

        const mfaResult = await pool.query(
            `
            SELECT
                secret_encrypted,
                algorithm,
                digits,
                period
            FROM mfa_credentials
            WHERE user_id = $1
            `,
            [userId]
        );


        if (mfaResult.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message: "MFA is not configured"

            });

        }


        const mfa =
            mfaResult.rows[0];


        // ------------------------------------------------------
        // Verify TOTP code
        // ------------------------------------------------------

        const verified =
            speakeasy.totp.verify({

                secret:
                    mfa.secret_encrypted,

                encoding:
                    "base32",

                token:
                    String(mfaCode),

                algorithm:
                    mfa.algorithm || "SHA1",

                digits:
                    Number(mfa.digits) || 6,

                step:
                    Number(mfa.period) || 30,

                window: 1

            });


        console.log(
            "🔐 Login MFA TOTP verified:",
            verified
        );


        if (!verified) {

            await logAudit({

                userId,

                action: "MFA_LOGIN_VERIFY",

                resource: "MFA",

                resourceId: userId,

                result: "FAILURE",

                riskLevel: "MEDIUM",

                ipAddress: req.ip,

                userAgent: req.get("user-agent"),

                metadata: {

                    email:
                        decoded.email,

                    reason:
                        "INVALID_TOTP"

                }

            });


            return res.status(401).json({

                success: false,

                message: "Invalid MFA code"

            });

        }


        // ------------------------------------------------------
        // Get user
        // ------------------------------------------------------

        const userResult =
            await pool.query(
                `
                SELECT
                    id,
                    username,
                    email,
                    first_name,
                    last_name,
                    is_active,
                    is_locked
                FROM users
                WHERE id = $1
                `,
                [userId]
            );


        if (userResult.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message: "User not found"

            });

        }


        const user =
            userResult.rows[0];


        // ------------------------------------------------------
        // Check account
        // ------------------------------------------------------

        if (!user.is_active) {

            return res.status(403).json({

                success: false,

                message: "Account is disabled"

            });

        }


        if (user.is_locked) {

            return res.status(403).json({

                success: false,

                message: "Account is locked"

            });

        }


        // ------------------------------------------------------
        // Update MFA last used
        // ------------------------------------------------------

        await pool.query(
            `
            UPDATE mfa_credentials
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // GENERATE FINAL JWT
        // ------------------------------------------------------

        const finalToken =
            jwt.sign(

                {
                    userId:
                        user.id,

                    email:
                        req.user.email,

                    username:
                        user.username,

                    mfaVerified:
                        true
                },

                process.env.JWT_SECRET,

                {
                    expiresIn:
                        process.env.JWT_EXPIRES_IN || "1h"
                }

            );


        console.log(
            "========================================"
        );

        console.log(
            "✅ FINAL JWT GENERATED"
        );

        console.log(
            "User:",
            req.user.email
        );

        console.log(
            "JWT exists:",
            !!finalToken
        );

        console.log(
            "========================================"
        );


        // ------------------------------------------------------
        // Audit
        // ------------------------------------------------------

        await logAudit({

            userId:
                user.id,

            action:
                "MFA_LOGIN_VERIFY",

            resource:
                "MFA",

            resourceId:
                user.id,

            result:
                "SUCCESS",

            riskLevel:
                "LOW",

            ipAddress:
                req.ip,

            userAgent:
                req.get("user-agent"),

            metadata: {

                email:
                    user.email

            }

        });


        // ------------------------------------------------------
        // RETURN FINAL JWT
        // ------------------------------------------------------

        return res.status(200).json({

            success: true,

            message:
                "MFA verification successful",

            token:
                finalToken,

            user: {

                id:
                    user.id,

                username:
                    user.username,

                email:
                    user.email,

                firstName:
                    user.first_name,

                lastName:
                    user.last_name

            }

        });


    } catch (error) {

        console.error(
            "❌ MFA login verification error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to verify MFA login"

        });

    }

};



// ============================================================
// DISABLE MFA
// ============================================================

export const disableMFA = async (req, res) => {

    try {

        const userId =
            req.user.id;


        const existingMFA =
            await pool.query(
                `
                SELECT user_id
                FROM mfa_credentials
                WHERE user_id = $1
                `,
                [userId]
            );


        if (existingMFA.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message:
                    "MFA is not configured"

            });

        }


        await pool.query(
            `
            DELETE FROM mfa_credentials
            WHERE user_id = $1
            `,
            [userId]
        );

        await pool.query(
            `
            UPDATE users
            SET mfa_enabled = FALSE
            WHERE id = $1
            `,
            [userId]
        );


        await logAudit({

            userId,

            action:
                "MFA_DISABLE",

            resource:
                "MFA",

            resourceId:
                userId,

            result:
                "SUCCESS",

            riskLevel:
                "HIGH",

            ipAddress:
                req.ip,

            userAgent:
                req.get("user-agent"),

            metadata: {

                email:
                    req.user.email

            }

        });


        return res.status(200).json({

            success: true,

            message:
                "MFA disabled successfully"

        });


    } catch (error) {

        console.error(
            "❌ MFA disable error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to disable MFA"

        });

    }

};
