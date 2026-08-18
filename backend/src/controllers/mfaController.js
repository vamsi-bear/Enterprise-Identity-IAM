import speakeasy from "speakeasy";
import QRCode from "qrcode";
import jwt from "jsonwebtoken";

import pool from "../config/database.js";
import { logAudit } from "../utils/auditLogger.js";


// ============================================================
// SETUP MFA
// ============================================================

export const setupMFA = async (req, res) => {

    try {

        const userId =
            req.user.id;


        const generatedSecret =
            speakeasy.generateSecret({

                name:
                    `SecureSphere IAM (${req.user.email || "User"})`,

                issuer:
                    "SecureSphere IAM",

                length:
                    32
            });


        const secret =
            generatedSecret.base32;


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
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5
            )

            ON CONFLICT (user_id)

            DO UPDATE SET

                secret_encrypted =
                    EXCLUDED.secret_encrypted,

                algorithm =
                    EXCLUDED.algorithm,

                digits =
                    EXCLUDED.digits,

                period =
                    EXCLUDED.period
            `,
            [
                userId,
                secret,
                "SHA1",
                6,
                30
            ]
        );


        const qrCode =
            await QRCode.toDataURL(
                generatedSecret.otpauth_url
            );


        await logAudit({

            userId,

            action:
                "MFA_SETUP",

            resource:
                "MFA",

            resourceId:
                userId,

            result:
                "SUCCESS",

            riskLevel:
                "MEDIUM",

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
                "MFA setup generated successfully",

            qrCode,

            secret

        });


    } catch (error) {

        console.error(
            "MFA setup error:",
            error
        );


        return res.status(500).json({

            success: false,

            message:
                "Unable to setup MFA"

        });

    }

};


// ============================================================
// VERIFY MFA
// ============================================================

export const verifyMFA = async (req, res) => {

    try {

        const {
            token: mfaCode
        } = req.body;


        const userId =
            req.user.id;


        console.log(
            "🔐 MFA verification started:",
            {
                userId,
                email: req.user.email,
                mfaCodeLength:
                    mfaCode
                        ? String(mfaCode).length
                        : 0
            }
        );


        // ====================================================
        // VALIDATE CODE
        // ====================================================

        if (
            !mfaCode ||
            !/^\d{6}$/.test(String(mfaCode))
        ) {

            await logAudit({

                userId,

                action:
                    "MFA_VERIFY",

                resource:
                    "MFA",

                resourceId:
                    userId,

                result:
                    "FAILURE",

                riskLevel:
                    "MEDIUM",

                ipAddress:
                    req.ip,

                userAgent:
                    req.get("user-agent"),

                metadata: {
                    email:
                        req.user.email,

                    reason:
                        "INVALID_FORMAT"
                }

            });


            return res.status(400).json({

                success: false,

                message:
                    "MFA code must contain exactly 6 digits"

            });

        }


        // ====================================================
        // GET MFA CREDENTIALS
        // ====================================================

        const result =
            await pool.query(
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

                message:
                    "MFA is not configured"

            });

        }


        const mfa =
            result.rows[0];


        console.log(
            "🔐 MFA configuration found:",
            {
                userId,
                algorithm:
                    mfa.algorithm,
                digits:
                    mfa.digits,
                period:
                    mfa.period
            }
        );


        // ====================================================
        // VERIFY TOTP
        // ====================================================

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

                window:
                    1
            });


        console.log(
            "🔐 TOTP verified:",
            verified
        );


        // ====================================================
        // INVALID MFA CODE
        // ====================================================

        if (!verified) {

            await logAudit({

                userId,

                action:
                    "MFA_VERIFY",

                resource:
                    "MFA",

                resourceId:
                    userId,

                result:
                    "FAILURE",

                riskLevel:
                    "MEDIUM",

                ipAddress:
                    req.ip,

                userAgent:
                    req.get("user-agent"),

                metadata: {
                    email:
                        req.user.email,

                    reason:
                        "INVALID_TOTP"
                }

            });


            return res.status(401).json({

                success: false,

                message:
                    "Invalid MFA code"

            });

        }


        // ====================================================
        // UPDATE LAST USED
        // ====================================================

        await pool.query(
            `
            UPDATE mfa_credentials
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
            `,
            [userId]
        );


        // ====================================================
        // GET USER
        // ====================================================

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

                message:
                    "User not found"

            });

        }


        const user =
            userResult.rows[0];


        // ====================================================
        // CHECK ACCOUNT
        // ====================================================

        if (!user.is_active) {

            return res.status(403).json({

                success: false,

                message:
                    "Account is disabled"

            });

        }


        if (user.is_locked) {

            return res.status(403).json({

                success: false,

                message:
                    "Account is locked"

            });

        }


        // ====================================================
        // GENERATE FINAL JWT
        // ====================================================

        const finalToken =
            jwt.sign(

                {
                    userId:
                        user.id,

                    email:
                        user.email,

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
            "✅ FINAL JWT GENERATED"
        );


        // ====================================================
        // SUCCESS AUDIT
        // ====================================================

        await logAudit({

            userId:
                user.id,

            action:
                "MFA_VERIFY",

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


        // ====================================================
        // RETURN FINAL TOKEN
        // ====================================================

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
            "MFA verification error:",
            error
        );


        return res.status(500).json({

            success: false,

            message:
                "Unable to verify MFA"

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
            "MFA disable error:",
            error
        );


        return res.status(500).json({

            success: false,

            message:
                "Unable to disable MFA"

        });

    }

};