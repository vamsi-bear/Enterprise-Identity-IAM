import speakeasy from "speakeasy";
import QRCode from "qrcode";
import jwt from "jsonwebtoken";
import crypto from "crypto";

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


        // Newly generated MFA secret must be verified first
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


        return res.status(200).json({

            success: true,

            message: "MFA setup generated successfully",

            qrCode,

            // Manual setup fallback
            secret
        });


    } catch (error) {

        console.error(
            "❌ MFA setup error:",
            error
        );

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


        console.log(
            "🔐 TOTP verification:",
            verified
        );


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


        // ------------------------------------------------------
        // Enable MFA
        // ------------------------------------------------------

        await pool.query(
            `
            UPDATE users
            SET mfa_enabled = TRUE
            WHERE id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Audit success
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
// Uses temporary MFA JWT
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
            authHeader.substring(7).trim();


        // ------------------------------------------------------
        // Verify temporary JWT
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


        // ------------------------------------------------------
        // Make sure this is actually an MFA pending token
        // ------------------------------------------------------

        if (decoded.mfaPending !== true) {

            return res.status(401).json({
                success: false,
                message: "Invalid MFA session"
            });
        }


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
        // Verify TOTP
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
                    email: decoded.email,
                    reason: "INVALID_TOTP"
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
        // Generate FINAL JWT
        // ------------------------------------------------------

        const finalToken =
            jwt.sign(

                {
                    userId: user.id,

                    email: user.email,

                    username: user.username,

                    mfaVerified: true
                },

                process.env.JWT_SECRET,

                {
                    expiresIn:
                        process.env.JWT_EXPIRES_IN || "1h"
                }
            );


        // ------------------------------------------------------
        // Audit success
        // ------------------------------------------------------

        await logAudit({

            userId: user.id,

            action: "MFA_LOGIN_VERIFY",

            resource: "MFA",

            resourceId: user.id,

            result: "SUCCESS",

            riskLevel: "LOW",

            ipAddress: req.ip,

            userAgent: req.get("user-agent"),

            metadata: {
                email: user.email,
                method: "TOTP"
            }
        });


        return res.status(200).json({

            success: true,

            message:
                "MFA verification successful",

            token: finalToken,

            user: {

                id: user.id,

                username: user.username,

                email: user.email,

                firstName: user.first_name,

                lastName: user.last_name
            }
        });


    } catch (error) {

        console.error(
            "❌ MFA login verification error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to verify MFA login"
        });
    }
};


// ============================================================
// GENERATE BACKUP CODES
// POST /api/mfa/backup-codes
// ============================================================

export const generateBackupCodes = async (req, res) => {

    try {

        const userId = req.user?.id;

        if (!userId) {

            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }


        // ------------------------------------------------------
        // Check user
        // ------------------------------------------------------

        const userResult = await pool.query(
            `
            SELECT
                id,
                email,
                mfa_enabled
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


        const user = userResult.rows[0];


        // ------------------------------------------------------
        // MFA must already be enabled
        // ------------------------------------------------------

        if (!user.mfa_enabled) {

            return res.status(400).json({
                success: false,
                message:
                    "Enable and verify MFA before generating backup codes"
            });
        }


        // ------------------------------------------------------
        // Generate 10 random backup codes
        // ------------------------------------------------------

        const backupCodes = [];

        for (let i = 0; i < 10; i++) {

            const code =
                crypto
                    .randomBytes(5)
                    .toString("hex")
                    .toUpperCase();

            backupCodes.push(code);
        }


        // ------------------------------------------------------
        // Replace old backup codes
        // ------------------------------------------------------

        await pool.query(
            `
            DELETE FROM backup_codes
            WHERE user_id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Store only SHA-256 hashes
        // ------------------------------------------------------

        for (const code of backupCodes) {

            const codeHash =
                crypto
                    .createHash("sha256")
                    .update(code)
                    .digest("hex");

            await pool.query(
                `
                INSERT INTO backup_codes
                (
                    user_id,
                    code_hash,
                    used
                )
                VALUES ($1, $2, FALSE)
                `,
                [
                    userId,
                    codeHash
                ]
            );
        }


        // ------------------------------------------------------
        // Audit
        // ------------------------------------------------------

        await logAudit({

            userId,

            action: "BACKUP_CODES_GENERATE",

            resource: "MFA",

            resourceId: userId,

            result: "SUCCESS",

            riskLevel: "MEDIUM",

            ipAddress: req.ip,

            userAgent: req.get("user-agent"),

            metadata: {
                email: user.email,
                count: backupCodes.length
            }
        });


        // ------------------------------------------------------
        // Return plaintext codes ONLY NOW
        // ------------------------------------------------------

        return res.status(200).json({

            success: true,

            message:
                "Backup codes generated successfully",

            backupCodes,

            count: backupCodes.length
        });


    } catch (error) {

        console.error(
            "❌ Backup code generation error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to generate backup codes"
        });
    }
};


// ============================================================
// VERIFY BACKUP CODE DURING LOGIN
// POST /api/mfa/verify-backup
// ============================================================

export const verifyBackupCode = async (req, res) => {

    try {

        const { code } = req.body;

        const userId =
            req.user?.id ||
            req.user?.userId;


        // ------------------------------------------------------
        // Validate MFA session
        // ------------------------------------------------------

        if (!userId) {

            return res.status(401).json({
                success: false,
                message: "Invalid MFA session"
            });
        }


        // ------------------------------------------------------
        // Validate code
        // ------------------------------------------------------

        if (
            !code ||
            typeof code !== "string"
        ) {

            return res.status(400).json({
                success: false,
                message: "Backup code is required"
            });
        }


        const normalizedCode =
            code.trim().toUpperCase();


        if (!normalizedCode) {

            return res.status(400).json({
                success: false,
                message: "Backup code is required"
            });
        }


        // ------------------------------------------------------
        // Hash submitted code
        // ------------------------------------------------------

        const codeHash =
            crypto
                .createHash("sha256")
                .update(normalizedCode)
                .digest("hex");


        // ------------------------------------------------------
        // Find unused backup code
        // ------------------------------------------------------

        const codeResult =
            await pool.query(
                `
                SELECT
                    id
                FROM backup_codes
                WHERE user_id = $1
                  AND code_hash = $2
                  AND used = FALSE
                LIMIT 1
                `,
                [
                    userId,
                    codeHash
                ]
            );


        // ------------------------------------------------------
        // Invalid / already used
        // ------------------------------------------------------

        if (codeResult.rows.length === 0) {

            try {

                await logAudit({

                    userId,

                    action:
                        "BACKUP_CODE_VERIFY",

                    resource:
                        "MFA",

                    resourceId:
                        userId,

                    result:
                        "FAILURE",

                    riskLevel:
                        "HIGH",

                    ipAddress:
                        req.ip,

                    userAgent:
                        req.get("user-agent"),

                    metadata: {
                        reason:
                            "INVALID_OR_USED_BACKUP_CODE"
                    }
                });

            } catch (auditError) {

                console.error(
                    "Audit logging error:",
                    auditError
                );
            }


            return res.status(401).json({

                success: false,

                message:
                    "Invalid or already used backup code"
            });
        }


        const backupCodeId =
            codeResult.rows[0].id;


        // ------------------------------------------------------
        // Mark code as used
        // ------------------------------------------------------

        const updateResult =
            await pool.query(
                `
                UPDATE backup_codes
                SET
                    used = TRUE,
                    used_at = CURRENT_TIMESTAMP
                WHERE id = $1
                  AND used = FALSE
                `,
                [backupCodeId]
            );


        // ------------------------------------------------------
        // Prevent race condition
        // ------------------------------------------------------

        if (updateResult.rowCount !== 1) {

            return res.status(401).json({

                success: false,

                message:
                    "Backup code has already been used"
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
        // Generate FINAL JWT
        // Same structure as TOTP login
        // ------------------------------------------------------

        const token =
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


        // ------------------------------------------------------
        // Count remaining backup codes
        // ------------------------------------------------------

        const remainingResult =
            await pool.query(
                `
                SELECT
                    COUNT(*)::int AS remaining
                FROM backup_codes
                WHERE user_id = $1
                  AND used = FALSE
                `,
                [userId]
            );


        const remainingCodes =
            remainingResult.rows[0].remaining;


        // ------------------------------------------------------
        // Audit success
        // ------------------------------------------------------

        try {

            await logAudit({

                userId,

                action:
                    "BACKUP_CODE_VERIFY",

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
                        user.email,

                    method:
                        "BACKUP_CODE",

                    remainingCodes
                }
            });

        } catch (auditError) {

            console.error(
                "Audit logging error:",
                auditError
            );
        }


        // ------------------------------------------------------
        // Success
        // ------------------------------------------------------

        return res.status(200).json({

            success: true,

            message:
                "Backup code verified successfully",

            token,

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
            },

            remainingBackupCodes:
                remainingCodes
        });


    } catch (error) {

        console.error(
            "❌ Backup code verification error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to verify backup code"
        });
    }
};


// ============================================================
// DISABLE MFA
// DELETE /api/mfa/disable
// ============================================================

export const disableMFA = async (req, res) => {

    try {

        const userId =
            req.user.id;


        // ------------------------------------------------------
        // Check MFA
        // ------------------------------------------------------

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


        // ------------------------------------------------------
        // Delete MFA credentials
        // ------------------------------------------------------

        await pool.query(
            `
            DELETE FROM mfa_credentials
            WHERE user_id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Disable MFA
        // ------------------------------------------------------

        await pool.query(
            `
            UPDATE users
            SET mfa_enabled = FALSE
            WHERE id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Delete backup codes
        // ------------------------------------------------------

        await pool.query(
            `
            DELETE FROM backup_codes
            WHERE user_id = $1
            `,
            [userId]
        );


        // ------------------------------------------------------
        // Audit
        // ------------------------------------------------------

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