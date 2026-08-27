import jwt from "jsonwebtoken";
import pool from "../config/database.js";


// ============================================================
// NORMAL AUTHENTICATION
// ============================================================

export const authenticate = (req, res, next) => {

    try {

        const authHeader =
            req.headers.authorization;

        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {

            return res.status(401).json({
                success: false,
                message: "Authentication token required"
            });

        }

        const token =
            authHeader.substring(7).trim();

        if (!token) {

            return res.status(401).json({
                success: false,
                message: "Authentication token required"
            });

        }

        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );

        console.log(
            "🔐 JWT decoded:",
            decoded
        );


        req.user = {

            id:
                decoded.id ||
                decoded.userId ||
                decoded.user_id,

            email:
                decoded.email,

            username:
                decoded.username || null,

            mfaVerified:
                decoded.mfaVerified || false,

            mfaPending:
                decoded.mfaPending || false
        };


        if (!req.user.id) {

            return res.status(401).json({
                success: false,
                message: "User ID missing from authentication token"
            });

        }


        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error
        );

        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token"
        });

    }

};


// ============================================================
// MFA AUTHENTICATION
// ============================================================

export const authenticateMfa = (req, res, next) => {

    try {

        const authHeader =
            req.headers.authorization;


        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {

            return res.status(401).json({
                success: false,
                message: "MFA authentication token required"
            });

        }


        const token =
            authHeader.substring(7).trim();


        if (!token) {

            return res.status(401).json({
                success: false,
                message: "MFA authentication token required"
            });

        }


        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );


        console.log(
            "🔐 MFA JWT decoded:",
            decoded
        );


        /*
         * MFA verification must use the temporary
         * MFA token generated during login.
         */

        if (decoded.mfaPending !== true) {

            return res.status(401).json({
                success: false,
                message: "Invalid MFA session"
            });

        }


        req.user = {

            id:
                decoded.id ||
                decoded.userId ||
                decoded.user_id,

            email:
                decoded.email,

            username:
                decoded.username || null,

            mfaPending: true
            
        };


        if (!req.user.id) {

            return res.status(401).json({
                success: false,
                message: "User ID missing from MFA token"
            });

        }


        console.log(
            "🔐 MFA session authenticated:",
            req.user
        );


        next();

    } catch (error) {

        console.error(
            "MFA authentication error:",
            error
        );


        if (error.name === "TokenExpiredError") {

            return res.status(401).json({
                success: false,
                message: "MFA authentication token expired"
            });

        }


        return res.status(401).json({
            success: false,
            message: "Invalid MFA authentication token"
        });

    }

};


// ============================================================
// RBAC AUTHORIZATION
// ============================================================

export const authorize = (requiredPermission) => {

    return async (req, res, next) => {

        try {

            if (!req.user || !req.user.id) {

                return res.status(401).json({
                    success: false,
                    message: "Authentication required"
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT EXISTS (
                        SELECT 1
                        FROM user_roles ur

                        JOIN role_permissions rp
                            ON rp.role_id = ur.role_id

                        JOIN permissions p
                            ON p.id = rp.permission_id

                        WHERE ur.user_id = $1

                        AND p.name = $2
                    ) AS allowed
                    `,
                    [
                        req.user.id,
                        requiredPermission
                    ]
                );


            const allowed =
                result.rows[0].allowed;


            console.log(
                `🔐 RBAC: ${req.user.email} → ${requiredPermission} → ${allowed}`
            );


            if (!allowed) {

                return res.status(403).json({

                    success: false,

                    message: "Access denied",

                    requiredPermission

                });

            }


            next();

        } catch (error) {

            console.error(
                "Authorization error:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to verify permissions"

            });

        }

    };

};