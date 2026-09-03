import pool from "../config/database.js";
import bcrypt from "bcryptjs";
import { logAudit } from "../utils/auditLogger.js";

// ========================================
// GET CURRENT USER
// GET /api/users/me
// ========================================

export const getCurrentUser = async (req, res) => {
    try {
        const userId = req.user.id;

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.username,
                u.email,

                COALESCE(
                    (
                        SELECT r.name
                        FROM user_roles ur2
                        JOIN roles r
                            ON r.id = ur2.role_id
                        WHERE ur2.user_id = u.id
                        ORDER BY r.name
                        LIMIT 1
                    ),
                    'EMPLOYEE'
                ) AS role,

                u.mfa_enabled AS "mfaEnabled",

                COALESCE(
                    (
                        SELECT json_agg(DISTINCT p.name)
                        FROM user_roles ur3
                        JOIN role_permissions rp
                            ON rp.role_id = ur3.role_id
                        JOIN permissions p
                            ON p.id = rp.permission_id
                        WHERE ur3.user_id = u.id
                    ),
                    '[]'
                ) AS permissions

            FROM users u

            WHERE u.id = $1
            `,
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user = result.rows[0];

        return res.json({
            success: true,

            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                permissions: user.permissions,
                mfaEnabled: user.mfaEnabled
            }
        });

    } catch (error) {
        console.error(
            "Get current user error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to load user"
        });
    }
};


// ========================================
// GET ALL USERS
// GET /api/users
// ========================================

export const getAllUsers = async (req, res) => {
    try {

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.username,
                u.email,
                u.first_name AS "firstName",
                u.last_name AS "lastName",
                u.created_at AS "createdAt",

                COALESCE(
                    (
                        SELECT r.name
                        FROM user_roles ur2
                        JOIN roles r
                            ON r.id = ur2.role_id
                        WHERE ur2.user_id = u.id
                        ORDER BY r.name
                        LIMIT 1
                    ),
                    'EMPLOYEE'
                ) AS role

            FROM users u

            ORDER BY u.created_at DESC
            `
        );

        return res.json({
            success: true,
            users: result.rows
        });

    } catch (error) {

        console.error(
            "Get users error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to fetch users"
        });
    }
};


// ========================================
// CREATE USER
// POST /api/users
// ========================================

export const createUser = async (req, res) => {
    try {

        const {
            username,
            email,
            password,
            firstName,
            lastName,
            role
        } = req.body;


        // --------------------------------
        // Validation
        // --------------------------------

        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message:
                    "Username, email and password are required"
            });
        }


        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must contain at least 8 characters"
            });
        }


        // --------------------------------
        // Normalize role
        // --------------------------------

        let normalizedRole = null;

        if (role) {
            normalizedRole = String(role)
                .trim()
                .toUpperCase();

            const allowedRoles = [
                "EMPLOYEE",
                "DEVELOPER",
                "ADMIN",
                "SUPER_ADMIN"
            ];

            if (!allowedRoles.includes(normalizedRole)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid role"
                });
            }
        }


        // --------------------------------
        // Check existing user
        // --------------------------------

        const existingUser = await pool.query(
            `
            SELECT id
            FROM users
            WHERE username = $1
               OR email = $2
            `,
            [
                username,
                email
            ]
        );


        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message:
                    "Username or email already exists"
            });
        }


        // --------------------------------
        // Check role exists
        // --------------------------------

        let roleResult = null;

        if (normalizedRole) {

            roleResult = await pool.query(
                `
                SELECT id, name
                FROM roles
                WHERE UPPER(name) = $1
                `,
                [normalizedRole]
            );


            if (roleResult.rows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Role does not exist"
                });
            }
        }


        // --------------------------------
        // Hash password
        // --------------------------------

        const hashedPassword =
            await bcrypt.hash(password, 12);


        // --------------------------------
        // Create user
        // --------------------------------

        const userResult = await pool.query(
            `
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                first_name,
                last_name
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5
            )
            RETURNING
                id,
                username,
                email,
                first_name AS "firstName",
                last_name AS "lastName"
            `,
            [
                username,
                email,
                hashedPassword,
                firstName || null,
                lastName || null
            ]
        );


        const user = userResult.rows[0];


        // --------------------------------
        // Assign role
        // --------------------------------

        if (roleResult) {

            await pool.query(
                `
                INSERT INTO user_roles
                (
                    user_id,
                    role_id
                )
                VALUES
                (
                    $1,
                    $2
                )
                ON CONFLICT DO NOTHING
                `,
                [
                    user.id,
                    roleResult.rows[0].id
                ]
            );
        }


        // --------------------------------
        // Audit
        // --------------------------------

        await logAudit({
            userId: req.user.id,
            action: "USER_CREATE",
            resource: "USER",
            resourceId: user.id,
            result: "SUCCESS",
            riskLevel: "MEDIUM",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                username: user.username,
                email: user.email,
                role: normalizedRole
            }
        });


        // --------------------------------
        // Response
        // --------------------------------

        return res.status(201).json({
            success: true,
            message: "User created successfully",

            user: {
                ...user,
                role: normalizedRole
            }
        });

    } catch (error) {

        console.error(
            "Create user error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to create user"
        });
    }
};


// ========================================
// UPDATE USER
// PUT /api/users/:userId
// ========================================

export const updateUser = async (req, res) => {
    try {

        const { userId } = req.params;

        const {
            email,
            firstName,
            lastName,
            password
        } = req.body;


        // --------------------------------
        // Check user
        // --------------------------------

        const existingUser = await pool.query(
            `
            SELECT
                id,
                username,
                email
            FROM users
            WHERE id = $1
            `,
            [userId]
        );


        if (existingUser.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }


        // --------------------------------
        // Update with password
        // --------------------------------

        if (password) {

            if (password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password must contain at least 8 characters"
                });
            }


            const hashedPassword =
                await bcrypt.hash(password, 12);


            await pool.query(
                `
                UPDATE users
                SET
                    email = COALESCE($1, email),
                    first_name = COALESCE($2, first_name),
                    last_name = COALESCE($3, last_name),
                    password_hash = $4,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $5
                `,
                [
                    email || null,
                    firstName || null,
                    lastName || null,
                    hashedPassword,
                    userId
                ]
            );

        } else {

            // --------------------------------
            // Update without password
            // --------------------------------

            await pool.query(
                `
                UPDATE users
                SET
                    email = COALESCE($1, email),
                    first_name = COALESCE($2, first_name),
                    last_name = COALESCE($3, last_name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $4
                `,
                [
                    email || null,
                    firstName || null,
                    lastName || null,
                    userId
                ]
            );
        }


        // --------------------------------
        // Get updated user
        // --------------------------------

        const result = await pool.query(
            `
            SELECT
                id,
                username,
                email,
                first_name AS "firstName",
                last_name AS "lastName"
            FROM users
            WHERE id = $1
            `,
            [userId]
        );


        const updatedUser = result.rows[0];


        // --------------------------------
        // Audit
        // --------------------------------

        await logAudit({
            userId: req.user.id,
            action: "USER_UPDATE",
            resource: "USER",
            resourceId: userId,
            result: "SUCCESS",
            riskLevel: "MEDIUM",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                username: updatedUser.username,
                email: updatedUser.email
            }
        });


        return res.json({
            success: true,
            message: "User updated successfully",
            user: updatedUser
        });

    } catch (error) {

        console.error(
            "Update user error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to update user"
        });
    }
};


// ========================================
// DELETE USER
// DELETE /api/users/:userId
// ========================================

export const deleteUser = async (req, res) => {
    try {

        const { userId } = req.params;


        // --------------------------------
        // Prevent deleting yourself
        // --------------------------------

        if (userId === req.user.id) {
            return res.status(400).json({
                success: false,
                message:
                    "You cannot delete your own account"
            });
        }


        // --------------------------------
        // Get user before deleting
        // --------------------------------

        const userResult = await pool.query(
            `
            SELECT
                id,
                username,
                email
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


        const deletedUser =
            userResult.rows[0];


        // --------------------------------
        // Delete user
        // --------------------------------

        await pool.query(
            `
            DELETE FROM users
            WHERE id = $1
            `,
            [userId]
        );


        // --------------------------------
        // Audit
        // --------------------------------

        await logAudit({
            userId: req.user.id,
            action: "USER_DELETE",
            resource: "USER",
            resourceId: userId,
            result: "SUCCESS",
            riskLevel: "HIGH",
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            metadata: {
                username: deletedUser.username,
                email: deletedUser.email
            }
        });


        return res.json({
            success: true,
            message: "User deleted successfully"
        });

    } catch (error) {

        console.error(
            "Delete user error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to delete user"
        });
    }
};