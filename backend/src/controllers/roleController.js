
import pool from "../config/database.js";
import { logAudit } from "../utils/auditLogger.js";

// ============================================
// GET ALL ROLES
// GET /api/roles
// ============================================

export const getRoles = async (req, res) => {

    try {

        const result = await pool.query(`
            SELECT
                id,
                name
            FROM roles
            ORDER BY name
        `);

        return res.status(200).json({
            success: true,
            roles: result.rows
        });

    } catch (error) {

        console.error("Get roles error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to fetch roles"
        });

    }

};


// ============================================
// ASSIGN / REPLACE USER ROLE
// POST /api/users/:userId/role
// ============================================

export const assignRole = async (req, res) => {

    try {

        const { userId } = req.params;
const normalizedRole = role
    ? String(role).trim().toUpperCase()
    : "";

        // --------------------------------------------
        // Validate role
        // --------------------------------------------

    if (!normalizedRole) {

            return res.status(400).json({
                success: false,
                message: "Role is required"
            });

        }


        // --------------------------------------------
        // Check target user
        // --------------------------------------------

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


        const targetUser =
            userResult.rows[0];


        // --------------------------------------------
        // Check role
        // --------------------------------------------

        const roleResult = await pool.query(
            `
            SELECT
                id,
                name
            FROM roles
            WHERE name = $1
            `,
[normalizedRole]        );


        if (roleResult.rows.length === 0) {

            return res.status(404).json({
                success: false,
                message: "Role not found"
            });

        }


        const targetRole =
            roleResult.rows[0];


        // --------------------------------------------
        // Replace existing role
        // --------------------------------------------

        await pool.query(
            `
            DELETE FROM user_roles
            WHERE user_id = $1
            `,
            [userId]
        );


        await pool.query(
            `
            INSERT INTO user_roles
                (user_id, role_id)
            VALUES
                ($1, $2)
            `,
            [
                userId,
                targetRole.id
            ]
        );


        // --------------------------------------------
        // Audit log
        // --------------------------------------------

        await logAudit({

            userId: req.user.id,

            action: "ROLE_ASSIGN",

            resource: "USER_ROLE",

            resourceId: userId,

            result: "SUCCESS",

            riskLevel: "HIGH",

            ipAddress: req.ip,

            userAgent: req.get("user-agent"),

            metadata: {

                targetUsername:
                    targetUser.username,

                targetEmail:
                    targetUser.email,

                assignedRole:
                    targetRole.name

            }

        });


        // --------------------------------------------
        // Response
        // --------------------------------------------

        return res.status(200).json({

            success: true,

            message: "Role assigned successfully",

            user: {

                id: targetUser.id,

                username: targetUser.username,

                email: targetUser.email,

                role: targetRole.name

            }

        });


    } catch (error) {

        console.error(
            "Assign role error:",
            error
        );

        return res.status(500).json({

            success: false,

            message: "Unable to assign role"

        });

    }

};
