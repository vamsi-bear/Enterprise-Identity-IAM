import pool from "../config/database.js";
import { logAudit } from "../utils/auditLogger.js";


// ===============================
// GET ALL ROLES
// ===============================
export const getRoles = async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name
             FROM roles
             ORDER BY name`
        );

        res.json({
            success: true,
            roles: result.rows
        });

    } catch (error) {
        console.error("Get roles error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to fetch roles"
        });
    }
};


// ===============================
// ASSIGN ROLE TO USER
// ===============================
export const assignRole = async (req, res) => {

    try {

        const { userId } = req.params;

        // IMPORTANT: Get role from request body
        const { role } = req.body;

        console.log("Assign role request:", {
            userId,
            role,
            body: req.body
        });


        // ===============================
        // VALIDATE ROLE
        // ===============================
        if (!role) {
            return res.status(400).json({
                success: false,
                message: "Role is required"
            });
        }


        // Normalize role
        const normalizedRole = String(role)
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


        // ===============================
        // CHECK USER
        // ===============================
        const userResult = await pool.query(
            `SELECT id, username, email
             FROM users
             WHERE id = $1`,
            [userId]
        );


        if (userResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }


        // ===============================
        // CHECK ROLE
        // ===============================
        const roleResult = await pool.query(
            `SELECT id, name
             FROM roles
             WHERE UPPER(name) = $1`,
            [normalizedRole]
        );


        if (roleResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Role does not exist"
            });
        }


        const roleId = roleResult.rows[0].id;
        const roleName = roleResult.rows[0].name;


        // ===============================
        // REMOVE EXISTING ROLES
        // ===============================
        await pool.query(
            `DELETE FROM user_roles
             WHERE user_id = $1`,
            [userId]
        );


        // ===============================
        // ASSIGN NEW ROLE
        // ===============================
        await pool.query(
            `INSERT INTO user_roles (user_id, role_id)
             VALUES ($1, $2)`,
            [userId, roleId]
        );


        // ===============================
        // AUDIT LOG
        // ===============================
        try {

            await logAudit({
                userId: req.user.id,
                action: "ROLE_ASSIGN",
                resource: "USER_ROLE",
                result: "SUCCESS",
                riskLevel: "HIGH",
                details: {
                    targetUserId: userId,
                    assignedRole: roleName
                }
            });

        } catch (auditError) {

            console.error(
                "Audit logging error:",
                auditError
            );

        }


        // ===============================
        // SUCCESS RESPONSE
        // ===============================
        return res.status(200).json({
            success: true,
            message: "Role assigned successfully",
            user: {
                id: userId,
                role: roleName
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