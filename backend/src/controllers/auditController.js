
import pool from "../config/database.js";


// ============================================
// GET AUDIT LOGS
// GET /api/audit-logs
//
// Supported filters:
// ?action=LOGIN
// ?result=FAILURE
// ?riskLevel=HIGH
// ?from=2026-08-01
// ?to=2026-08-17
// ?limit=50
// ============================================

export const getAuditLogs = async (req, res) => {

    try {

        const {
            action,
            result,
            riskLevel,
            from,
            to,
            limit
        } = req.query;


        let query = `
            SELECT
                a.id,
                a.user_id AS "userId",
                u.username,
                u.email,
                a.action,
                a.resource,
                a.resource_id AS "resourceId",
                a.result,
                a.risk_level AS "riskLevel",
                a.ip_address AS "ipAddress",
                a.user_agent AS "userAgent",
                a.metadata,
                a.created_at AS "createdAt"

            FROM audit_logs a

            LEFT JOIN users u
                ON a.user_id = u.id

            WHERE 1 = 1
        `;


        const values = [];
        let parameterIndex = 1;


        // ============================================
        // ACTION FILTER
        // ============================================

        if (action) {

            query += `
                AND a.action = $${parameterIndex}
            `;

            values.push(action);

            parameterIndex++;
        }


        // ============================================
        // RESULT FILTER
        // ============================================

        if (result) {

            query += `
                AND a.result = $${parameterIndex}
            `;

            values.push(result);

            parameterIndex++;
        }


        // ============================================
        // RISK LEVEL FILTER
        // ============================================

        if (riskLevel) {

            query += `
                AND a.risk_level = $${parameterIndex}
            `;

            values.push(riskLevel);

            parameterIndex++;
        }


        // ============================================
        // FROM DATE
        // ============================================

        if (from) {

            query += `
                AND a.created_at >= $${parameterIndex}::date
            `;

            values.push(from);

            parameterIndex++;
        }


        // ============================================
        // TO DATE
        // ============================================

        if (to) {

            query += `
                AND a.created_at < ($${parameterIndex}::date + INTERVAL '1 day')
            `;

            values.push(to);

            parameterIndex++;
        }


        // ============================================
        // ORDER
        // ============================================

        query += `
            ORDER BY a.id DESC
        `;


        // ============================================
        // LIMIT
        // ============================================

        let requestedLimit = 100;

        if (limit) {

            const parsedLimit = parseInt(limit, 10);

            if (
                !Number.isNaN(parsedLimit) &&
                parsedLimit > 0 &&
                parsedLimit <= 500
            ) {
                requestedLimit = parsedLimit;
            }
        }


        query += `
            LIMIT $${parameterIndex}
        `;

        values.push(requestedLimit);


        // ============================================
        // DATABASE QUERY
        // ============================================

        const resultData = await pool.query(
            query,
            values
        );


        return res.status(200).json({

            success: true,

            count: resultData.rows.length,

            filters: {
                action: action || null,
                result: result || null,
                riskLevel: riskLevel || null,
                from: from || null,
                to: to || null,
                limit: requestedLimit
            },

            logs: resultData.rows

        });

    } catch (error) {

        console.error(
            "Get audit logs error:",
            error
        );

        return res.status(500).json({

            success: false,

            message: "Unable to fetch audit logs"

        });
    }
};



// ============================================
// GET AUDIT SUMMARY
// GET /api/audit-logs/summary
// ============================================

export const getAuditSummary = async (req, res) => {

    try {

        const result = await pool.query(`
            SELECT

                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE result = 'SUCCESS'
                ) AS successful,

                COUNT(*) FILTER (
                    WHERE result = 'FAILURE'
                ) AS failed,

                COUNT(*) FILTER (
                    WHERE risk_level = 'HIGH'
                ) AS high_risk,

                COUNT(*) FILTER (
                    WHERE risk_level = 'MEDIUM'
                ) AS medium_risk,

                COUNT(*) FILTER (
                    WHERE risk_level = 'LOW'
                ) AS low_risk

            FROM audit_logs
        `);


        const summary = result.rows[0];


        return res.status(200).json({

            success: true,

            summary: {

                total: Number(summary.total),

                successful: Number(summary.successful),

                failed: Number(summary.failed),

                highRisk: Number(summary.high_risk),

                mediumRisk: Number(summary.medium_risk),

                lowRisk: Number(summary.low_risk)

            }

        });

    } catch (error) {

        console.error(
            "Get audit summary error:",
            error
        );

        return res.status(500).json({

            success: false,

            message: "Unable to fetch audit summary"

        });
    }
};

