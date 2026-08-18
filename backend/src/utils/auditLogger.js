import pool from "../config/database.js";


// ============================================================
// AUDIT LOGGER
// ============================================================

export const logAudit = async ({
    userId = null,
    action,
    resource = null,
    resourceId = null,
    result,
    riskLevel = "LOW",
    ipAddress = null,
    userAgent = null,
    metadata = {}
}) => {

    try {

        /*
         * IMPORTANT:
         *
         * Your database currently rejects:
         *
         *     FAILURE
         *
         * Therefore we convert FAILURE to FAILED.
         *
         * SUCCESS remains SUCCESS.
         */

        let databaseResult = result;


        if (result === "FAILURE") {

            databaseResult = "FAILED";

        }


        await pool.query(
            `
            INSERT INTO audit_logs
            (
                user_id,
                action,
                resource,
                resource_id,
                result,
                risk_level,
                ip_address,
                user_agent,
                metadata
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8,
                $9
            )
            `,
            [
                userId,
                action,
                resource,
                resourceId,
                databaseResult,
                riskLevel,
                ipAddress,
                userAgent,
                metadata
            ]
        );


        console.log(
            "Audit log created:",
            {
                userId,
                action,
                result: databaseResult
            }
        );


    } catch (error) {

        /*
         * Do NOT allow an audit-log failure to break
         * authentication or MFA.
         */

        console.error(
            "Audit logging error:",
            error.message
        );


        console.error(
            "Audit log details:",
            {
                userId,
                action,
                resource,
                resourceId,
                result,
                riskLevel
            }
        );

    }

};