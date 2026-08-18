
import express from "express";

import {
    getAuditLogs,
    getAuditSummary
} from "../controllers/auditController.js";

import {
    authenticate,
    authorize
} from "../middleware/authMiddleware.js";


const router = express.Router();


// ============================================
// AUDIT SUMMARY
// GET /api/audit-logs/summary
// ============================================

router.get(
    "/summary",
    authenticate,
    authorize("AUDIT_READ"),
    getAuditSummary
);


// ============================================
// AUDIT LOGS
// GET /api/audit-logs
// ============================================

router.get(
    "/",
    authenticate,
    authorize("AUDIT_READ"),
    getAuditLogs
);


export default router;
