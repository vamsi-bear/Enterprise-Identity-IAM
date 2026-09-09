import express from "express";

import {
    setupMFA,
    verifyMFA,
    verifyLoginMFA,
    verifyBackupCode,
    generateBackupCodes,
    disableMFA
} from "../controllers/mfaController.js";

import {
    authenticate,
    authenticateMfa,
    authorize
} from "../middleware/authMiddleware.js";

const router = express.Router();


// ============================================================
// MFA SETUP
// POST /api/mfa/setup
// ============================================================

router.post(
    "/setup",
    authenticate,
    setupMFA
);


// ============================================================
// MFA SETUP VERIFICATION
// POST /api/mfa/verify
// ============================================================

router.post(
    "/verify",
    authenticate,
    verifyMFA
);


// ============================================================
// MFA VERIFICATION DURING LOGIN
// POST /api/mfa/verify-login
// ============================================================

router.post(
    "/verify-login",
    authenticateMfa,
    verifyLoginMFA
);


// ============================================================
// BACKUP CODE VERIFICATION DURING LOGIN
// POST /api/mfa/verify-backup
// ============================================================

router.post(
    "/verify-backup",
    authenticateMfa,
    verifyBackupCode
);


// ============================================================
// GENERATE NEW BACKUP CODES
// POST /api/mfa/backup-codes
// ============================================================

router.post(
    "/backup-codes",
    authenticate,
    generateBackupCodes
);


// ============================================================
// MFA DISABLE
// DELETE /api/mfa/disable
// ============================================================

router.delete(
    "/disable",
    authenticate,
    authorize("MFA_DISABLE"),
    disableMFA
);


export default router;