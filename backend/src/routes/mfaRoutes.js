import express from "express";

import {
    setupMFA,
    verifyMFA,
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
// MFA LOGIN VERIFICATION
// POST /api/mfa/verify
//
// IMPORTANT:
// This uses authenticateMfa because the browser sends
// the temporary mfaToken here.
// ============================================================

router.post(
    "/verify",
    authenticateMfa,
    verifyMFA
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