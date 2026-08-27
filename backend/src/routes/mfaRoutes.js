import express from "express";

import {
    setupMFA,
    verifyMFA,
    verifyLoginMFA,
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
//
// This endpoint is used by an already authenticated user when
// enabling MFA, so it requires the final authentication token.
// ============================================================

router.post(
    "/verify",
    authenticate,
    verifyMFA
);

// MFA VERIFICATION DURING LOGIN
// POST /api/mfa/verify-login
//
// This endpoint accepts the short-lived mfaToken issued after the
// password check, not a final authenticated session token.
router.post(
    "/verify-login",
    authenticateMfa,
    verifyLoginMFA
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
