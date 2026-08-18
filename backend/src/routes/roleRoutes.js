import express from "express";

import {
    getRoles
} from "../controllers/roleController.js";

import {
    authenticate,
    authorize
} from "../middleware/authMiddleware.js";

const router = express.Router();


// ========================================
// GET ALL ROLES
// GET /api/roles
// ========================================

router.get(
    "/",
    authenticate,
    authorize("ROLE_READ"),
    getRoles
);


export default router;