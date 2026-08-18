import express from "express";

import {
    getCurrentUser,
    getAllUsers,
    createUser,
    updateUser,
    deleteUser
} from "../controllers/userController.js";

import {
    assignRole
} from "../controllers/roleController.js";

import {
    authenticate,
    authorize
} from "../middleware/authMiddleware.js";

const router = express.Router();


// GET CURRENT USER
router.get(
    "/me",
    authenticate,
    getCurrentUser
);


// GET ALL USERS
router.get(
    "/",
    authenticate,
    authorize("USER_READ"),
    getAllUsers
);


// CREATE USER
router.post(
    "/",
    authenticate,
    authorize("USER_CREATE"),
    createUser
);


// UPDATE USER
router.put(
    "/:userId",
    authenticate,
    authorize("USER_UPDATE"),
    updateUser
);


// DELETE USER
router.delete(
    "/:userId",
    authenticate,
    authorize("USER_DELETE"),
    deleteUser
);


// ASSIGN ROLE
router.post(
    "/:userId/role",
    authenticate,
    authorize("ROLE_ASSIGN"),
    assignRole
);


export default router;