import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";

import authRoutes from "./routes/authRoutes.js";
import mfaRoutes from "./routes/mfaRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import roleRoutes from "./routes/roleRoutes.js";
import auditRoutes from "./routes/auditRoutes.js";

import pool from "./config/database.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// ============================================================
// ALLOWED FRONTEND ORIGINS
// ============================================================

const allowedOrigins = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "https://securesphere-iam.netlify.app"
];

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================

app.use(helmet());

app.use(
    cors({
        origin: function (origin, callback) {

            // Allow Postman, curl, etc.
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            console.error("❌ CORS blocked:", origin);

            return callback(
                new Error("CORS: Origin not allowed")
            );
        },

        credentials: true,

        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(express.json());

// ============================================================
// RATE LIMITING
// ============================================================

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use(limiter);

// ============================================================
// DATABASE TEST
// ============================================================

pool.query("SELECT NOW()")
    .then(() => {
        console.log("✅ Database query successful");
    })
    .catch((error) => {
        console.error(
            "❌ Database query failed:",
            error
        );
    });

// ============================================================
// ROUTES
// ============================================================

app.use("/api/auth", authRoutes);

app.use("/api/mfa", mfaRoutes);

app.use("/api/users", userRoutes);

app.use("/api/roles", roleRoutes);

app.use(
    "/api/audit-logs",
    auditRoutes
);

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", async (req, res) => {

    try {

        const result =
            await pool.query("SELECT NOW()");

        res.json({

            status: "success",

            message:
                "Enterprise IAM API is running",

            database: "connected",

            time: result.rows[0].now

        });

    } catch (error) {

        console.error(
            "Health check error:",
            error
        );

        res.status(500).json({

            status: "error",

            message:
                "Database connection failed"

        });

    }

});

// ============================================================
// SERVER
// ============================================================

console.log("🚀 server.js loaded");

console.log("🔵 About to start server...");

console.log("🔵 PORT =", PORT);

const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(`
========================================
 SecureSphere Enterprise IAM
========================================

 🟢 API running on port ${PORT}

 Environment:
 ${process.env.NODE_ENV || "Development"}

 Security:
 ✓ Helmet
 ✓ CORS
 ✓ Rate Limiting
 ✓ PostgreSQL

========================================
        `);

    }
);

server.on("error", (error) => {

    console.error(
        "❌ Server error:",
        error
    );

});