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
// SERVER INFO
// ============================================================

console.log("🚀 server.js loaded");
console.log("🔵 About to start server...");
console.log("🔵 PORT =", PORT);

// ============================================================
// ALLOWED FRONTEND ORIGINS
// ============================================================

const allowedOrigins = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "https://securesphereiam.netlify.app"
];

// ============================================================
// SECURITY
// ============================================================



app.use(
    cors({
        origin: function (origin, callback) {

            // Allow Postman, curl and requests without Origin
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
app.use(helmet());
// ============================================================
// BODY PARSER
// ============================================================

app.use(express.json());

// ============================================================
// RATE LIMITING
// ============================================================

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});

app.use(limiter);

// ============================================================
// ROUTES
// ============================================================

app.use("/api/auth", authRoutes);

app.use("/api/mfa", mfaRoutes);

app.use("/api/users", userRoutes);

app.use("/api/roles", roleRoutes);

app.use("/api/audit-logs", auditRoutes);

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", async (req, res) => {

    try {

        const result = await pool.query("SELECT NOW()");

        res.status(200).json({

            status: "success",

            message: "Enterprise IAM API is running",

            database: "connected",

            time: result.rows[0].now

        });

    } catch (error) {

        console.error(
            "❌ Health check database error:",
            error
        );

        res.status(500).json({

            status: "error",

            message: "Database connection failed"

        });

    }

});

// ============================================================
// DATABASE CONNECTION TEST
// ============================================================

pool.query("SELECT NOW()")
    .then(() => {

        console.log("✅ PostgreSQL connected");

        console.log("✅ Database query successful");

    })
    .catch((error) => {

        console.error(
            "❌ Database query failed:",
            error
        );

    });

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {

    res.status(404).json({

        success: false,

        message: "API route not found",

        path: req.originalUrl

    });

});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {

    console.error("❌ Server error:", error);

    if (error.message === "CORS: Origin not allowed") {

        return res.status(403).json({

            success: false,

            message: "CORS: Origin not allowed"

        });

    }

    res.status(500).json({

        success: false,

        message: "Internal server error"

    });

});

// ============================================================
// START SERVER
// ============================================================

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
 ${process.env.NODE_ENV || "development"}

 Security:
 ✓ Helmet
 ✓ CORS
 ✓ Rate Limiting
 ✓ PostgreSQL

========================================
        `);

    }
);

// ============================================================
// SERVER ERROR
// ============================================================

server.on("error", (error) => {

    console.error(
        "❌ Server error:",
        error
    );

});