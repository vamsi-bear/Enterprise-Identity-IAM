import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

console.log("DATABASE_URL loaded:", !!process.env.DATABASE_URL);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

pool.on("connect", () => {
    console.log("✅ PostgreSQL connected");
});

pool.on("error", (error) => {
    console.error("❌ PostgreSQL error:", error);
});

export default pool;