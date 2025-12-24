import 'dotenv/config';
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import jwt, { JwtPayload } from "jsonwebtoken";
import crypto from "crypto";
import validator from "validator";
import nodemailer from "nodemailer";
import sanitizeText from "./sanitizeTextInputs";

/* ===================== CONFIG ===================== */
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev_super_secret_key_change_me";
const SALT_ROUNDS = 10;

app.use(cors());
app.use(express.json());

/* ===================== DATABASE ===================== */
const db = new sqlite3.Database("./auth.db");

/* ===================== TYPES ===================== */
interface UserRow {
    id: number;
    username: string;
    email: string;
    password_hash: string;
    created_at: string;
}

interface PasswordResetRow {
    id: number;
    user_id: number;
    token: string;
    expires_at: string;
}

interface AuthRequest extends Request {
    user?: JwtPayload | string;
}

/* ===================== TABLES ===================== */
db.run(`
    CREATE TABLE IF NOT EXISTS users (
                                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                                         username TEXT UNIQUE NOT NULL,
                                         email TEXT UNIQUE NOT NULL,
                                         password_hash TEXT NOT NULL,
                                         created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

db.run(`
    CREATE TABLE IF NOT EXISTS password_resets (
                                                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                   user_id INTEGER NOT NULL,
                                                   token TEXT UNIQUE NOT NULL,
                                                   expires_at DATETIME NOT NULL,
                                                   FOREIGN KEY (user_id) REFERENCES users(id)
        )
`);

/* ===================== HELPERS ===================== */
function sanitizeUsername(input: string): string | null {
    const clean = sanitizeText(input, 30);
    return clean.length >= 3 ? clean : null;
}

function authenticateJWT(req: AuthRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
}

/* ===================== MAILER ===================== */
export const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: Number(process.env.SMTP_PORT) === 465, // true for SSL
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

transporter.verify((err, success) => {
    if (err) console.error("SMTP ERROR:", err);
    else console.log("SMTP connection ready");
});

/* ===================== ROUTES ===================== */

// Signup
app.post("/signup", async (req: Request, res: Response) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
        return res.status(400).json({ error: "Missing fields" });

    const safeUsername = sanitizeUsername(username);
    if (!safeUsername) return res.status(400).json({ error: "Invalid username" });
    if (!validator.isEmail(email)) return res.status(400).json({ error: "Invalid email" });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    db.run(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        [safeUsername, email.toLowerCase(), hash],
        (err) => {
            if (err) return res.status(400).json({ error: "Username or email already exists" });
            res.json({ message: "User created" });
        }
    );
});

// Signin
app.post("/signin", (req: Request, res: Response) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

    db.get<UserRow>("SELECT * FROM users WHERE email = ?", [email.toLowerCase()], async (_err, user) => {
        if (!user) return res.status(400).json({ error: "Invalid credentials" });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ error: "Invalid credentials" });

        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, username: user.username });
    });
});

// Password Reset Request
app.post("/password-reset-request", async (req: Request, res: Response) => {
    const { email } = req.body;
    if (!email || !validator.isEmail(email)) return res.json({ message: "If account exists, email sent" });

    db.get<UserRow>("SELECT * FROM users WHERE email = ?", [email.toLowerCase()], async (_err, user) => {
        if (!user) return res.json({ message: "If account exists, email sent" });

        const token = crypto.randomUUID();
        const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        db.run("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)", [user.id, token, expires]);

        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        try {
            await transporter.sendMail({
                to: user.email,
                from: `"Support" <${process.env.SMTP_USER}>`,
                subject: "Reset your password",
                html: `<p>Click below to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
            });
            console.log("Reset email sent to", user.email);
        } catch (mailErr) {
            console.error("Failed to send reset email:", mailErr);
            return res.status(500).json({ error: "Failed to send email", details: mailErr });
        }

        return res.json({ message: "If account exists, email sent" });
    });
});


// Password Reset
app.post("/password-reset", async (req: Request, res: Response) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "Missing data" });

    db.get<PasswordResetRow>(
        "SELECT * FROM password_resets WHERE token = ? AND expires_at > CURRENT_TIMESTAMP",
        [token],
        async (_err, row) => {
            if (!row) return res.status(400).json({ error: "Invalid or expired token" });

            const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
            db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hash, row.user_id], () => {
                db.run("DELETE FROM password_resets WHERE user_id = ?", [row.user_id]);
                res.json({ message: "Password successfully reset" });
            });
        }
    );
});

// Auth Test
app.get("/me", authenticateJWT, (req: AuthRequest, res: Response) => {
    res.json({ user: req.user });
});

/* ===================== START SERVER ===================== */
app.listen(PORT, () => {
    console.log(`Auth server running on http://localhost:${PORT}`);
});
