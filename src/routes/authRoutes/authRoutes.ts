import { FastifyInstance } from "fastify";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { ZodError } from "zod";
import dotenv from 'dotenv';
import { db } from "../../db-connector/drizzle-connection";
import { usersTable, passwordResetsRequestTable } from "../../db/schema";
import {
    signupSchema,
    signinSchema,
    passwordResetRequestSchema,
    passwordResetSchema
} from "../../utils/validation";
import nodemailer from "nodemailer";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const SALT_ROUNDS = 10;

dotenv.config(); // MUST be first
export const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: Number(process.env.SMTP_PORT) === 465, // true for SSL
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});



export async function authRoutes(fastify: FastifyInstance) {

    /* ---------- SIGN UP ---------- */
    fastify.post("/sign-up", async (request, reply) => {
        try {
            const data = signupSchema.parse(request.body);

            const [existing] = await db.select()
                .from(usersTable)
                .where(eq(usersTable.email, data.email))
                .limit(1);

            if (existing) {
                return reply.status(400).send({ error: "User already exists" });
            }

            const passwordHash = await bcrypt.hash(data.password, SALT_ROUNDS);

            await db.insert(usersTable).values({
                email: data.email,
                username: data.username,
                password_hash: passwordHash,
                isVerified: true
            });

            return reply.send({ message: "User created" });

        } catch (e) {
            if (e instanceof ZodError) {
                return reply.status(400).send(e.flatten());
            }
            console.error(e);
            return reply.status(500).send({ error: "Internal server error" });
        }
    });

    /* ---------- SIGN IN ---------- */
    fastify.post("/sign-in", async (request, reply) => {
        const {email,password} = signinSchema.parse(request.body);

        const [user] = await db.select()
            .from(usersTable)
            .where(eq(usersTable.email, email))
            .limit(1);

        if (!user) {
            return reply.status(400).send({ error: "Invalid credentials" });
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            return reply.status(400).send({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userId: user.id },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return reply.send({ token , username: user.username });
    });


    /* ---------- PASSWORD RESET REQUEST ---------- */
    fastify.post("/password-reset-request", async (request, reply) => {
        const { email } = passwordResetRequestSchema.parse(request.body);

        const [user] = await db.select()
            .from(usersTable)
            .where(eq(usersTable.email, email))
            .limit(1);

        // Prevent email enumeration
        if (!user || !user.email) {
            return reply.send({ message: "If account exists, email sent" });
        }

        const token = crypto.randomUUID();
        const expiresAt = Math.floor(Date.now() / 1000) + 15 * 60;

        await db.insert(passwordResetsRequestTable).values({
            user_id: user.id,
            token,
            expires_at: expiresAt
        });

        const resetLink =
            `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        await transporter.sendMail({
            to: user.email, // ✅ now guaranteed string
            subject: "Reset your password",
            html: `
            <p>You requested a password reset.</p>
            <p>Click below:</p>
            <a href="${resetLink}">${resetLink}</a>
            <p>Expires in 15 minutes.</p>
        `
        });

        return reply.send({ message: "If account exists, email sent" });
    });



    /* ---------- PASSWORD RESET ---------- */
    fastify.post("/password-reset", async (request, reply) => {
        const { token, newPassword } = passwordResetSchema.parse(request.body);

        const now = Math.floor(Date.now() / 1000);

        const [reset] = await db.select()
            .from(passwordResetsRequestTable)
            .where(eq(passwordResetsRequestTable.token, token))
            .limit(1);

        if (!reset || reset.expires_at < now) {
            return reply.status(400).send({ error: "Invalid or expired token" });
        }

        const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);

        await db.transaction(async (tx) => {
            await tx.update(usersTable)
                .set({ password_hash: passwordHash })
                .where(eq(usersTable.id, reset.user_id));

            await tx.delete(passwordResetsRequestTable)
                .where(eq(passwordResetsRequestTable.user_id, reset.user_id));
        });

        return reply.send({ message: "Password reset successful" });
    });
}
