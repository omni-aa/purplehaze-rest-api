import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { db } from "../../db-connector/drizzle-connection";
import { usersTable } from "../../db/schema";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";
import { signupSchema } from "../../utils/validation";
import { ZodError } from "zod";

export async function authRoutes(fastify: FastifyInstance) {
    fastify.post('/sign-up', async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            const validateData = signupSchema.parse(request.body as any);

            // Check if user exists
            const existingUser = await db.select()
                .from(usersTable)
                .where(eq(usersTable.email, validateData.email))
                .limit(1);

            if (existingUser.length > 0) {
                return reply.code(400).send({ error: "User already exists" });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(validateData.password, 10);

            // Insert user and get ID
            const [inserted] = await db.insert(usersTable).values({
                email: validateData.email,
                username: validateData.username,
                password: hashedPassword,
                isVerified: true,
                age: validateData.age
            }).$returningId();

            // Query the inserted user by ID
            const [user] = await db.select()
                .from(usersTable)
                .where(eq(usersTable.id, inserted.id))
                .limit(1);

            return reply.send({
                message: 'User created successfully',
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    isVerified: user.isVerified,
                    age: user.age
                },
            });

        } catch (e: unknown) {
            // Handle Zod validation errors
            if (e instanceof ZodError) {
                return reply.status(400).send({
                    error: "Validation failed",
                    issues: e.format()  // safer than using e.errors
                });
            }

            // Any other error
            console.error('Sign-up error:', e);
            return reply.status(500).send({ error: 'Internal server error' });
        }
    });
    fastify.post('/sign-in', async (request: FastifyRequest, reply: FastifyReply) => {
        const validateData = signupSchema.parse(request.body as any);




    });
    fastify.post('/password-reset', async (request: FastifyRequest, reply: FastifyReply) => {

    });
    fastify.post('/password-reset-request', async (request: FastifyRequest, reply: FastifyReply) => {

    });

}
