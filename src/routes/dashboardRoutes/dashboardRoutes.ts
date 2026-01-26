import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import jwt, { JwtPayload } from "jsonwebtoken";
import { eq } from "drizzle-orm";
import { usersTable } from "../../db/schema";
import { db } from "../../db-connector/drizzle-connection";
import {testSchema} from "../../utils/validation";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// Extend FastifyRequest to include user
interface AuthRequest extends FastifyRequest {
    user?: JwtPayload & { userId: number };
}

// --- Reusable JWT authentication preHandler ---
async function authenticateJWT(request: AuthRequest, reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (!authHeader) return reply.status(401).send({ error: "Missing token" });

    const token = authHeader.split(" ")[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET) as JwtPayload & { userId: number };
        request.user = payload;
    } catch {
        return reply.status(403).send({ error: "Invalid token" });
    }
}

// --- Dashboard routes ---
export async function dashboardRoutes(fastify: FastifyInstance) {
    fastify.get("/me", { preHandler: authenticateJWT }, async (request: AuthRequest, reply: FastifyReply) => {
        if (!request.user?.userId) return reply.status(401).send({ error: "Invalid user" });

        // Fetch user from DB
        const [user] = await db.select()
            .from(usersTable)
            .where(eq(usersTable.id, request.user.userId))
            .limit(1);

        if (!user) return reply.status(404).send({ error: "User not found" });

        // Return safe user info
        return reply.send({
            id: user.id,
            username: user.username,
            email: user.email,
            isVerified: user.isVerified
        });
    });

    fastify.get("/test", async (request, reply) => {
        return reply.send({
            message:"Hello World"
        })
    })
    fastify.post("/testing", async (request, reply) => {
        const {message, message_Id} = testSchema.parse(request.body);

        return reply.send({
            message:"Recived the message with message id",
            recieved:message,
            message_id:message_Id
        })

    })
}
