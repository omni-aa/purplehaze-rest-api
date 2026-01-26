import dotenv from 'dotenv';
dotenv.config(); // must be first

import Fastify from "fastify";
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import { authRoutes } from "./routes/authRoutes/authRoutes";
import { dashboardRoutes } from "./routes/dashboardRoutes/dashboardRoutes";

const fastify = Fastify({ logger: true });

// ======= CORS =======
fastify.register(cors, {
    origin: process.env.FRONTEND_URL || true, // allow frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
});

// ======= Cookies =======
fastify.register(cookie);

// ======= Health check =======
fastify.get('/health', async () => ({
    status: 'OK',
    timestamp: new Date().toISOString()
}));

// ======= Routes =======
fastify.register(authRoutes, { prefix: '/auth' });
fastify.register(dashboardRoutes, { prefix: '/dashboard' });

// ======= Server start =======
const start = async () => {
    try {
        const port = Number(process.env.PORT) || 3000;
        await fastify.listen({ port, host: '0.0.0.0' }); // listen on all interfaces
        console.log(`Server started on http://localhost:${port}`);
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
