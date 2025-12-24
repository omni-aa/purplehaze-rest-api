import Fastify from "fastify"
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import dotenv from 'dotenv'
import {authRoutes} from "./routes/authRoutes/authRoutes";
import {dashboardRoutes} from "./routes/dashboardRoutes/dashboardRoutes";
dotenv.config()


const fastify = Fastify({
    logger: true
})



fastify.register(cookie);
// Health check
fastify.get('/health', async () => {
    return { status: 'OK', timestamp: new Date().toISOString() };
});


fastify.register(authRoutes, {prefix: '/auth'});
fastify.register(dashboardRoutes, {prefix: '/dashboard'});





const start = async () => {
    try{
        await fastify.listen({port:3000, host:'localhost'});
        console.log("Server started on port 3000");
    }catch(e){
        fastify.log.error(e);
        process.exit(1);
    }
}

start()

