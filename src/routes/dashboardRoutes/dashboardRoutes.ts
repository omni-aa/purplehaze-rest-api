import {FastifyInstance, FastifyReply, FastifyRequest} from "fastify";


export async function dashboardRoutes(fastify:FastifyInstance) {

    fastify.post('/profile', async (request: FastifyRequest,reply:FastifyReply)=>{

    })


    fastify.post('/stats', async (request: FastifyRequest,reply:FastifyReply)=>{

    })
}