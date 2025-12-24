import {FastifyInstance, FastifyReply, FastifyRequest} from "fastify";


export async function authRoutes(fastify:FastifyInstance) {

    fastify.post('/sign-up', async (request: FastifyRequest,reply:FastifyReply)=>{

    })


    fastify.post('/sign-in', async (request: FastifyRequest,reply:FastifyReply)=>{

    })
    fastify.post('/password-reset-request', async (request: FastifyRequest,reply:FastifyReply)=>{

    })
    fastify.post('/password-reset', async (request: FastifyRequest,reply:FastifyReply)=>{

    })
}