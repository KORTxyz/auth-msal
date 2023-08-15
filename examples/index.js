require('dotenv').config();

const fastify = require('fastify')({ logger: true });
const fastifySession = require('@fastify/session');
const fastifyCookie = require('@fastify/cookie');
fastify.register(fastifyCookie);

fastify.register(fastifySession, {
    secret: process.env.SESSION_SECRET,
    cookie: { secure: false },
    expires: 1800000
});

fastify.register(require('../src/auth'), { prefix: 'auth' });

fastify.register(async (instance, opts, done) => {
    // authenticated routes
    instance.addHook('preHandler', (req, reply, done) => {
        if (!req.session?.isAuthenticated) {
            return reply.redirect('/auth/signin'); // redirect to sign-in route
        }
        done()
    })

    instance.get('/', async (req, reply) => {
        reply.send({ hello: 'world2' })
    })

    instance.get('/test', async (req, reply) => {
        reply.send({ user: req.session.account?.username })
    })

})


// Run the server!
fastify.listen({ port: 3000 }, (err) => {
    if (err) {
        fastify.log.error(err)
        process.exit(1)
    }
})