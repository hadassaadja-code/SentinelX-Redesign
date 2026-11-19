// Point d'entrée du serveur SentinelX : API Fastify, en-têtes de sécurité, CSRF, limitation de débit,
// frontend compilé, file de tâches et travaux de fond. PROCESS_ROLE=api|worker|all permet de séparer les rôles.
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import fstatic from '@fastify/static'
import fs from 'node:fs'
import path from 'node:path'
import { config, ROOT } from './config.js'
import { prisma, asPlatform, HttpError, reloadPlans } from './core.js'
import { connectDb } from './db.js'
import { TenantViolation } from './db.js'
import { rateLimit } from './security.js'
import authRoutes from './routes/auth.js'
import orgRoutes from './routes/org.js'
import scanRoutes from './routes/scans.js'
import monitoringRoutes from './routes/monitoring.js'
import adminRoutes from './routes/admin.js'
import publicRoutes from './routes/public.js'
import { initQueue, closeQueue } from './queue.js'
import { startBackgroundJobs } from './monitor.js'
import { closeBrowsers } from './scanners/browser.js'

const app = Fastify({ logger: { level: config.isProd ? 'info' : 'warn' }, bodyLimit: 200_000, trustProxy: !!process.env.TRUST_PROXY })
await app.register(cookie)

// Corps brut conservé pour les webhooks signés (Stripe)
app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req: any, body: Buffer, done) => {
  if (req.routeOptions?.config?.rawBody) req.rawBody = body
  if (!body.length) return done(null, {})
  try {
    done(null, JSON.parse(body.toString('utf8')))
  } catch {
    done(new HttpError(400, 'JSON invalide'), undefined)
  }
})

// En-têtes de sécurité sur toutes les réponses
app.addHook('onSend', async (_req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff')
  reply.header('X-Frame-Options', 'DENY')
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  reply.header('Cross-Origin-Opener-Policy', 'same-origin')
  reply.header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
  if (config.isProd) reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
})

// Limitation de débit globale sur l'API et protection CSRF (cookie SameSite=Strict + en-tête personnalisé obligatoire)
app.addHook('preHandler', async (req, reply) => {
  if (!req.url.startsWith('/api')) return
  const r = rateLimit(`api:${req.ip}`, config.rateLimit.apiPerMinute)
  if (!r.ok) {
    reply.header('retry-after', String(r.retryAfter))
    throw new HttpError(429, 'Trop de requêtes. Réessayez dans quelques instants.')
  }
  const exempt = req.url.startsWith('/api/billing/webhook')
  if (!exempt && !['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers['x-requested-with'] !== 'sentinelx') throw new HttpError(403, 'Requête refusée (protection CSRF)')
})

app.setErrorHandler((err: any, req, reply) => {
  if (err instanceof HttpError) return reply.code(err.status).send({ error: err.message, ...(err.extra ?? {}) })
  if (err instanceof TenantViolation) {
    app.log.error({ url: req.url }, err.message)
    return reply.code(403).send({ error: 'Accès refusé' })
  }
  if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: err.statusCode === 413 ? 'Requête trop volumineuse' : 'Requête invalide' })
  app.log.error(err)
  reply.code(500).send({ error: 'Erreur interne' }) // aucun détail technique renvoyé au client
})

if (config.processRole !== 'worker') {
  await app.register(async (api: any) => {
    await publicRoutes(api)
    await authRoutes(api)
    await orgRoutes(api)
    await scanRoutes(api)
    await monitoringRoutes(api)
    await adminRoutes(api)
  }, { prefix: '/api' })

  // Sert le frontend compilé (web/dist) : une seule adresse pour la démonstration
  const dist = path.join(ROOT, '..', 'web', 'dist')
  if (fs.existsSync(dist)) {
    await app.register(fstatic, { root: dist, maxAge: '1h', immutable: false })
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith('/api')) return reply.code(404).send({ error: 'Introuvable' })
      return reply.sendFile('index.html')
    })
  } else {
    app.setNotFoundHandler((req, reply) => reply.code(404).send({ error: req.url.startsWith('/api') ? 'Introuvable' : 'Frontend non compilé : exécutez npm run build dans web/' }))
  }
}

// ---------- Démarrage ----------
await connectDb()
await reloadPlans()
// Promotion des Super Administrateurs déclarés par l'environnement
if (config.superAdminEmails.length) await asPlatform(() => prisma.user.updateMany({ where: { email: { in: config.superAdminEmails } }, data: { isSuperAdmin: true } }))
// Les audits interrompus par un arrêt du serveur sont marqués en échec (file mémoire uniquement : avec Redis, BullMQ les reprend)
if (!config.redisUrl) await asPlatform(() => prisma.scan.updateMany({ where: { status: { in: ['QUEUED', 'RUNNING'] } }, data: { status: 'FAILED', error: 'Audit interrompu par un redémarrage du serveur', finishedAt: new Date(), progress: 100 } }))
await initQueue()
if (config.processRole !== 'api') startBackgroundJobs()

if (config.processRole !== 'worker') {
  await app.listen({ port: config.port, host: config.host })
  console.log(`SentinelX est démarré : http://localhost:${config.port} (${config.env}, rôle ${config.processRole})`)
} else console.log('SentinelX worker démarré')

const shutdown = async (sig: string) => {
  console.log(`Arrêt (${sig})…`)
  await Promise.race([Promise.all([app.close(), closeQueue(), closeBrowsers()]), new Promise((r) => setTimeout(r, 8000))])
  await prisma.$disconnect().catch(() => {})
  process.exit(0)
}
process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
