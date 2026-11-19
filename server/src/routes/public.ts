// Points d'entrée sans session : santé, rapports partagés par lien, webhook du fournisseur de paiement, message de maintenance.
import { prisma, asPlatform, asTenant, HttpError } from '../core.js'
import { buildPdf } from '../report.js'
import { stripe, handleWebhook } from '../billing.js'
import { queueStats } from '../queue.js'
import { rateLimit } from '../security.js'

export default async function publicRoutes(app: any) {
  app.get('/health', async () => {
    const db = await asPlatform(() => prisma.platformSetting.count()).then(() => 'ok').catch(() => 'error')
    const q = await queueStats().catch(() => null)
    return { status: db === 'ok' ? 'ok' : 'degraded', db, queue: q?.backend ?? 'unknown', time: new Date().toISOString() }
  })
  app.get('/public/maintenance', async () => {
    const m = await asPlatform(() => prisma.platformSetting.findUnique({ where: { key: 'maintenanceMessage' } }))
    return { message: m?.value ?? '' }
  })

  // Rapport partagé : accès par jeton à durée limitée (10.2 : partage uniquement avec les personnes autorisées)
  app.get('/public/reports/:token', async (req: any, reply: any) => {
    const r = rateLimit(`share:${req.ip}`, 30)
    if (!r.ok) throw new HttpError(429, 'Trop de requêtes')
    const token = String(req.params.token ?? '')
    if (!/^[A-Za-z0-9_-]{20,}$/.test(token)) throw new HttpError(404, 'Lien invalide')
    const rep = await asPlatform(() => prisma.report.findUnique({ where: { shareToken: token } }))
    if (!rep || !rep.scanId || (rep.shareExpiresAt && rep.shareExpiresAt < new Date())) throw new HttpError(404, 'Ce lien de partage est invalide ou a expiré')
    return asTenant(rep.orgId, async () => {
      const scan = await prisma.scan.findFirst({ where: { id: rep.scanId!, status: 'DONE' }, include: { application: true, findings: true, testResults: true, metrics: true } })
      if (!scan) throw new HttpError(404, 'Rapport introuvable')
      const org = await asPlatform(() => prisma.organization.findUnique({ where: { id: rep.orgId } }))
      await asPlatform(() => prisma.auditLog.create({ data: { orgId: rep.orgId, action: 'report.shared_view', detail: `${rep.id} consulté via lien partagé`, ip: req.ip ?? '' } }))
      const pdf = await buildPdf({ ...scan, summary: JSON.parse(scan.summary), comparison: null }, org?.name ?? '')
      return reply.header('content-type', 'application/pdf').header('content-disposition', `inline; filename="sentinelx-rapport-${scan.id}.pdf"`).header('x-robots-tag', 'noindex').send(pdf)
    })
  })

  // Webhook Stripe : corps brut requis pour vérifier la signature
  app.post('/billing/webhook', { config: { rawBody: true } }, async (req: any, reply: any) => {
    if (!stripe) throw new HttpError(404, 'Fournisseur de paiement non configuré')
    try {
      await handleWebhook(req.rawBody ?? Buffer.from(typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {})), String(req.headers['stripe-signature'] ?? ''))
    } catch (e: any) {
      return reply.code(400).send({ error: `Webhook refusé : ${e?.message ?? e}` })
    }
    return { received: true }
  })
}
