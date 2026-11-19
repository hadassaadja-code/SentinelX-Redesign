// Campagnes d'audit, constats (cycle de vie, affectation, commentaires), rapports et comparaisons.
import fs from 'node:fs'
import path from 'node:path'
import { config } from '../config.js'
import { prisma, asPlatform, HttpError, secured, str, audit, usage, withLock, alert, templates, recordUsage, roleCan } from '../core.js'
import { randomToken } from '../security.js'
import { enqueueScan } from '../queue.js'
import { buildPdf, buildCsv, buildSarif, buildSummaryPdf } from '../report.js'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const FINDING_STATUS = ['DETECTED', 'CONFIRMED', 'ASSIGNED', 'IN_PROGRESS', 'FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE']
const MODULES = ['QA', 'SECURITY', 'API', 'PERFORMANCE']
const OPEN_STATUS = ['FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE']
const order = (s: string) => SEVERITIES.indexOf(s)

export default async function scanRoutes(app: any) {
  // ================= CAMPAGNES =================
  app.get('/scans', secured('scan.read', async (ctx, req) => {
    const where: any = {}
    if (req.query?.applicationId) where.applicationId = String(req.query.applicationId)
    if (req.query?.status) where.status = String(req.query.status)
    const list = await prisma.scan.findMany({ where, orderBy: { createdAt: 'desc' }, take: Math.min(300, Number(req.query?.limit) || 100), include: { application: { select: { name: true, url: true, environment: true } } } })
    return list.map((s) => ({ ...s, summary: JSON.parse(s.summary), config: undefined }))
  }))

  app.post('/scans', secured('scan.run', async (ctx, req) => {
    const b = req.body ?? {}
    const profile = ['STANDARD', 'DEEP', 'LOAD'].includes(b.profile) ? b.profile : 'STANDARD'
    let modules: string[] = (Array.isArray(b.modules) ? b.modules : []).filter((m: any) => MODULES.includes(m))
    if (profile === 'LOAD') modules = ['PERFORMANCE']
    if (!modules.length) throw new HttpError(400, 'Sélectionnez au moins un module')
    if (modules.includes('API') && !ctx.plan.api) throw new HttpError(402, `Le module API n'est pas inclus dans la formule ${ctx.plan.label}`)
    if (profile === 'LOAD' && !roleCan(ctx.role, 'scan.load')) throw new HttpError(403, 'Les tests de charge sont réservés aux administrateurs et responsables techniques')
    return withLock(ctx.orgId, async () => {
      const a = await prisma.application.findFirst({ where: { id: str(b.applicationId) } })
      if (!a) throw new HttpError(404, 'Application introuvable')
      if (!a.authorized) throw new HttpError(403, "Aucun audit ne peut être lancé sans autorisation explicite sur la cible")
      if (a.authorizationExpires && a.authorizationExpires < new Date()) throw new HttpError(403, "L'autorisation d'audit de cette cible a expiré : renouvelez-la")
      if (config.requireEmailVerification && !ctx.user.emailVerifiedAt) throw new HttpError(403, 'Confirmez votre adresse e-mail avant de lancer un audit')
      if (profile === 'LOAD') {
        if (!a.authorizedScopes.includes('LOAD')) throw new HttpError(403, 'Les tests de charge exigent une autorisation spécifique « charge » sur cette cible')
        if (b.confirmLoad !== true) throw new HttpError(400, 'Confirmez explicitement le lancement du test de charge')
      }
      const u = await usage(ctx.orgId)
      if (u.scansThisMonth >= ctx.plan.scansPerMonth) {
        await alert(ctx.orgId, { type: 'QUOTA', title: 'Quota mensuel d\'audits atteint', body: `${ctx.plan.scansPerMonth} audits avec la formule ${ctx.plan.label}`, link: '/app/billing', mail: (to) => templates.quotaReached(to, `${ctx.plan.scansPerMonth} audits par mois`) })
        throw new HttpError(402, `Quota mensuel atteint : ${ctx.plan.scansPerMonth} audits avec la formule ${ctx.plan.label}`)
      }
      if (u.running >= ctx.plan.concurrent) throw new HttpError(429, `Limite d'audits simultanés atteinte (${ctx.plan.concurrent}). Attendez la fin de l'audit en cours.`)
      const cfg: any = {}
      if (profile === 'LOAD') {
        cfg.vus = Math.max(1, Math.min(Number(b.vus) || 5, ctx.plan.loadVus))
        cfg.seconds = Math.max(5, Math.min(Number(b.seconds) || 15, ctx.plan.loadSeconds))
        cfg.p95Ms = Math.max(100, Number(b.p95Ms) || 2000)
        cfg.errorRate = Math.max(0, Math.min(100, Number(b.errorRate) || 5))
        cfg.paths = (Array.isArray(b.paths) ? b.paths : []).map((p: any) => str(p, 200)).filter((p: string) => p.startsWith('/')).slice(0, 5)
      }
      const scan = await prisma.scan.create({ data: { orgId: ctx.orgId, applicationId: a.id, modules: [...new Set(modules)].join(','), profile, config: JSON.stringify(cfg), createdById: ctx.user.id } })
      await audit(req, ctx, profile === 'LOAD' ? 'scan.load_launch' : 'scan.launch', `${a.name} — ${profile} — modules : ${scan.modules}${profile === 'LOAD' ? ` — ${cfg.vus} VU / ${cfg.seconds} s` : ''}`)
      await recordUsage(ctx.orgId, 'scans')
      await enqueueScan(scan.id)
      return scan
    })
  }))

  async function loadScan(id: string) {
    const scan = await prisma.scan.findFirst({ where: { id }, include: { application: true, findings: { include: { comments: { orderBy: { createdAt: 'asc' } } } }, testResults: true, metrics: true } })
    if (!scan) throw new HttpError(404, 'Audit introuvable')
    scan.findings.sort((a, b) => order(a.severity) - order(b.severity))
    const prev = await prisma.scan.findFirst({ where: { applicationId: scan.applicationId, status: 'DONE', createdAt: { lt: scan.createdAt }, profile: { not: 'LOAD' }, id: { not: scan.id } }, orderBy: { createdAt: 'desc' }, include: { findings: true } })
    let comparison: any = null
    if (prev && scan.status === 'DONE' && scan.profile !== 'LOAD') {
      const before = new Set(prev.findings.map((f) => f.fingerprint)), now = new Set(scan.findings.map((f) => f.fingerprint))
      const ps = JSON.parse(prev.summary)
      comparison = {
        previousId: prev.id, previousDate: prev.createdAt, previousScore: prev.score,
        fixed: prev.findings.filter((f) => !now.has(f.fingerprint)).map((f) => f.title),
        added: scan.findings.filter((f) => !before.has(f.fingerprint)).map((f) => f.title),
        persistent: scan.findings.filter((f) => before.has(f.fingerprint)).length,
        previous: { qa: ps.qa?.rate ?? null, security: ps.security?.score ?? null, performance: ps.performance?.score ?? null, avgMs: ps.performance?.avg ?? null },
      }
    }
    const users = await asPlatform(() => prisma.user.findMany({ where: { id: { in: [...new Set([scan.createdById, ...scan.findings.map((f) => f.assigneeId).filter(Boolean) as string[]])] } }, select: { id: true, name: true } }))
    const uname = (id: string | null) => users.find((u) => u.id === id)?.name ?? null
    return { ...scan, application: { ...scan.application, scanHeaders: undefined }, config: JSON.parse(scan.config), summary: JSON.parse(scan.summary), comparison, createdBy: uname(scan.createdById), findings: scan.findings.map((f) => ({ ...f, assignee: uname(f.assigneeId) })) }
  }

  app.get('/scans/:id', secured('scan.read', async (ctx, req) => loadScan(req.params.id)))
  app.post('/scans/:id/cancel', secured('scan.cancel', async (ctx, req) => {
    const s = await prisma.scan.findFirst({ where: { id: req.params.id } })
    if (!s) throw new HttpError(404, 'Audit introuvable')
    if (s.status === 'QUEUED') await prisma.scan.update({ where: { id: s.id }, data: { status: 'CANCELED', cancelRequested: true, finishedAt: new Date(), stage: 'Annulé' } })
    else if (s.status === 'RUNNING') await prisma.scan.update({ where: { id: s.id }, data: { cancelRequested: true, stage: 'Annulation demandée' } })
    else throw new HttpError(409, 'Cet audit est déjà terminé')
    await audit(req, ctx, 'scan.cancel', s.id)
    return { ok: true }
  }))
  app.delete('/scans/:id', secured('scan.cancel', async (ctx, req) => {
    const s = await prisma.scan.findFirst({ where: { id: req.params.id } })
    if (!s) throw new HttpError(404, 'Audit introuvable')
    if (['QUEUED', 'RUNNING'].includes(s.status)) throw new HttpError(409, 'Annulez l\'audit avant de le supprimer')
    await prisma.scan.delete({ where: { id: s.id } })
    await audit(req, ctx, 'scan.delete', s.id)
    return { ok: true }
  }))

  app.get('/scans/:id/report', secured('report.download', async (ctx, req, reply) => {
    const scan = await loadScan(req.params.id)
    if (scan.status !== 'DONE') throw new HttpError(409, "Le rapport n'est disponible qu'une fois l'audit terminé")
    const fmt = String(req.query?.format ?? 'pdf')
    const file = `sentinelx-rapport-${scan.id}`
    await audit(req, ctx, 'report.download', `${scan.id} (${fmt})`)
    if (fmt === 'json') return reply.header('content-disposition', `attachment; filename="${file}.json"`).send({ ...scan, application: { ...scan.application, verificationToken: undefined } })
    if (fmt === 'csv') return reply.header('content-type', 'text/csv; charset=utf-8').header('content-disposition', `attachment; filename="${file}.csv"`).send(buildCsv(scan))
    if (fmt === 'sarif') return reply.header('content-type', 'application/sarif+json').header('content-disposition', `attachment; filename="${file}.sarif"`).send(buildSarif(scan))
    const pdf = await buildPdf(scan, ctx.org.name)
    return reply.header('content-type', 'application/pdf').header('content-disposition', `${req.query?.inline ? 'inline' : 'attachment'}; filename="${file}.pdf"`).send(pdf)
  }))

  app.get('/scans/:id/screenshot/:name', secured('scan.read', async (ctx, req, reply) => {
    const scan = await prisma.scan.findFirst({ where: { id: req.params.id }, select: { id: true } })
    if (!scan) throw new HttpError(404, 'Audit introuvable')
    const name = String(req.params.name)
    if (!/^[a-z0-9-]+\.png$/.test(name) || !name.startsWith(scan.id)) throw new HttpError(404, 'Capture introuvable')
    const file = path.join(config.screenshotsDir, name)
    if (!fs.existsSync(file)) throw new HttpError(404, 'Capture introuvable')
    return reply.header('content-type', 'image/png').header('cache-control', 'private, max-age=3600').send(fs.createReadStream(file))
  }))

  // ================= CONSTATS (6.5) =================
  app.get('/findings', secured('finding.read', async (ctx, req) => {
    const q = req.query ?? {}
    const where: any = {}
    if (SEVERITIES.includes(q.severity)) where.severity = q.severity
    if (FINDING_STATUS.includes(q.status)) where.status = q.status
    if (q.open === 'true') where.status = { notIn: OPEN_STATUS }
    if (q.applicationId) where.applicationId = String(q.applicationId)
    if (q.module && ['SECURITY', 'API', 'QA', 'PERFORMANCE'].includes(q.module)) where.module = q.module
    if (q.assignee === 'me') where.assigneeId = ctx.user.id
    if (q.q) where.OR = [{ title: { contains: String(q.q) } }, { resource: { contains: String(q.q) } }, { cwe: { contains: String(q.q) } }]
    // Par défaut : dernière occurrence de chaque empreinte (pas de doublons entre campagnes)
    const list = await prisma.finding.findMany({ where, orderBy: { createdAt: 'desc' }, take: 1000, include: { scan: { select: { application: { select: { name: true } }, createdAt: true } }, _count: { select: { comments: true } } } })
    const seen = new Set<string>()
    const latest = q.all === 'true' ? list : list.filter((f) => {
      const k = `${f.applicationId}|${f.fingerprint}`
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
    const users = await asPlatform(() => prisma.user.findMany({ where: { id: { in: [...new Set(latest.map((f) => f.assigneeId).filter(Boolean) as string[])] } }, select: { id: true, name: true } }))
    return latest.sort((a, b) => order(a.severity) - order(b.severity)).slice(0, 400).map((f) => ({ ...f, application: f.scan.application.name, scan: undefined, comments: f._count.comments, _count: undefined, assignee: users.find((u) => u.id === f.assigneeId)?.name ?? null }))
  }))
  app.get('/findings/stats', secured('finding.read', async () => {
    const [byStatus, bySev, byCat] = await Promise.all([
      prisma.finding.groupBy({ by: ['status'], _count: true }),
      prisma.finding.groupBy({ by: ['severity'], where: { status: { notIn: OPEN_STATUS } }, _count: true }),
      prisma.finding.groupBy({ by: ['category'], where: { status: { notIn: OPEN_STATUS } }, _count: true }),
    ])
    return { byStatus: Object.fromEntries(byStatus.map((x: any) => [x.status, x._count])), bySeverity: Object.fromEntries(bySev.map((x: any) => [x.severity, x._count])), byCategory: Object.fromEntries(byCat.map((x: any) => [x.category, x._count])) }
  }))
  app.patch('/findings/:id', secured('finding.update', async (ctx, req) => {
    const b = req.body ?? {}
    const data: any = {}
    if (b.status !== undefined) {
      const status = String(b.status)
      if (!FINDING_STATUS.includes(status)) throw new HttpError(400, 'Statut invalide')
      if (status === 'FALSE_POSITIVE' && !str(b.note, 500)) throw new HttpError(400, 'Un faux positif doit être justifié')
      data.status = status
    }
    if (b.note !== undefined) data.note = str(b.note, 500)
    if (b.assigneeId !== undefined) {
      if (!roleCan(ctx.role, 'finding.assign')) throw new HttpError(403, 'Seuls les administrateurs et responsables techniques affectent les anomalies')
      const id = str(b.assigneeId) || null
      if (id && !(await prisma.organizationMember.findFirst({ where: { orgId: ctx.orgId, userId: id } }))) throw new HttpError(400, 'Membre invalide')
      data.assigneeId = id
      if (id && !data.status) data.status = 'ASSIGNED'
    }
    const f = await prisma.finding.findFirst({ where: { id: req.params.id } })
    if (!f) throw new HttpError(404, 'Constat introuvable')
    // Le changement s'applique à toutes les occurrences du même constat sur l'application (empreinte)
    if (b.propagate !== false) await prisma.finding.updateMany({ where: { applicationId: f.applicationId, fingerprint: f.fingerprint }, data })
    else await prisma.finding.update({ where: { id: f.id }, data })
    await audit(req, ctx, 'finding.update', `${f.title} → ${JSON.stringify(data)}`)
    return { ok: true }
  }))
  app.get('/findings/:id/comments', secured('finding.read', async (ctx, req) => prisma.findingComment.findMany({ where: { findingId: req.params.id }, orderBy: { createdAt: 'asc' } })))
  app.post('/findings/:id/comments', secured('finding.comment', async (ctx, req) => {
    const text = str(req.body?.text, 2000)
    if (!text) throw new HttpError(400, 'Commentaire vide')
    const f = await prisma.finding.findFirst({ where: { id: req.params.id } })
    if (!f) throw new HttpError(404, 'Constat introuvable')
    const c = await prisma.findingComment.create({ data: { orgId: ctx.orgId, findingId: f.id, userId: ctx.user.id, userName: ctx.user.name, text } })
    return c
  }))

  // ================= RAPPORTS (10.2) =================
  app.get('/reports', secured('report.read', async () => {
    const [scans, shares] = await Promise.all([
      prisma.scan.findMany({ where: { status: 'DONE' }, orderBy: { createdAt: 'desc' }, take: 200, include: { application: { select: { name: true, environment: true } } } }),
      prisma.report.findMany({ where: { shareToken: { not: null } }, orderBy: { createdAt: 'desc' } }),
    ])
    return { scans: scans.map((s) => ({ id: s.id, application: s.application, createdAt: s.createdAt, modules: s.modules, profile: s.profile, score: s.score, summary: JSON.parse(s.summary) })), shares: shares.map((r) => ({ id: r.id, scanId: r.scanId, title: r.title, url: `${config.appUrl}/api/public/reports/${r.shareToken}`, expiresAt: r.shareExpiresAt, createdAt: r.createdAt })) }
  }))
  app.post('/reports/share', secured('report.share', async (ctx, req) => {
    const scan = await prisma.scan.findFirst({ where: { id: str(req.body?.scanId), status: 'DONE' }, include: { application: { select: { name: true } } } })
    if (!scan) throw new HttpError(404, 'Audit terminé introuvable')
    const days = Math.max(1, Math.min(30, Number(req.body?.days) || 7))
    const token = randomToken(24)
    const r = await prisma.report.create({ data: { orgId: ctx.orgId, scanId: scan.id, kind: 'SCAN', title: `Rapport ${scan.application.name} — ${scan.createdAt.toLocaleDateString('fr-FR')}`, shareToken: token, shareExpiresAt: new Date(Date.now() + days * 86400_000), createdById: ctx.user.id } })
    await audit(req, ctx, 'report.share', `${scan.id} — ${days} jour(s)`)
    return { id: r.id, url: `${config.appUrl}/api/public/reports/${token}`, expiresAt: r.shareExpiresAt }
  }))
  app.delete('/reports/:id/share', secured('report.share', async (ctx, req) => {
    const r = await prisma.report.updateMany({ where: { id: req.params.id }, data: { shareToken: null, shareExpiresAt: null } })
    if (!r.count) throw new HttpError(404, 'Partage introuvable')
    await audit(req, ctx, 'report.unshare', req.params.id)
    return { ok: true }
  }))
  app.get('/reports/compare', secured('report.read', async (ctx, req) => {
    const [a, b] = await Promise.all([loadScan(str(req.query?.a)), loadScan(str(req.query?.b))])
    const fa = new Map(a.findings.map((f) => [f.fingerprint, f])), fb = new Map(b.findings.map((f) => [f.fingerprint, f]))
    const metric = (s: any, name: string) => s.metrics.find((m: any) => m.name === name)?.value ?? null
    return {
      a: { id: a.id, date: a.createdAt, score: a.score, app: a.application.name, summary: a.summary }, b: { id: b.id, date: b.createdAt, score: b.score, app: b.application.name, summary: b.summary },
      fixed: [...fa.values()].filter((f) => !fb.has(f.fingerprint)).map((f) => ({ title: f.title, severity: f.severity })),
      added: [...fb.values()].filter((f) => !fa.has(f.fingerprint)).map((f) => ({ title: f.title, severity: f.severity })),
      persistent: [...fb.values()].filter((f) => fa.has(f.fingerprint)).map((f) => ({ title: f.title, severity: f.severity })),
      tests: { a: a.testResults.filter((t) => t.status === 'PASS').length, b: b.testResults.filter((t) => t.status === 'PASS').length, totalA: a.testResults.length, totalB: b.testResults.length },
      perf: ['Average Response Time', 'P95 Response Time', 'Error Rate', 'Largest Contentful Paint'].map((n) => ({ name: n, a: metric(a, n), b: metric(b, n) })),
    }
  }))
  app.get('/reports/summary', secured('report.download', async (ctx, req, reply) => {
    const to = req.query?.to ? new Date(String(req.query.to)) : new Date()
    const from = req.query?.from ? new Date(String(req.query.from)) : new Date(to.getTime() - 30 * 86400_000)
    if (isNaN(from.getTime()) || isNaN(to.getTime())) throw new HttpError(400, 'Dates invalides')
    const [apps, scans, findings, incidents] = await Promise.all([
      prisma.application.findMany({ orderBy: { name: 'asc' } }),
      prisma.scan.findMany({ where: { createdAt: { gte: from, lte: to } }, orderBy: { createdAt: 'asc' } }),
      prisma.finding.findMany({ where: { createdAt: { gte: from, lte: to } }, orderBy: { createdAt: 'desc' } }),
      prisma.incident.findMany({ where: { startedAt: { gte: from, lte: to } }, orderBy: { startedAt: 'desc' } }),
    ])
    const seen = new Set<string>()
    const latest = findings.filter((f) => { const k = `${f.applicationId}|${f.fingerprint}`; if (seen.has(k)) return false; seen.add(k); return true }).sort((a, b) => order(a.severity) - order(b.severity))
    const uptime: Record<string, number | null> = {}
    for (const a of apps) {
      const [t, u] = await Promise.all([prisma.monitorCheck.count({ where: { applicationId: a.id, at: { gte: from, lte: to } } }), prisma.monitorCheck.count({ where: { applicationId: a.id, at: { gte: from, lte: to }, up: true } })])
      uptime[a.id] = t ? Math.round((u / t) * 1000) / 10 : null
    }
    const pdf = await buildSummaryPdf({ orgName: ctx.org.name, from, to, apps, scans, findings: latest, incidents, uptime })
    await audit(req, ctx, 'report.summary', `${from.toISOString().slice(0, 10)} → ${to.toISOString().slice(0, 10)}`)
    return reply.header('content-type', 'application/pdf').header('content-disposition', `attachment; filename="sentinelx-synthese-${from.toISOString().slice(0, 10)}.pdf"`).send(pdf)
  }))
}
