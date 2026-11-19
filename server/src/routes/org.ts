// Organisation : tableau de bord, projets, applications et autorisations, membres et invitations, abonnement, paramètres.
import { config } from '../config.js'
import { prisma, asPlatform, HttpError, PLANS, planOf, ROLES, secured, str, EMAIL, audit, usage, withLock, templates, sendMail, alert, sendWebhook, hashPassword, recordUsage } from '../core.js'
import { encrypt, randomToken, sha256 } from '../security.js'
import { assertAllowedUrl } from '../scanners/http.js'
import { verifyOwnership, VERIFY_PREFIX } from '../verify.js'
import { billingMode, createCheckout, createPortal, stripe } from '../billing.js'
import { checkApplication } from '../monitor.js'

const ENVS = ['DEVELOPMENT', 'STAGING', 'PRODUCTION']
const SCOPES = ['PASSIVE', 'ACTIVE', 'LOAD']
const OPEN_STATUS = ['FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE']

async function uptime(appId: string, hours: number): Promise<number | null> {
  const since = new Date(Date.now() - hours * 3600_000)
  const [total, up] = await Promise.all([prisma.monitorCheck.count({ where: { applicationId: appId, at: { gte: since } } }), prisma.monitorCheck.count({ where: { applicationId: appId, at: { gte: since }, up: true } })])
  return total ? Math.round((up / total) * 1000) / 10 : null
}

export default async function orgRoutes(app: any) {
  // ================= TABLEAU DE BORD (10.1) =================
  app.get('/dashboard', secured('project.read', async (ctx) => {
    const orgId = ctx.orgId
    const open = { status: { notIn: OPEN_STATUS } }
    const d30 = new Date(Date.now() - 30 * 86400_000), d7 = new Date(Date.now() - 7 * 86400_000)
    const [projects, apps, scans, bySev, byModule, incidents, recent, newFindings, fixedFindings, openIncidents, byApp] = await Promise.all([
      prisma.project.count({ where: { archived: false } }),
      prisma.application.findMany({ select: { id: true, name: true, url: true, environment: true, lastStatus: true, lastResponseMs: true, monitoring: true, authorized: true, verifiedAt: true, sslExpiresAt: true, lastCheckedAt: true } }),
      prisma.scan.count(),
      prisma.finding.groupBy({ by: ['severity'], where: open, _count: true }),
      prisma.finding.groupBy({ by: ['module'], where: open, _count: true }),
      prisma.incident.findMany({ orderBy: { startedAt: 'desc' }, take: 6, include: { application: { select: { name: true } } } }),
      prisma.scan.findMany({ where: { status: 'DONE' }, orderBy: { createdAt: 'desc' }, take: 20, include: { application: { select: { name: true } } } }),
      prisma.finding.findMany({ where: { createdAt: { gte: d30 }, occurrences: 1 }, select: { createdAt: true, severity: true } }),
      prisma.finding.count({ where: { status: { in: ['FIXED', 'RETESTED', 'CLOSED'] }, createdAt: { gte: d30 } } }),
      prisma.incident.count({ where: { status: { in: ['OPEN', 'ACKNOWLEDGED'] } } }),
      prisma.finding.groupBy({ by: ['applicationId'], where: { ...open, severity: { in: ['CRITICAL', 'HIGH'] } }, _count: true }),
    ])
    const sev: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    bySev.forEach((s: any) => (sev[s.severity] = s._count))
    const modules: any = {}
    byModule.forEach((m: any) => (modules[m.module] = m._count))
    const sums = recent.map((s) => ({ ...JSON.parse(s.summary), id: s.id, appId: s.applicationId }))
    const avg = (a: number[]) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null)
    // Constats créés par jour sur 30 jours
    const days: Record<string, number> = {}
    for (let i = 29; i >= 0; i--) days[new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10)] = 0
    for (const f of newFindings) {
      const k = f.createdAt.toISOString().slice(0, 10)
      if (k in days) days[k]++
    }
    const uptimes = await Promise.all(apps.filter((a) => a.monitoring).map(async (a) => [a.id, await uptime(a.id, 24)] as const))
    const lastScore = new Map<string, number | null>()
    for (const s of recent) if (!lastScore.has(s.applicationId)) lastScore.set(s.applicationId, s.score)
    const highByApp = Object.fromEntries(byApp.map((b: any) => [b.applicationId, b._count]))
    // Temps moyen de correction (constats corrigés sur 30 jours)
    const fixed = await prisma.finding.findMany({ where: { status: { in: ['FIXED', 'RETESTED', 'CLOSED'] }, createdAt: { gte: d30 } }, select: { firstSeenAt: true, createdAt: true }, take: 200 })
    const mttrDays = fixed.length ? Math.round(fixed.reduce((a, f) => a + (f.createdAt.getTime() - f.firstSeenAt.getTime()), 0) / fixed.length / 86400_000 * 10) / 10 : null
    return {
      projects, applications: apps.length, scans, severities: sev, modules,
      openFindings: Object.values(sev).reduce((a: any, b: any) => a + b, 0),
      qaRate: avg(sums.filter((s) => s.qa?.rate != null).map((s) => s.qa.rate)),
      perfScore: avg(sums.filter((s) => s.performance?.score != null).map((s) => s.performance.score)),
      securityScore: avg(sums.filter((s) => s.security?.score != null).map((s) => s.security.score)),
      scansThisWeek: await prisma.scan.count({ where: { createdAt: { gte: d7 } } }),
      fixedFindings, openIncidents, mttrDays,
      apps: apps.map((a) => ({ ...a, uptime24h: uptimes.find(([id]) => id === a.id)?.[1] ?? null, lastScore: lastScore.get(a.id) ?? null, highOpen: highByApp[a.id] ?? 0 })),
      incidents,
      trend: recent.slice().reverse().map((s) => ({ id: s.id, app: s.application.name, score: s.score, date: s.createdAt })),
      findingsPerDay: Object.entries(days).map(([date, n]) => ({ date, n })),
      usage: await usage(orgId), plan: ctx.plan,
    }
  }))

  // ================= PROJETS (4.1) =================
  app.get('/projects', secured('project.read', async () => {
    const list = await prisma.project.findMany({ orderBy: { createdAt: 'desc' }, include: { applications: { orderBy: { createdAt: 'asc' }, include: { _count: { select: { scans: true } } } } } })
    const users = await asPlatform(() => prisma.user.findMany({ where: { id: { in: [...new Set(list.flatMap((p) => [p.techLeadId, ...p.applications.map((a) => a.ownerId)]).filter(Boolean) as string[])] } }, select: { id: true, name: true } }))
    const name = (id: string | null) => users.find((u) => u.id === id)?.name ?? null
    return list.map((p) => ({ ...p, techLead: name(p.techLeadId), applications: p.applications.map((a) => ({ ...a, scanHeaders: undefined, hasHeaders: !!a.scanHeaders, owner: name(a.ownerId), scanCount: a._count.scans })) }))
  }))
  app.get('/projects/:id/stats', secured('project.read', async (ctx, req) => {
    const p = await prisma.project.findFirst({ where: { id: req.params.id }, include: { applications: { select: { id: true } } } })
    if (!p) throw new HttpError(404, 'Projet introuvable')
    const ids = p.applications.map((a) => a.id)
    const [scans, findings, incidents, last] = await Promise.all([
      prisma.scan.count({ where: { applicationId: { in: ids } } }),
      prisma.finding.groupBy({ by: ['severity'], where: { applicationId: { in: ids }, status: { notIn: OPEN_STATUS } }, _count: true }),
      prisma.incident.count({ where: { applicationId: { in: ids } } }),
      prisma.scan.findMany({ where: { applicationId: { in: ids }, status: 'DONE' }, orderBy: { createdAt: 'desc' }, take: 10, select: { score: true, createdAt: true, applicationId: true } }),
    ])
    return { scans, findings: Object.fromEntries(findings.map((f: any) => [f.severity, f._count])), incidents, avgScore: last.length ? Math.round(last.reduce((a, s) => a + (s.score ?? 0), 0) / last.length) : null }
  }))
  app.post('/projects', secured('project.manage', async (ctx, req) => {
    const name = str(req.body?.name, 80)
    if (!name) throw new HttpError(400, 'Nom du projet requis')
    const techLeadId = str(req.body?.techLeadId) || null
    if (techLeadId && !(await prisma.organizationMember.findFirst({ where: { orgId: ctx.orgId, userId: techLeadId } }))) throw new HttpError(400, 'Responsable technique invalide')
    const p = await prisma.project.create({ data: { orgId: ctx.orgId, name, description: str(req.body?.description, 500), techLeadId } })
    await audit(req, ctx, 'project.create', name)
    return p
  }))
  app.patch('/projects/:id', secured('project.manage', async (ctx, req) => {
    const data: any = {}
    const b = req.body ?? {}
    if (b.name !== undefined) data.name = str(b.name, 80) || undefined
    if (b.description !== undefined) data.description = str(b.description, 500)
    if (b.archived !== undefined) data.archived = !!b.archived
    if (b.techLeadId !== undefined) {
      const id = str(b.techLeadId) || null
      if (id && !(await prisma.organizationMember.findFirst({ where: { orgId: ctx.orgId, userId: id } }))) throw new HttpError(400, 'Responsable technique invalide')
      data.techLeadId = id
    }
    const r = await prisma.project.updateMany({ where: { id: req.params.id }, data })
    if (!r.count) throw new HttpError(404, 'Projet introuvable')
    await audit(req, ctx, 'project.update', req.params.id)
    return { ok: true }
  }))
  app.delete('/projects/:id', secured('project.delete', async (ctx, req) => {
    const p = await prisma.project.findFirst({ where: { id: req.params.id } })
    if (!p) throw new HttpError(404, 'Projet introuvable')
    if (!p.archived && req.body?.confirm !== p.name) throw new HttpError(400, 'Suppression contrôlée : archivez le projet ou confirmez en saisissant son nom exact')
    await prisma.project.delete({ where: { id: p.id } })
    await audit(req, ctx, 'project.delete', p.name)
    return { ok: true }
  }))

  // ================= APPLICATIONS (4.3) =================
  app.get('/applications', secured('project.read', async () => {
    const list = await prisma.application.findMany({ orderBy: { createdAt: 'desc' }, include: { project: { select: { name: true } } } })
    return list.map((a) => ({ ...a, scanHeaders: undefined, hasHeaders: !!a.scanHeaders }))
  }))
  const appData = (b: any, ctx: any, data: any = {}) => {
    if (b.name !== undefined) data.name = str(b.name, 80) || undefined
    if (b.description !== undefined) data.description = str(b.description, 500)
    if (b.environment !== undefined && ENVS.includes(b.environment)) data.environment = b.environment
    if (b.type !== undefined) data.type = b.type === 'API' ? 'API' : 'WEB'
    if (b.technologies !== undefined) data.technologies = str(b.technologies, 200)
    if (b.openapiUrl !== undefined) {
      const v = str(b.openapiUrl, 500)
      if (v) {
        try {
          assertAllowedUrl(v)
        } catch (e: any) {
          throw new HttpError(400, `URL OpenAPI : ${e.message}`)
        }
      }
      data.openapiUrl = v || null
    }
    if (b.allowedPaths !== undefined) data.allowedPaths = str(b.allowedPaths, 2000)
    if (b.excludedPaths !== undefined) data.excludedPaths = str(b.excludedPaths, 2000)
    if (b.maxRequestsPerScan !== undefined) data.maxRequestsPerScan = Math.max(20, Math.min(2000, Number(b.maxRequestsPerScan) || 300))
    if (b.perfBudgetMs !== undefined) data.perfBudgetMs = Math.max(0, Math.min(60000, Number(b.perfBudgetMs) || 0))
    if (b.browsers !== undefined) data.browsers = (Array.isArray(b.browsers) ? b.browsers : String(b.browsers).split(',')).map((x: string) => x.trim()).filter((x: string) => ctx.plan.browsers.includes(x)).join(',') || 'chromium'
    if (b.scheduleHours !== undefined) data.scheduleHours = [0, 24, 168].includes(Number(b.scheduleHours)) ? Number(b.scheduleHours) : 0
    if (b.scheduleModules !== undefined) data.scheduleModules = (Array.isArray(b.scheduleModules) ? b.scheduleModules : []).filter((m: string) => ['QA', 'SECURITY', 'API', 'PERFORMANCE'].includes(m)).join(',') || 'QA,SECURITY,PERFORMANCE'
    if (b.scanHeaders !== undefined) {
      const h = b.scanHeaders && typeof b.scanHeaders === 'object' ? Object.fromEntries(Object.entries(b.scanHeaders).filter(([k, v]) => /^[a-z0-9-]+$/i.test(k) && typeof v === 'string').slice(0, 10).map(([k, v]) => [k.toLowerCase(), String(v).slice(0, 500)])) : {}
      data.scanHeaders = Object.keys(h).length ? encrypt(JSON.stringify(h)) : ''
    }
    if (b.monitoring !== undefined) data.monitoring = !!b.monitoring
    if (b.monitorInterval !== undefined) {
      const n = Number(b.monitorInterval), min = ctx.plan.minMonitorInterval
      if (![5, 15, 30, 60].includes(n)) throw new HttpError(400, 'Fréquence invalide (5, 15, 30 ou 60 minutes)')
      if (n < min) throw new HttpError(402, `Votre formule autorise une fréquence minimale de ${min} minutes`)
      data.monitorInterval = n
    }
    if (b.monitorExpectStatus !== undefined) data.monitorExpectStatus = Math.max(0, Math.min(599, Number(b.monitorExpectStatus) || 0))
    if (b.monitorKeyword !== undefined) data.monitorKeyword = str(b.monitorKeyword, 100)
    if (b.monitorMaxMs !== undefined) data.monitorMaxMs = Math.max(0, Math.min(60000, Number(b.monitorMaxMs) || 0))
    if (b.monitorFailThreshold !== undefined) data.monitorFailThreshold = Math.max(1, Math.min(10, Number(b.monitorFailThreshold) || 2))
    if (b.sslDaysWarn !== undefined) data.sslDaysWarn = Math.max(1, Math.min(90, Number(b.sslDaysWarn) || 30))
    if (b.ownerId !== undefined) data.ownerId = str(b.ownerId) || null
    return data
  }
  app.post('/applications', secured('application.manage', async (ctx, req) => {
    const b = req.body ?? {}
    const name = str(b.name, 80)
    if (!name) throw new HttpError(400, "Nom de l'application requis")
    let url: URL
    try {
      url = assertAllowedUrl(str(b.url, 500))
    } catch (e: any) {
      throw new HttpError(400, e.message)
    }
    return withLock(ctx.orgId, async () => {
      const project = await prisma.project.findFirst({ where: { id: str(b.projectId) } })
      if (!project) throw new HttpError(404, 'Projet introuvable')
      if ((await prisma.application.count()) >= ctx.plan.apps) {
        await alert(ctx.orgId, { type: 'QUOTA', title: 'Quota d\'applications atteint', body: `${ctx.plan.apps} application(s) maximum avec la formule ${ctx.plan.label}`, link: '/app/billing' })
        throw new HttpError(402, `Quota atteint : ${ctx.plan.apps} application(s) maximum avec la formule ${ctx.plan.label}`)
      }
      const data = appData(b, ctx, { orgId: ctx.orgId, projectId: project.id, name, url: url.href, monitorInterval: ctx.plan.minMonitorInterval, verificationToken: randomToken(16) })
      const a = await prisma.application.create({ data })
      await audit(req, ctx, 'application.create', `${name} (${url.href})`)
      return { ...a, scanHeaders: undefined }
    })
  }))
  app.patch('/applications/:id', secured('application.manage', async (ctx, req) => {
    const b = req.body ?? {}
    const data = appData(b, ctx)
    if (b.url !== undefined) {
      try {
        data.url = assertAllowedUrl(str(b.url, 500)).href
      } catch (e: any) {
        throw new HttpError(400, e.message)
      }
      const cur = await prisma.application.findFirst({ where: { id: req.params.id } })
      if (cur && new URL(cur.url).host !== new URL(data.url).host) Object.assign(data, { authorized: false, authorizedAt: null, verifiedAt: null, verificationMethod: null, authorizedScopes: 'PASSIVE' }) // nouvelle cible = nouvelle autorisation
    }
    if (data.scheduleHours !== undefined) data.nextScanAt = data.scheduleHours ? new Date(Date.now() + data.scheduleHours * 3600_000) : null
    const r = await prisma.application.updateMany({ where: { id: req.params.id }, data })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.update', `${req.params.id} : ${Object.keys(data).join(', ')}`)
    return { ok: true }
  }))
  app.delete('/applications/:id', secured('application.delete', async (ctx, req) => {
    const r = await prisma.application.deleteMany({ where: { id: req.params.id } })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.delete', req.params.id)
    return { ok: true }
  }))

  // ----- Autorisation d'audit (14.4) : déclaration, périmètre, vérification de propriété -----
  app.get('/applications/:id/verification', secured('project.read', async (ctx, req) => {
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    const token = a.verificationToken ?? (await prisma.application.update({ where: { id: a.id }, data: { verificationToken: randomToken(16) } })).verificationToken!
    const host = new URL(a.url).hostname
    return {
      token, verifiedAt: a.verifiedAt, method: a.verificationMethod,
      methods: [
        { id: 'DNS', label: 'Enregistrement DNS TXT', instructions: `Créer un enregistrement TXT sur _sentinelx.${host} (ou ${host}) avec la valeur : ${VERIFY_PREFIX}${token}` },
        { id: 'HTTP', label: 'Fichier .well-known', instructions: `Publier le fichier ${new URL(a.url).origin}/.well-known/sentinelx-verification.txt contenant : ${VERIFY_PREFIX}${token}` },
        { id: 'META', label: 'Balise meta', instructions: `Ajouter dans le <head> de la page principale : <meta name="sentinelx-verify" content="${token}">` },
      ],
    }
  }))
  app.post('/applications/:id/verify', secured('application.authorize', async (ctx, req) => {
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    if (!a.verificationToken) throw new HttpError(400, 'Jeton de vérification absent')
    const r = await verifyOwnership(a.url, a.verificationToken)
    if (r.ok) {
      await prisma.application.update({ where: { id: a.id }, data: { verifiedAt: new Date(), verificationMethod: r.method } })
      await audit(req, ctx, 'application.verified', `${a.name} — ${r.method} : ${r.detail}`)
    } else await audit(req, ctx, 'application.verify_failed', `${a.name} — ${r.detail}`)
    return r
  }))
  app.post('/applications/:id/authorize', secured('application.authorize', async (ctx, req) => {
    const b = req.body ?? {}
    if (b.declaration !== true) throw new HttpError(400, 'Vous devez déclarer être propriétaire de la cible ou détenir une autorisation écrite')
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    const scopes = (Array.isArray(b.scopes) ? b.scopes : ['PASSIVE']).filter((s: string) => SCOPES.includes(s))
    if (!scopes.includes('PASSIVE')) scopes.unshift('PASSIVE')
    // Les contrôles actifs et les tests de charge exigent une validation spécifique : propriété vérifiée ou environnement hors production
    if ((scopes.includes('ACTIVE') || scopes.includes('LOAD')) && !a.verifiedAt && a.environment === 'PRODUCTION') throw new HttpError(400, 'Les contrôles actifs et tests de charge sur un environnement de production exigent une vérification préalable de la propriété du domaine (DNS, fichier ou balise meta).')
    if (scopes.includes('ACTIVE') && !ctx.plan.activeScans) throw new HttpError(402, `Les contrôles actifs ne sont pas inclus dans la formule ${ctx.plan.label}`)
    if ((scopes.includes('ACTIVE') || scopes.includes('LOAD')) && b.activeDeclaration !== true) throw new HttpError(400, 'Confirmez explicitement l\'autorisation des contrôles actifs / tests de charge')
    const months = Math.max(1, Math.min(24, Number(b.months) || 12))
    await prisma.application.update({ where: { id: a.id }, data: { authorized: true, authorizedAt: new Date(), authorizedBy: ctx.user.id, authorizedScopes: scopes.join(','), authorizationExpires: new Date(Date.now() + months * 30 * 86400_000) } })
    await audit(req, ctx, 'application.authorize', `Déclaration de propriété/autorisation par ${ctx.user.email} pour ${a.name} (${a.url}) — périmètre ${scopes.join(',')} — ${months} mois${a.verifiedAt ? ' — propriété vérifiée' : ''}`)
    return { ok: true }
  }))
  app.post('/applications/:id/revoke-authorization', secured('application.authorize', async (ctx, req) => {
    const r = await prisma.application.updateMany({ where: { id: req.params.id }, data: { authorized: false, authorizedScopes: 'PASSIVE', monitoring: false, scheduleHours: 0, nextScanAt: null } })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.authorization_revoked', req.params.id)
    return { ok: true }
  }))
  app.post('/applications/:id/check', secured('monitoring.check', async (ctx, req) => {
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    if (!a.authorized) throw new HttpError(403, 'Autorisation requise avant toute vérification de cette cible')
    return checkApplication(a, true)
  }))
  app.get('/applications/:id/history', secured('scan.read', async (ctx, req) => {
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    const scans = await prisma.scan.findMany({ where: { applicationId: a.id, status: 'DONE' }, orderBy: { createdAt: 'asc' }, take: 60, select: { id: true, createdAt: true, score: true, summary: true, modules: true, profile: true } })
    const checks = await prisma.monitorCheck.findMany({ where: { applicationId: a.id, at: { gte: new Date(Date.now() - 7 * 86400_000) } }, orderBy: { at: 'asc' }, select: { at: true, up: true, responseMs: true, httpCode: true } })
    return {
      scans: scans.map((s) => {
        const sum = JSON.parse(s.summary)
        return { id: s.id, date: s.createdAt, score: s.score, modules: s.modules, profile: s.profile, qa: sum.qa?.rate ?? null, security: sum.security?.score ?? null, api: sum.api?.score ?? null, performance: sum.performance?.score ?? null, avgMs: sum.performance?.avg ?? null, p95: sum.performance?.p95 ?? null, lcp: sum.performance?.vitals?.lcp ?? null, findings: sum.security?.total ?? 0 }
      }),
      checks, uptime24h: await uptime(a.id, 24), uptime7d: await uptime(a.id, 168), uptime30d: await uptime(a.id, 720),
    }
  }))
  app.post('/applications/:id/baseline/reset', secured('application.manage', async (ctx, req) => {
    const a = await prisma.application.findFirst({ where: { id: req.params.id } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    const fs = await import('node:fs')
    const path = await import('node:path')
    for (const b of ['chromium', 'firefox', 'webkit']) fs.rmSync(path.join(config.screenshotsDir, `baseline-${a.id}-${b}.png`), { force: true })
    await audit(req, ctx, 'application.baseline_reset', a.name)
    return { ok: true }
  }))

  // ================= MEMBRES ET INVITATIONS =================
  app.get('/members', secured('member.read', async (ctx) => {
    const list = await prisma.organizationMember.findMany({ where: { orgId: ctx.orgId }, include: { user: { select: { id: true, name: true, email: true, createdAt: true, totpEnabled: true, emailVerifiedAt: true, lastLoginAt: true } } } })
    return list.map((m) => ({ id: m.user.id, memberId: m.id, role: m.role, name: m.user.name, email: m.user.email, createdAt: m.createdAt, totpEnabled: m.user.totpEnabled, emailVerified: !!m.user.emailVerifiedAt, lastLoginAt: m.user.lastLoginAt, self: m.userId === ctx.user.id }))
  }))
  app.get('/members/invitations', secured('member.manage', async (ctx) => {
    const list = await asPlatform(() => prisma.token.findMany({ where: { kind: 'INVITE', orgId: ctx.orgId, usedAt: null, expiresAt: { gt: new Date() } }, orderBy: { createdAt: 'desc' } }))
    return list.map((t) => ({ id: t.id, email: t.email, role: JSON.parse(t.data).role, createdAt: t.createdAt, expiresAt: t.expiresAt }))
  }))
  app.post('/members/invite', secured('member.manage', async (ctx, req) => {
    const email = str(req.body?.email, 160).toLowerCase()
    const role = ROLES.includes(req.body?.role) ? req.body.role : 'READER'
    if (!EMAIL.test(email)) throw new HttpError(400, 'Adresse e-mail invalide')
    return withLock(ctx.orgId, async () => {
      const pending = await asPlatform(() => prisma.token.count({ where: { kind: 'INVITE', orgId: ctx.orgId, usedAt: null, expiresAt: { gt: new Date() } } }))
      if ((await prisma.organizationMember.count({ where: { orgId: ctx.orgId } })) + pending >= ctx.plan.members) throw new HttpError(402, `Quota atteint : ${ctx.plan.members} collaborateur(s) maximum avec la formule ${ctx.plan.label}`)
      const existing = await prisma.user.findUnique({ where: { email }, include: { memberships: true } })
      if (existing?.memberships.some((m) => m.orgId === ctx.orgId)) throw new HttpError(409, 'Cette personne est déjà membre de l\'organisation')
      const token = randomToken()
      await asPlatform(() => prisma.token.create({ data: { kind: 'INVITE', tokenHash: sha256(token), orgId: ctx.orgId, email, data: JSON.stringify({ role, inviter: ctx.user.name }), expiresAt: new Date(Date.now() + 7 * 86400_000) } }))
      await sendMail(templates.invite(email, token, ctx.org.name, ctx.user.name, role))
      await audit(req, ctx, 'member.invite', `${email} (${role})`)
      return { ok: true, devLinks: config.mail.exposeLinks ? { invite: `${config.appUrl}/invite?token=${token}` } : undefined }
    })
  }))
  app.delete('/members/invitations/:id', secured('member.manage', async (ctx, req) => {
    const r = await asPlatform(() => prisma.token.deleteMany({ where: { id: req.params.id, kind: 'INVITE', orgId: ctx.orgId } }))
    if (!r.count) throw new HttpError(404, 'Invitation introuvable')
    return { ok: true }
  }))
  // Création directe (mot de passe provisoire) conservée pour les démonstrations sans e-mail
  app.post('/members', secured('member.manage', async (ctx, req) => {
    const b = req.body ?? {}
    const name = str(b.name, 80), email = str(b.email, 160).toLowerCase(), password = String(b.password ?? '')
    const role = ROLES.includes(b.role) ? b.role : 'READER'
    if (!name || !EMAIL.test(email)) throw new HttpError(400, 'Nom et e-mail valides requis')
    const { passwordProblems } = await import('../security.js')
    const pb = passwordProblems(password, [name])
    if (pb) throw new HttpError(400, pb)
    return withLock(ctx.orgId, async () => {
      if ((await prisma.organizationMember.count({ where: { orgId: ctx.orgId } })) >= ctx.plan.members) throw new HttpError(402, `Quota atteint : ${ctx.plan.members} collaborateur(s) maximum avec la formule ${ctx.plan.label}`)
      if (await prisma.user.findUnique({ where: { email } })) throw new HttpError(409, 'Un compte existe déjà avec cet e-mail : utilisez une invitation')
      const user = await prisma.user.create({ data: { name, email, passwordHash: await hashPassword(password), memberships: { create: { orgId: ctx.orgId, role } } } })
      await audit(req, ctx, 'member.create', `${email} (${role})`)
      return { id: user.id }
    })
  }))
  const adminCount = (orgId: string) => prisma.organizationMember.count({ where: { orgId, role: 'ADMIN' } })
  app.patch('/members/:id', secured('member.manage', async (ctx, req) => {
    const role = String(req.body?.role ?? '')
    if (!ROLES.includes(role as any)) throw new HttpError(400, 'Rôle invalide')
    const m = await prisma.organizationMember.findFirst({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!m) throw new HttpError(404, 'Membre introuvable')
    if (m.role === 'ADMIN' && role !== 'ADMIN' && (await adminCount(ctx.orgId)) <= 1) throw new HttpError(400, "L'organisation doit conserver au moins un administrateur")
    await prisma.organizationMember.update({ where: { id: m.id }, data: { role } })
    await audit(req, ctx, 'member.role', `${m.userId} → ${role}`)
    return { ok: true }
  }))
  app.delete('/members/:id', secured('member.manage', async (ctx, req) => {
    const m = await prisma.organizationMember.findFirst({ where: { id: req.params.id, orgId: ctx.orgId } })
    if (!m) throw new HttpError(404, 'Membre introuvable')
    if (m.userId === ctx.user.id) throw new HttpError(400, 'Vous ne pouvez pas vous retirer vous-même')
    if (m.role === 'ADMIN' && (await adminCount(ctx.orgId)) <= 1) throw new HttpError(400, "L'organisation doit conserver au moins un administrateur")
    await prisma.organizationMember.delete({ where: { id: m.id } })
    await prisma.session.updateMany({ where: { userId: m.userId, orgId: ctx.orgId }, data: { orgId: null } })
    const others = await prisma.organizationMember.count({ where: { userId: m.userId } })
    const u = await prisma.user.findUnique({ where: { id: m.userId } })
    if (!others && u && !u.isSuperAdmin) await prisma.user.delete({ where: { id: m.userId } })
    await audit(req, ctx, 'member.remove', m.userId)
    return { ok: true }
  }))

  // ================= ORGANISATION : PARAMÈTRES =================
  app.get('/org', secured('member.read', async (ctx) => ({ id: ctx.org.id, name: ctx.org.name, require2fa: ctx.org.require2fa, alertEmails: ctx.org.alertEmails, webhookUrl: ctx.org.webhookUrl ?? '', plan: ctx.org.plan, status: ctx.org.status, createdAt: ctx.org.createdAt })))
  app.patch('/org', secured('org.settings', async (ctx, req) => {
    const b = req.body ?? {}
    const data: any = {}
    if (b.name !== undefined) data.name = str(b.name, 80) || undefined
    if (b.require2fa !== undefined) {
      if (b.require2fa && !ctx.user.totpEnabled) throw new HttpError(400, 'Activez d\'abord la 2FA sur votre propre compte')
      data.require2fa = !!b.require2fa
    }
    if (b.alertEmails !== undefined) data.alertEmails = String(b.alertEmails).split(',').map((s: string) => s.trim().toLowerCase()).filter((s: string) => EMAIL.test(s)).slice(0, 10).join(',')
    if (b.webhookUrl !== undefined) {
      const v = str(b.webhookUrl, 500)
      if (v) {
        try {
          assertAllowedUrl(v)
        } catch (e: any) {
          throw new HttpError(400, `Webhook : ${e.message}`)
        }
      }
      data.webhookUrl = v || null
    }
    await asPlatform(() => prisma.organization.update({ where: { id: ctx.orgId }, data }))
    await audit(req, ctx, 'org.settings', Object.keys(data).join(', '))
    return { ok: true }
  }))
  app.post('/org/webhook/test', secured('org.settings', async (ctx) => {
    if (!ctx.org.webhookUrl) throw new HttpError(400, 'Aucun webhook configuré')
    try {
      await sendWebhook(ctx.org.webhookUrl, { source: 'sentinelx', type: 'TEST', title: 'Test de webhook SentinelX', text: 'Test de webhook SentinelX', content: 'Test de webhook SentinelX', at: new Date().toISOString() })
      return { ok: true }
    } catch (e: any) {
      throw new HttpError(400, `Échec : ${e?.message ?? e}`)
    }
  }))

  // ================= NOTIFICATIONS =================
  app.get('/notifications', secured('notification.read', async () => prisma.notification.findMany({ orderBy: { createdAt: 'desc' }, take: 100 })))
  app.post('/notifications/read-all', secured('notification.read', async () => {
    await prisma.notification.updateMany({ where: { read: false }, data: { read: true } })
    return { ok: true }
  }))
  app.post('/notifications/:id/read', secured('notification.read', async (ctx, req) => {
    await prisma.notification.updateMany({ where: { id: req.params.id }, data: { read: true } })
    return { ok: true }
  }))

  // ================= ABONNEMENT (12.2) =================
  app.get('/billing', secured('billing.read', async (ctx) => ({
    mode: billingMode(), current: ctx.org.plan, plans: PLANS, usage: await usage(ctx.orgId), status: ctx.org.subscriptionStatus, currentPeriodEnd: ctx.org.currentPeriodEnd,
    payments: await prisma.payment.findMany({ orderBy: { createdAt: 'desc' }, take: 24 }),
    effective: ctx.plan, overrides: Object.keys(JSON.parse(ctx.org.planOverrides || '{}')),
  })))
  app.post('/billing/plan', secured('billing.manage', async (ctx, req) => {
    const plan = String(req.body?.plan ?? '')
    if (!PLANS[plan]) throw new HttpError(400, 'Formule inconnue')
    return withLock(ctx.orgId, async () => {
      const u = await usage(ctx.orgId), p = PLANS[plan]
      if (u.apps > p.apps || u.members > p.members) throw new HttpError(409, `Votre utilisation actuelle dépasse les limites de la formule ${p.label} (${p.apps} applications, ${p.members} collaborateurs)`)
      if (stripe && PLANS[plan].priceMonthly > 0) {
        const url = await createCheckout(ctx.org, ctx.user.email, plan)
        await audit(req, ctx, 'billing.checkout_started', `${ctx.org.plan} → ${plan}`)
        return { checkoutUrl: url }
      }
      if (stripe && ctx.org.stripeSubscriptionId && plan === 'STARTER') throw new HttpError(400, 'Résiliez votre abonnement depuis le portail de facturation pour revenir à la formule Starter')
      await asPlatform(() => prisma.organization.update({ where: { id: ctx.orgId }, data: { plan, subscriptionStatus: stripe ? ctx.org.subscriptionStatus : 'DEMO' } }))
      await audit(req, ctx, 'billing.plan_change', `${ctx.org.plan} → ${plan}${stripe ? '' : ' (démonstration, sans paiement)'}`)
      return { ok: true }
    })
  }))
  app.post('/billing/portal', secured('billing.manage', async (ctx, req) => {
    if (!stripe) throw new HttpError(400, 'Le fournisseur de paiement n\'est pas configuré')
    const url = await createPortal(ctx.org, ctx.user.email)
    await audit(req, ctx, 'billing.portal_opened')
    return { url }
  }))

  // ================= JOURNAL =================
  app.get('/audit-logs', secured('audit.read', async (ctx, req) => {
    const take = Math.min(500, Number(req.query?.limit) || 100)
    const q = str(req.query?.q, 80)
    const list = await asPlatform(() => prisma.auditLog.findMany({ where: { orgId: ctx.orgId, ...(q ? { OR: [{ action: { contains: q } }, { detail: { contains: q } }] } : {}) }, orderBy: { createdAt: 'desc' }, take }))
    const users = await asPlatform(() => prisma.user.findMany({ where: { id: { in: [...new Set(list.map((l) => l.userId).filter(Boolean) as string[])] } }, select: { id: true, name: true, email: true } }))
    return list.map((l) => ({ ...l, user: users.find((u) => u.id === l.userId) ?? null }))
  }))

  void recordUsage
}
