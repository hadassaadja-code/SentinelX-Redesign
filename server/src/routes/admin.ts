// Super Administrateur (2.1) : organisations, statuts et formules, statistiques globales, moteurs, journaux, paramètres.
// Tout accès aux données d'une organisation cliente exige une justification et est journalisé.
import { config } from '../config.js'
import { prisma, HttpError, PLANS, DEFAULT_PLANS, reloadPlans, platform, str, audit, safeJson } from '../core.js'
import { queueStats } from '../queue.js'
import { availableBrowsers } from '../scanners/browser.js'
import { mailEnabled } from '../mail.js'
import { billingMode } from '../billing.js'

const reason = (req: any) => {
  const r = str(req.query?.reason ?? req.body?.reason, 300)
  if (r.length < 5) throw new HttpError(400, 'Justification requise (motif d\'accès aux données client, 5 caractères minimum)')
  return r
}

export default async function adminRoutes(app: any) {
  app.get('/admin/overview', platform(async () => {
    const d30 = new Date(Date.now() - 30 * 86400_000)
    const [orgs, users, apps, scans, scansMonth, running, failed, incidents, findings, byPlan, byStatus, usage, emails] = await Promise.all([
      prisma.organization.count(), prisma.user.count(), prisma.application.count(), prisma.scan.count(),
      prisma.scan.count({ where: { createdAt: { gte: d30 } } }), prisma.scan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } }),
      prisma.scan.count({ where: { status: 'FAILED', createdAt: { gte: d30 } } }), prisma.incident.count({ where: { status: { in: ['OPEN', 'ACKNOWLEDGED'] } } }),
      prisma.finding.count({ where: { createdAt: { gte: d30 } } }),
      prisma.organization.groupBy({ by: ['plan'], _count: true }), prisma.organization.groupBy({ by: ['status'], _count: true }),
      prisma.usageRecord.findMany({ where: { day: { gte: d30.toISOString().slice(0, 10) } } }),
      prisma.emailOutbox.groupBy({ by: ['status'], _count: true }),
    ])
    const perDay: Record<string, { scans: number; requests: number; checks: number }> = {}
    for (let i = 29; i >= 0; i--) perDay[new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10)] = { scans: 0, requests: 0, checks: 0 }
    for (const u of usage) if (perDay[u.day]) { perDay[u.day].scans += u.scans; perDay[u.day].requests += u.requests; perDay[u.day].checks += u.checks }
    return {
      counts: { orgs, users, apps, scans, scansMonth, running, failed, incidents, findings },
      byPlan: Object.fromEntries(byPlan.map((x: any) => [x.plan, x._count])), byStatus: Object.fromEntries(byStatus.map((x: any) => [x.status, x._count])),
      usage: Object.entries(perDay).map(([day, v]) => ({ day, ...v })),
      emails: Object.fromEntries(emails.map((x: any) => [x.status, x._count])),
      engines: { queue: await queueStats(), browsers: await availableBrowsers(), playwright: config.playwright.enabled, mail: mailEnabled ? 'smtp' : 'journal', billing: billingMode(), db: process.env.DATABASE_URL ? 'postgresql' : 'sqlite', redis: !!config.redisUrl, allowPrivateTargets: config.allowPrivateTargets, env: config.env, node: process.version, uptimeSec: Math.round(process.uptime()), memoryMb: Math.round(process.memoryUsage().rss / 1048576) },
    }
  }))

  app.get('/admin/organizations', platform(async (ctx, req) => {
    const q = str(req.query?.q, 80)
    const list = await prisma.organization.findMany({ where: q ? { name: { contains: q } } : {}, orderBy: { createdAt: 'desc' }, take: 200, include: { _count: { select: { members: true, projects: true } } } })
    const ids = list.map((o) => o.id)
    const [apps, scans, open] = await Promise.all([
      prisma.application.groupBy({ by: ['orgId'], where: { orgId: { in: ids } }, _count: true }),
      prisma.scan.groupBy({ by: ['orgId'], where: { orgId: { in: ids }, createdAt: { gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) } }, _count: true }),
      prisma.finding.groupBy({ by: ['orgId'], where: { orgId: { in: ids }, severity: { in: ['CRITICAL', 'HIGH'] }, status: { notIn: ['FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE'] } }, _count: true }),
    ])
    const n = (g: any[], id: string) => g.find((x) => x.orgId === id)?._count ?? 0
    return list.map((o) => ({ id: o.id, name: o.name, plan: o.plan, status: o.status, subscriptionStatus: o.subscriptionStatus, createdAt: o.createdAt, members: o._count.members, projects: o._count.projects, apps: n(apps, o.id), scansMonth: n(scans, o.id), highOpen: n(open, o.id), overrides: Object.keys(safeJson(o.planOverrides, {})).length > 0 }))
  }))
  app.get('/admin/organizations/:id', platform(async (ctx, req) => {
    const why = reason(req)
    const o = await prisma.organization.findUnique({ where: { id: req.params.id }, include: { members: { include: { user: { select: { id: true, name: true, email: true, totpEnabled: true, lastLoginAt: true } } } }, projects: { include: { applications: true } } } })
    if (!o) throw new HttpError(404, 'Organisation introuvable')
    await audit(req, { orgId: o.id, user: ctx.user }, 'admin.org_access', `Super Administrateur ${ctx.user.email} — motif : ${why}`)
    const [scans, logs, incidents] = await Promise.all([
      prisma.scan.findMany({ where: { orgId: o.id }, orderBy: { createdAt: 'desc' }, take: 20, include: { application: { select: { name: true } } } }),
      prisma.auditLog.findMany({ where: { orgId: o.id }, orderBy: { createdAt: 'desc' }, take: 50 }),
      prisma.incident.findMany({ where: { orgId: o.id }, orderBy: { startedAt: 'desc' }, take: 20 }),
    ])
    return { ...o, planOverrides: safeJson(o.planOverrides, {}), effectivePlan: { ...(PLANS[o.plan] ?? PLANS.STARTER), ...safeJson(o.planOverrides, {}) }, projects: o.projects.map((p) => ({ ...p, applications: p.applications.map((a) => ({ ...a, scanHeaders: undefined, verificationToken: undefined })) })), scans: scans.map((s) => ({ id: s.id, app: s.application.name, status: s.status, score: s.score, createdAt: s.createdAt, modules: s.modules, error: s.error })), logs, incidents }
  }))
  app.patch('/admin/organizations/:id', platform(async (ctx, req) => {
    const why = reason(req)
    const b = req.body ?? {}
    const data: any = {}
    if (b.status !== undefined) {
      if (!['ACTIVE', 'SUSPENDED'].includes(b.status)) throw new HttpError(400, 'Statut invalide')
      data.status = b.status
    }
    if (b.plan !== undefined) {
      if (!PLANS[b.plan]) throw new HttpError(400, 'Formule inconnue')
      data.plan = b.plan
    }
    if (b.planOverrides !== undefined) {
      const allowed = ['apps', 'members', 'scansPerMonth', 'concurrent', 'historyDays', 'minMonitorInterval', 'api', 'loadVus', 'loadSeconds', 'activeScans', 'browsers']
      const o: any = {}
      for (const [k, v] of Object.entries(b.planOverrides ?? {})) if (allowed.includes(k) && v !== null && v !== '') o[k] = typeof v === 'boolean' ? v : Array.isArray(v) ? v : Number(v)
      data.planOverrides = JSON.stringify(o)
    }
    const o = await prisma.organization.update({ where: { id: req.params.id }, data })
    if (data.status === 'SUSPENDED') await prisma.session.updateMany({ where: { orgId: o.id }, data: { revoked: true } })
    await audit(req, { orgId: o.id, user: ctx.user }, 'admin.org_update', `${JSON.stringify(data)} — motif : ${why}`)
    return { ok: true }
  }))

  app.get('/admin/users', platform(async (ctx, req) => {
    const q = str(req.query?.q, 80)
    const list = await prisma.user.findMany({ where: q ? { OR: [{ email: { contains: q } }, { name: { contains: q } }] } : {}, orderBy: { createdAt: 'desc' }, take: 200, include: { memberships: { include: { org: { select: { name: true } } } } } })
    return list.map((u) => ({ id: u.id, name: u.name, email: u.email, isSuperAdmin: u.isSuperAdmin, totpEnabled: u.totpEnabled, emailVerified: !!u.emailVerifiedAt, lockedUntil: u.lockedUntil, failedLogins: u.failedLogins, lastLoginAt: u.lastLoginAt, createdAt: u.createdAt, orgs: u.memberships.map((m) => `${m.org.name} (${m.role})`) }))
  }))
  app.patch('/admin/users/:id', platform(async (ctx, req) => {
    const b = req.body ?? {}
    const data: any = {}
    if (b.isSuperAdmin !== undefined) {
      if (req.params.id === ctx.user.id && !b.isSuperAdmin) throw new HttpError(400, 'Vous ne pouvez pas retirer votre propre rôle')
      data.isSuperAdmin = !!b.isSuperAdmin
    }
    if (b.unlock) Object.assign(data, { failedLogins: 0, lockedUntil: null })
    if (b.reset2fa) Object.assign(data, { totpEnabled: false, totpSecret: null, recoveryCodes: '[]' })
    if (b.revokeSessions) await prisma.session.updateMany({ where: { userId: req.params.id }, data: { revoked: true } })
    if (Object.keys(data).length) await prisma.user.update({ where: { id: req.params.id }, data })
    await audit(req, { user: ctx.user }, 'admin.user_update', `${req.params.id} ${JSON.stringify({ ...data, revokeSessions: !!b.revokeSessions })}`)
    return { ok: true }
  }))

  app.get('/admin/scans', platform(async () => {
    const list = await prisma.scan.findMany({ where: { OR: [{ status: { in: ['QUEUED', 'RUNNING'] } }, { createdAt: { gte: new Date(Date.now() - 86400_000) } }] }, orderBy: { createdAt: 'desc' }, take: 100, include: { application: { select: { name: true, url: true, orgId: true } } } })
    const orgs = await prisma.organization.findMany({ where: { id: { in: [...new Set(list.map((s) => s.orgId))] } }, select: { id: true, name: true } })
    return list.map((s) => ({ id: s.id, org: orgs.find((o) => o.id === s.orgId)?.name, app: s.application.name, url: s.application.url, status: s.status, stage: s.stage, progress: s.progress, modules: s.modules, profile: s.profile, requestsMade: s.requestsMade, error: s.error, createdAt: s.createdAt, startedAt: s.startedAt, finishedAt: s.finishedAt }))
  }))
  app.post('/admin/scans/:id/cancel', platform(async (ctx, req) => {
    const why = reason(req)
    const s = await prisma.scan.findUnique({ where: { id: req.params.id } })
    if (!s) throw new HttpError(404, 'Audit introuvable')
    await prisma.scan.update({ where: { id: s.id }, data: s.status === 'QUEUED' ? { status: 'CANCELED', cancelRequested: true, finishedAt: new Date() } : { cancelRequested: true } })
    await audit(req, { orgId: s.orgId, user: ctx.user }, 'admin.scan_cancel', `${s.id} — motif : ${why}`)
    return { ok: true }
  }))

  app.get('/admin/audit-logs', platform(async (ctx, req) => {
    const q = str(req.query?.q, 80)
    const list = await prisma.auditLog.findMany({ where: q ? { OR: [{ action: { contains: q } }, { detail: { contains: q } }] } : {}, orderBy: { createdAt: 'desc' }, take: 300 })
    const orgs = await prisma.organization.findMany({ where: { id: { in: [...new Set(list.map((l) => l.orgId).filter(Boolean) as string[])] } }, select: { id: true, name: true } })
    return list.map((l) => ({ ...l, org: orgs.find((o) => o.id === l.orgId)?.name ?? null }))
  }))
  app.get('/admin/emails', platform(async () => prisma.emailOutbox.findMany({ orderBy: { createdAt: 'desc' }, take: 100, select: { id: true, to: true, subject: true, status: true, error: true, createdAt: true, sentAt: true, text: true } })))

  app.get('/admin/settings', platform(async () => {
    const rows = await prisma.platformSetting.findMany({ where: { key: { in: ['plans', 'registrationsOpen', 'maintenanceMessage'] } } })
    const get = (k: string) => rows.find((r) => r.key === k)?.value
    return { plans: PLANS, defaultPlans: DEFAULT_PLANS, planOverrides: safeJson(get('plans') ?? '{}', {}), registrationsOpen: get('registrationsOpen') === undefined ? config.registrationsOpen : get('registrationsOpen') === 'true', maintenanceMessage: get('maintenanceMessage') ?? '', config: { appUrl: config.appUrl, requireEmailVerification: config.requireEmailVerification, superAdminEmails: config.superAdminEmails } }
  }))
  app.put('/admin/settings', platform(async (ctx, req) => {
    const b = req.body ?? {}
    const set = (key: string, value: string) => prisma.platformSetting.upsert({ where: { key }, create: { key, value }, update: { value } })
    if (b.planOverrides !== undefined) {
      const out: any = {}
      for (const k of Object.keys(DEFAULT_PLANS)) {
        const o = b.planOverrides?.[k]
        if (!o || typeof o !== 'object') continue
        out[k] = {}
        for (const f of ['apps', 'members', 'scansPerMonth', 'concurrent', 'historyDays', 'minMonitorInterval', 'loadVus', 'loadSeconds', 'priceMonthly']) if (o[f] !== undefined && o[f] !== '' && Number.isFinite(Number(o[f]))) out[k][f] = Number(o[f])
        for (const f of ['api', 'activeScans']) if (typeof o[f] === 'boolean') out[k][f] = o[f]
        if (Array.isArray(o.browsers)) out[k].browsers = o.browsers.filter((x: any) => ['chromium', 'firefox', 'webkit'].includes(x))
        if (typeof o.label === 'string' && o.label.trim()) out[k].label = o.label.trim().slice(0, 40)
      }
      await set('plans', JSON.stringify(out))
      await reloadPlans()
    }
    if (b.registrationsOpen !== undefined) await set('registrationsOpen', b.registrationsOpen ? 'true' : 'false')
    if (b.maintenanceMessage !== undefined) await set('maintenanceMessage', str(b.maintenanceMessage, 300))
    await audit(req, { user: ctx.user }, 'admin.settings', Object.keys(b).join(', '))
    return { ok: true }
  }))
}
