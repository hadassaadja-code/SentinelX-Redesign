// Monitoring (section 9) : état des applications, disponibilité, historique des vérifications, incidents, maintenance.
import { prisma, HttpError, secured, str, audit } from '../core.js'

async function uptime(appId: string, hours: number): Promise<number | null> {
  const since = new Date(Date.now() - hours * 3600_000)
  const [total, up] = await Promise.all([prisma.monitorCheck.count({ where: { applicationId: appId, at: { gte: since } } }), prisma.monitorCheck.count({ where: { applicationId: appId, at: { gte: since }, up: true } })])
  return total ? Math.round((up / total) * 1000) / 10 : null
}

export default async function monitoringRoutes(app: any) {
  app.get('/monitoring', secured('project.read', async () => {
    const apps = await prisma.application.findMany({ orderBy: { name: 'asc' }, include: { project: { select: { name: true } } } })
    const out = []
    for (const a of apps) {
      const since = new Date(Date.now() - 24 * 3600_000)
      const checks = await prisma.monitorCheck.findMany({ where: { applicationId: a.id, at: { gte: since } }, orderBy: { at: 'asc' }, select: { at: true, up: true, responseMs: true } })
      const ms = checks.filter((c) => c.responseMs != null).map((c) => c.responseMs!)
      out.push({
        ...a, scanHeaders: undefined, project: a.project,
        uptime24h: await uptime(a.id, 24), uptime7d: await uptime(a.id, 168), uptime30d: await uptime(a.id, 720),
        avgMs24h: ms.length ? Math.round(ms.reduce((x, y) => x + y, 0) / ms.length) : null,
        sparkline: checks.slice(-48),
        sslDaysLeft: a.sslExpiresAt ? Math.floor((a.sslExpiresAt.getTime() - Date.now()) / 86400_000) : null,
        inMaintenance: !!(a.maintenanceUntil && a.maintenanceUntil > new Date()),
      })
    }
    return out
  }))
  app.get('/monitoring/:id/checks', secured('project.read', async (ctx, req) => {
    const hours = Math.min(720, Math.max(1, Number(req.query?.hours) || 24))
    const a = await prisma.application.findFirst({ where: { id: req.params.id }, select: { id: true } })
    if (!a) throw new HttpError(404, 'Application introuvable')
    return prisma.monitorCheck.findMany({ where: { applicationId: a.id, at: { gte: new Date(Date.now() - hours * 3600_000) } }, orderBy: { at: 'asc' }, take: 2000 })
  }))
  app.post('/applications/:id/maintenance', secured('monitoring.manage', async (ctx, req) => {
    const hours = Math.max(0, Math.min(72, Number(req.body?.hours) || 0))
    const r = await prisma.application.updateMany({ where: { id: req.params.id }, data: { maintenanceUntil: hours ? new Date(Date.now() + hours * 3600_000) : null } })
    if (!r.count) throw new HttpError(404, 'Application introuvable')
    await audit(req, ctx, 'application.maintenance', `${req.params.id} — ${hours} h`)
    return { ok: true }
  }))

  // ----- Incidents -----
  app.get('/incidents', secured('project.read', async (ctx, req) => {
    const where: any = {}
    if (req.query?.status) where.status = String(req.query.status)
    if (req.query?.open === 'true') where.status = { in: ['OPEN', 'ACKNOWLEDGED'] }
    return prisma.incident.findMany({ where, orderBy: { startedAt: 'desc' }, take: 200, include: { application: { select: { name: true, url: true } } } })
  }))
  app.patch('/incidents/:id', secured('incident.update', async (ctx, req) => {
    const i = await prisma.incident.findFirst({ where: { id: req.params.id } })
    if (!i) throw new HttpError(404, 'Incident introuvable')
    const data: any = {}
    const status = req.body?.status
    if (status === 'ACKNOWLEDGED' && i.status === 'OPEN') Object.assign(data, { status, acknowledgedById: ctx.user.id, acknowledgedAt: new Date() })
    else if (status === 'RESOLVED' && i.status !== 'RESOLVED') Object.assign(data, { status, resolvedAt: new Date() })
    else if (status === 'OPEN' && i.status === 'RESOLVED') Object.assign(data, { status, resolvedAt: null })
    if (req.body?.notes !== undefined) data.notes = str(req.body.notes, 2000)
    if (!Object.keys(data).length) throw new HttpError(400, 'Aucune modification')
    await prisma.incident.update({ where: { id: i.id }, data })
    await audit(req, ctx, 'incident.update', `${i.id} → ${status ?? 'notes'}`)
    return { ok: true }
  }))
}
