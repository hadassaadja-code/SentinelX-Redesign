// Monitoring (section 9), planification des audits, conservation de l'historique et synthèses hebdomadaires.
import tls from 'node:tls'
import net from 'node:net'
import { prisma, asTenant, asPlatform, alert, templates, planOf, PLANS, recordUsage, sendMail } from './core.js'
import { safeRequest, guardedLookup, errMsg } from './scanners/http.js'
import { enqueueScan } from './queue.js'

function certExpiry(host: string, port: number): Promise<Date | null> {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, lookup: guardedLookup as any, timeout: 8000 }, () => {
      const c: any = s.getPeerCertificate()
      s.end()
      resolve(c?.valid_to ? new Date(c.valid_to) : null)
    })
    s.on('error', () => resolve(null))
    s.on('timeout', () => { s.destroy(); resolve(null) })
  })
}

/** Vérifie une application : disponibilité, code HTTP, mot-clé, temps de réponse ; gère incidents et alertes avec regroupement. */
export async function checkApplication(app: any, manual = false) {
  return asTenant(app.orgId, async () => {
    let up = false, code: number | null = null, ms: number | null = null, reason = '', kind = 'DOWN'
    try {
      const r = await safeRequest(app.url, { readBody: !!app.monitorKeyword, maxBytes: 500_000 })
      code = r.status
      ms = Math.round(r.total)
      up = app.monitorExpectStatus ? r.status === app.monitorExpectStatus : r.status < 500
      if (!up) reason = `HTTP ${r.status}${app.monitorExpectStatus ? ` (attendu ${app.monitorExpectStatus})` : ''}`
      if (up && app.monitorKeyword && !r.body.includes(app.monitorKeyword)) { up = false; kind = 'KEYWORD'; reason = `Texte attendu introuvable : « ${app.monitorKeyword} »` }
      if (up && app.monitorMaxMs > 0 && ms > app.monitorMaxMs) { up = false; kind = 'SLOW'; reason = `Temps de réponse ${ms} ms > ${app.monitorMaxMs} ms` }
    } catch (e) {
      reason = errMsg(e)
    }
    const inMaintenance = app.maintenanceUntil && app.maintenanceUntil > new Date()
    const fails = up ? 0 : app.consecutiveFails + 1
    await prisma.monitorCheck.create({ data: { orgId: app.orgId, applicationId: app.id, up, httpCode: code, responseMs: ms, error: reason.slice(0, 200) } })
    await prisma.application.update({ where: { id: app.id }, data: { lastStatus: up ? 'UP' : 'DOWN', lastHttpCode: code, lastResponseMs: ms, lastCheckedAt: new Date(), consecutiveFails: fails } })
    await recordUsage(app.orgId, 'checks')
    const open = await prisma.incident.findFirst({ where: { applicationId: app.id, status: { in: ['OPEN', 'ACKNOWLEDGED'] } } })
    if (!up) {
      // Regroupement : un seul incident ouvert par application ; création seulement après N échecs consécutifs (anti-faux positifs)
      if (open) await prisma.incident.update({ where: { id: open.id }, data: { occurrences: { increment: 1 }, lastSeenAt: new Date() } })
      else if ((fails >= app.monitorFailThreshold || manual) && !inMaintenance) {
        await prisma.incident.create({ data: { orgId: app.orgId, applicationId: app.id, kind, title: `${app.name} ${kind === 'SLOW' ? 'trop lente' : kind === 'KEYWORD' ? 'contenu inattendu' : 'indisponible'} (${reason})`.slice(0, 200) } })
        await alert(app.orgId, { type: 'APP_DOWN', title: `Application indisponible : ${app.name}`, body: reason, link: '/app/monitoring', important: true, mail: (to) => templates.appDown(to, app.name, reason) })
      }
    } else if (open) {
      const mins = Math.round((Date.now() - open.startedAt.getTime()) / 60000)
      await prisma.incident.update({ where: { id: open.id }, data: { status: 'RESOLVED', resolvedAt: new Date() } })
      await alert(app.orgId, { type: 'INCIDENT_RESOLVED', title: `Incident résolu : ${app.name}`, body: `L'application répond de nouveau après ${mins} min.`, link: '/app/monitoring', mail: (to) => templates.appUp(to, app.name, mins) })
    }
    return { up, code, ms, reason }
  })
}

/** Surveillance des certificats : expiration dans moins de N jours → alerte (une fois par jour). */
async function checkCertificates() {
  const apps = await asPlatform(() => prisma.application.findMany({ where: { monitoring: true, authorized: true, url: { startsWith: 'https://' } } }))
  for (const a of apps) {
    try {
      const u = new URL(a.url)
      const exp = await certExpiry(u.hostname, Number(u.port) || 443)
      await asPlatform(() => prisma.application.update({ where: { id: a.id }, data: { sslExpiresAt: exp } }))
      if (exp) {
        const days = Math.floor((exp.getTime() - Date.now()) / 86400_000)
        if (days <= a.sslDaysWarn) {
          const recent = await asPlatform(() => prisma.notification.findFirst({ where: { orgId: a.orgId, type: 'SSL_EXPIRING', link: `/app/monitoring?app=${a.id}`, createdAt: { gt: new Date(Date.now() - 86400_000) } } }))
          if (!recent) await alert(a.orgId, { type: 'SSL_EXPIRING', title: `Certificat TLS bientôt expiré : ${a.name}`, body: `Expiration dans ${days} jour(s)`, link: `/app/monitoring?app=${a.id}`, mail: (to) => templates.sslExpiring(to, a.name, days) })
        }
      }
    } catch {}
  }
}

/** Audits planifiés (quotidien/hebdomadaire) : création de la campagne dans la limite des quotas. */
async function runSchedules() {
  const due = await asPlatform(() => prisma.application.findMany({ where: { scheduleHours: { gt: 0 }, authorized: true, nextScanAt: { lte: new Date() } } }))
  for (const a of due) {
    await asTenant(a.orgId, async () => {
      const org = await asPlatform(() => prisma.organization.findUnique({ where: { id: a.orgId } }))
      if (!org || org.status !== 'ACTIVE') return
      const plan = planOf(org)
      const monthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1)
      const [month, running] = await Promise.all([prisma.scan.count({ where: { createdAt: { gte: monthStart } } }), prisma.scan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } })])
      const next = new Date(Date.now() + a.scheduleHours * 3600_000)
      if (month >= plan.scansPerMonth || running >= plan.concurrent) {
        await prisma.application.update({ where: { id: a.id }, data: { nextScanAt: new Date(Date.now() + 3600_000) } })
        if (month >= plan.scansPerMonth) await alert(a.orgId, { type: 'QUOTA', title: 'Audit planifié reporté : quota mensuel atteint', body: `${a.name}`, link: '/app/billing', mail: (to) => templates.quotaReached(to, `${plan.scansPerMonth} audits par mois`) })
        return
      }
      const modules = a.scheduleModules.split(',').filter((m) => ['QA', 'SECURITY', 'API', 'PERFORMANCE'].includes(m) && (m !== 'API' || plan.api))
      if (!modules.length) return
      const scan = await prisma.scan.create({ data: { orgId: a.orgId, applicationId: a.id, modules: modules.join(','), createdById: a.authorizedBy ?? 'schedule', triggeredBy: 'SCHEDULE' } })
      await prisma.application.update({ where: { id: a.id }, data: { nextScanAt: next } })
      await recordUsage(a.orgId, 'scans')
      await enqueueScan(scan.id)
    }).catch((e) => console.error('[schedule]', errMsg(e)))
  }
}

/** Conservation de l'historique selon la formule, nettoyage des jetons et vérifications anciennes. */
async function purge() {
  await asPlatform(async () => {
    const orgs = await prisma.organization.findMany()
    for (const o of orgs) {
      const days = planOf(o).historyDays
      const before = new Date(Date.now() - days * 86400_000)
      await prisma.scan.deleteMany({ where: { orgId: o.id, createdAt: { lt: before } } })
      await prisma.monitorCheck.deleteMany({ where: { orgId: o.id, at: { lt: new Date(Date.now() - Math.max(days, 30) * 86400_000) } } })
      await prisma.notification.deleteMany({ where: { orgId: o.id, read: true, createdAt: { lt: new Date(Date.now() - 90 * 86400_000) } } })
    }
    await prisma.token.deleteMany({ where: { OR: [{ expiresAt: { lt: new Date(Date.now() - 7 * 86400_000) } }, { usedAt: { lt: new Date(Date.now() - 7 * 86400_000) } }] } })
    await prisma.session.deleteMany({ where: { OR: [{ expiresAt: { lt: new Date() } }, { revoked: true, createdAt: { lt: new Date(Date.now() - 30 * 86400_000) } }] } })
    await prisma.emailOutbox.deleteMany({ where: { createdAt: { lt: new Date(Date.now() - 60 * 86400_000) } } })
    // Fin d'abonnement proche : rappel 7 jours avant (une fois)
    const soon = await prisma.organization.findMany({ where: { subscriptionStatus: { in: ['ACTIVE', 'PAST_DUE'] }, currentPeriodEnd: { lte: new Date(Date.now() + 7 * 86400_000), gt: new Date() } } })
    for (const o of soon) {
      const key = `/app/billing?period=${o.currentPeriodEnd!.toISOString().slice(0, 10)}`
      const sent = await prisma.notification.findFirst({ where: { orgId: o.id, type: 'SUBSCRIPTION_ENDING', link: key } })
      if (!sent) await alert(o.id, { type: 'SUBSCRIPTION_ENDING', title: 'Abonnement : fin de période proche', body: `Fin de période le ${o.currentPeriodEnd!.toLocaleDateString('fr-FR')}`, link: key, mail: (to) => templates.subscriptionEnding(to, o.name, o.currentPeriodEnd!.toLocaleDateString('fr-FR')) })
    }
  })
}

/** Synthèse hebdomadaire par e-mail (lundi matin). */
async function weeklyDigest() {
  const now = new Date()
  if (now.getDay() !== 1 || now.getHours() !== 8) return
  const key = `digest-${now.toISOString().slice(0, 10)}`
  const done = await asPlatform(() => prisma.platformSetting.findUnique({ where: { key } }))
  if (done) return
  await asPlatform(() => prisma.platformSetting.create({ data: { key, value: '1' } }))
  const orgs = await asPlatform(() => prisma.organization.findMany({ include: { members: { include: { user: true } } } }))
  const since = new Date(Date.now() - 7 * 86400_000)
  for (const o of orgs) {
    await asTenant(o.id, async () => {
      const [scans, findings, incidents] = await Promise.all([
        prisma.scan.findMany({ where: { createdAt: { gte: since }, status: 'DONE' } }),
        prisma.finding.groupBy({ by: ['severity'], where: { createdAt: { gte: since } }, _count: true }),
        prisma.incident.count({ where: { startedAt: { gte: since } } }),
      ])
      if (!scans.length && !incidents) return
      const sev = Object.fromEntries(findings.map((f: any) => [f.severity, f._count]))
      const avg = scans.filter((s) => s.score != null).reduce((a, s) => a + s.score!, 0) / Math.max(1, scans.filter((s) => s.score != null).length)
      const lines = [`${scans.length} audit(s) terminé(s), score moyen ${Math.round(avg) || '-'}/100.`, `Nouveaux constats : ${sev.CRITICAL ?? 0} critique(s), ${sev.HIGH ?? 0} élevé(s), ${sev.MEDIUM ?? 0} moyen(s).`, `${incidents} incident(s) de disponibilité.`]
      for (const m of o.members) if (m.user.notifyDigest && m.user.notifyEmail) await sendMail(templates.digest(m.user.email, o.name, lines))
    })
  }
}

export function startBackgroundJobs() {
  let busy = false
  let lastPurge = 0, lastCert = 0
  const tick = async () => {
    if (busy) return
    busy = true
    try {
      const apps = await asPlatform(() => prisma.application.findMany({ where: { monitoring: true, authorized: true } }))
      for (const a of apps) {
        const due = !a.lastCheckedAt || Date.now() - a.lastCheckedAt.getTime() >= a.monitorInterval * 60_000 - 5000
        if (due) await checkApplication(a).catch((e) => console.error('[monitor]', errMsg(e)))
      }
      await runSchedules()
      if (Date.now() - lastCert > 6 * 3600_000) {
        lastCert = Date.now()
        await checkCertificates()
      }
      if (Date.now() - lastPurge > 3600_000) {
        lastPurge = Date.now()
        await purge()
      }
      await weeklyDigest()
    } catch (e) {
      console.error('[jobs]', errMsg(e))
    } finally {
      busy = false
    }
  }
  setInterval(tick, 60_000).unref()
  setTimeout(tick, 5000).unref()
}

export { PLANS }
