// Orchestration d'une campagne d'audit (13.3) : vérification de l'autorisation, exécution des modules,
// suivi de progression, annulation, dédoublonnage et cycle de vie des constats, notifications.
import { prisma, asTenant, asPlatform, alert, templates, planOf, recordUsage, safeJson } from './core.js'
import { decrypt } from './security.js'
import { buildScope, errMsg } from './scanners/http.js'
import { Collector, type ScanContext, SEVERITIES } from './scanners/types.js'
import { runQA } from './scanners/qa.js'
import { runSecurity } from './scanners/security.js'
import { runApi } from './scanners/api.js'
import { runPerf, runLoad, perfScore } from './scanners/perf.js'

const SEV_WEIGHT: Record<string, number> = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0 }
export const MODULES = ['QA', 'SECURITY', 'API', 'PERFORMANCE'] as const

export async function runScan(scanId: string): Promise<void> {
  const scan0 = await asPlatform(() => prisma.scan.findUnique({ where: { id: scanId }, include: { application: true } }))
  if (!scan0) return
  if (scan0.status === 'CANCELED') return
  const orgId = scan0.orgId
  await asTenant(orgId, async () => {
    const org = await asPlatform(() => prisma.organization.findUnique({ where: { id: orgId } }))
    const plan = planOf(org!)
    const scan = await prisma.scan.update({ where: { id: scanId }, data: { status: 'RUNNING', startedAt: new Date(), stage: 'Préparation', progress: 1 }, include: { application: true } })
    const app = scan.application
    // Vérifications de dernière minute : autorisation toujours valide
    if (!app.authorized || (app.authorizationExpires && app.authorizationExpires < new Date())) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED', error: "Autorisation d'audit absente ou expirée", finishedAt: new Date() } })
      return
    }
    const mods = scan.modules.split(',')
    const cfg = safeJson(scan.config, {})
    let headers: Record<string, string> = {}
    try {
      if (app.scanHeaders) headers = safeJson(decrypt(app.scanHeaders), {})
    } catch {}
    const scope = buildScope(app, headers)
    let lastProgress = 0
    let used = 0
    scope.onRequest = () => {
      used++
    }
    const ctx: ScanContext = {
      scanId, orgId, app, scope, config: cfg,
      profile: (scan.profile as any) || 'STANDARD',
      active: app.authorizedScopes.includes('ACTIVE') && plan.activeScans && scan.profile !== 'LOAD',
      browsers: app.browsers.split(',').map((b) => b.trim()).filter((b) => plan.browsers.includes(b)),
      progress: async (pct, stage) => {
        const p = Math.min(99, Math.max(lastProgress, Math.round(pct)))
        lastProgress = p
        await prisma.scan.update({ where: { id: scanId }, data: { progress: p, stage, requestsMade: scope.used } }).catch(() => {})
      },
      cancelled: async () => {
        const s = await prisma.scan.findUnique({ where: { id: scanId }, select: { cancelRequested: true } })
        return !!s?.cancelRequested
      },
      log: (m) => console.log(`[scan ${scanId}] ${m}`),
    }
    if (scan.profile === 'LOAD') cfg.limits = { vus: plan.loadVus, seconds: plan.loadSeconds }

    const summary: any = { profile: scan.profile, active: ctx.active, modules: mods }
    const scores: number[] = []
    let ok = 0
    const all = new Collector()
    const weight = 100 / Math.max(1, mods.length)
    const runModule = async (name: string, fn: (c: ScanContext, col: Collector) => Promise<void>, idx: number) => {
      if (await ctx.cancelled()) return
      const col = new Collector()
      const sub: ScanContext = { ...ctx, progress: (pct, stage) => ctx.progress(idx * weight + (pct / 100) * weight, stage) }
      try {
        await fn(sub, col)
        all.findings.push(...col.findings)
        all.tests.push(...col.tests)
        all.metrics.push(...col.metrics)
        Object.assign(all.info, col.info)
        ok++
        return col
      } catch (e) {
        summary[name.toLowerCase()] = { error: errMsg(e) }
        ctx.log(`${name} en échec : ${errMsg(e)}`)
        return null
      }
    }

    let idx = 0
    if (scan.profile === 'LOAD') {
      const col = await runModule('LOAD', runLoad, idx++)
      if (col) {
        summary.load = { score: col.info.load?.score ?? null, ...col.info.load, series: undefined }
        summary.performance = { score: col.info.load?.score ?? null, avg: col.metrics.find((m) => m.name === 'Average Response Time')?.value, p95: col.metrics.find((m) => m.name === 'P95 Response Time')?.value, load: true }
        summary.loadSeries = col.info.load?.series ?? []
        if (summary.load.score != null) scores.push(summary.load.score)
      }
    } else {
      if (mods.includes('QA')) {
        const col = await runModule('QA', runQA, idx++)
        if (col) {
          const counted = col.tests.filter((t) => t.status !== 'SKIP')
          const passed = counted.filter((t) => t.status === 'PASS').length
          summary.qa = { passed, failed: counted.length - passed, skipped: col.tests.length - counted.length, total: counted.length, rate: counted.length ? Math.round((passed / counted.length) * 100) : 100, browserRan: !!col.info.browserRan, axe: col.info.axe ?? null, screenshots: col.info.screenshots ?? null, visualDiff: col.info.visualDiff ?? null, vitals: col.info.vitals ? { fcp: col.info.vitals.fcp, lcp: col.info.vitals.lcp, cls: col.info.vitals.cls, resources: col.info.vitals.resources, bytes: col.info.vitals.bytes } : null }
          scores.push(summary.qa.rate)
        }
      }
      if (mods.includes('SECURITY')) {
        const col = await runModule('SECURITY', runSecurity, idx++)
        if (col) {
          const counts: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
          col.findings.forEach((x) => counts[x.severity]++)
          const penalty = col.findings.reduce((a, x) => a + SEV_WEIGHT[x.severity], 0)
          summary.security = { counts, total: col.findings.length, score: Math.max(0, 100 - penalty), info: col.info, activeSkipped: !!col.info.activeSkipped }
          scores.push(summary.security.score)
        }
      }
      if (mods.includes('API')) {
        const col = await runModule('API', runApi, idx++)
        if (col) {
          const counts: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
          col.findings.forEach((x) => counts[x.severity]++)
          const penalty = col.findings.reduce((a, x) => a + SEV_WEIGHT[x.severity], 0)
          const tests = col.tests.filter((t) => t.status !== 'SKIP')
          summary.api = { counts, total: col.findings.length, score: Math.max(0, 100 - penalty), info: col.info.api ?? null, tests: tests.length, passed: tests.filter((t) => t.status === 'PASS').length }
          scores.push(summary.api.score)
        }
      }
      if (mods.includes('PERFORMANCE')) {
        const col = await runModule('PERFORMANCE', runPerf, idx++)
        if (col) {
          const p = col.info.perf
          const vitals = all.info.vitals
          let score = perfScore(p.avg, p.errorRate / 100, p.p95)
          if (vitals?.lcp) score = Math.round(score * 0.7 + Math.max(0, 100 - Math.max(0, vitals.lcp - 2500) / 40) * 0.3)
          summary.performance = { score, avg: p.avg, p95: p.p95, p99: p.p99, errorRate: p.errorRate, encoding: p.encoding, samples: p.samples, vitals: vitals ? { fcp: vitals.fcp, lcp: vitals.lcp, cls: vitals.cls } : null }
          scores.push(score)
        }
      }
    }

    const cancelled = await ctx.cancelled()
    // Persistance des résultats
    if (all.tests.length) await prisma.testResult.createMany({ data: all.tests.map((t) => ({ orgId, scanId, group: t.group, browser: t.browser ?? '', name: t.name, status: t.status, detail: t.detail, durationMs: t.durationMs })) })
    if (all.metrics.length) await prisma.performanceMetric.createMany({ data: all.metrics.map((m) => ({ orgId, scanId, group: m.group, name: m.name, value: m.value, unit: m.unit })) })
    if (all.findings.length) {
      // Cycle de vie : un constat déjà connu (même empreinte sur la même application) conserve son historique
      const fps = all.findings.map((x) => `${x.title}|${x.resource}`)
      const previous = await prisma.finding.findMany({ where: { applicationId: app.id, fingerprint: { in: fps } }, orderBy: { createdAt: 'desc' } })
      const byFp = new Map<string, any>()
      for (const p of previous) if (!byFp.has(p.fingerprint)) byFp.set(p.fingerprint, p)
      let regressions = 0
      await prisma.finding.createMany({
        data: all.findings.map((x) => {
          const fp = `${x.title}|${x.resource}`
          const prev = byFp.get(fp)
          let status = 'DETECTED', note = '', firstSeenAt = new Date(), occurrences = 1
          if (prev) {
            firstSeenAt = prev.firstSeenAt
            occurrences = prev.occurrences + 1
            if (prev.status === 'FALSE_POSITIVE') { status = 'FALSE_POSITIVE'; note = prev.note }
            else if (['FIXED', 'RETESTED', 'CLOSED'].includes(prev.status)) { status = 'DETECTED'; note = `Régression : constat marqué « ${prev.status} » réapparu`; regressions++ }
            else { status = prev.status; note = prev.note }
          }
          return { orgId, scanId, applicationId: app.id, module: x.category === 'API' ? 'API' : x.category === 'PERFORMANCE' ? 'PERFORMANCE' : x.category === 'ACCESSIBILITY' ? 'QA' : 'SECURITY', category: x.category, title: x.title, description: x.description, severity: x.severity, resource: x.resource, evidence: x.evidence, recommendation: x.recommendation, cwe: x.cwe ?? '', owasp: x.owasp ?? '', status, note, fingerprint: fp, firstSeenAt, occurrences, assigneeId: prev?.assigneeId ?? null }
        }),
      })
      summary.regressions = regressions
    }
    const failed = ok === 0
    const status = cancelled ? 'CANCELED' : failed ? 'FAILED' : 'DONE'
    const score = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status, progress: 100, stage: cancelled ? 'Annulé' : 'Terminé', requestsMade: scope.used,
        error: failed ? Object.values(summary).map((s: any) => s?.error).filter(Boolean).join(' | ').slice(0, 400) : null,
        score, summary: JSON.stringify(summary), finishedAt: new Date(),
      },
    })
    await recordUsage(orgId, 'requests', scope.used)
    const critical = all.findings.filter((f) => f.severity === 'CRITICAL' && f.category !== 'ACCESSIBILITY').length
    if (status === 'DONE') {
      await alert(orgId, { type: critical ? 'CRITICAL_FINDING' : 'SCAN_DONE', title: critical ? `Vulnérabilité critique détectée sur ${app.name}` : `Audit terminé : ${app.name}`, body: critical ? `${critical} vulnérabilité(s) critique(s) — score ${score ?? '-'}/100` : `Score global ${score ?? '-'}/100. Le rapport est disponible.`, link: `/app/scans/${scanId}`, important: critical > 0, mail: (to) => templates.scanDone(to, app.name, score, scanId, critical) })
      if (summary.regressions) await alert(orgId, { type: 'REGRESSION', title: `Régression détectée sur ${app.name}`, body: `${summary.regressions} constat(s) corrigé(s) sont réapparus.`, link: `/app/scans/${scanId}` })
    } else if (status === 'FAILED') {
      await alert(orgId, { type: 'SCAN_FAILED', title: `Audit en échec : ${app.name}`, body: "La cible n'a pas pu être analysée.", link: `/app/scans/${scanId}` })
    }
  })
}

/** Marque en échec une campagne dont l'exécution a levé une exception inattendue. */
export async function failScan(scanId: string, e: any) {
  await asPlatform(() => prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED', error: errMsg(e), finishedAt: new Date(), progress: 100, stage: 'Erreur' } })).catch(() => {})
}
