// Moteur de performance (section 8) : mesures serveur, analyse des ressources, budget de performance et tests de charge encadrés.
import { cut, errMsg, inScope, safeRequest } from './http.js'
import { Collector, type ScanContext } from './types.js'

const pct = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))]
const r1 = (n: number) => Math.round(n * 10) / 10

export function perfScore(avg: number, errorRate: number, p95: number): number {
  return Math.max(0, Math.min(100, Math.round(100 - Math.max(0, avg - 200) / 28 - Math.max(0, p95 - 800) / 60 - errorRate * 50)))
}

export async function runPerf(ctx: ScanContext, col: Collector): Promise<void> {
  const app = ctx.app
  const N = ctx.profile === 'DEEP' ? 20 : 10
  await ctx.progress(5, `Performance : ${N} mesures`)
  const times: number[] = [], ttfbs: number[] = []
  let errors = 0, bytes = 0, totalBytes = 0, encoding = '', cache = '', status = 0
  const t0 = performance.now()
  for (let i = 0; i < N; i++) {
    if (await ctx.cancelled()) return
    try {
      const r = await safeRequest(app.url, { scope: ctx.scope, headers: { 'accept-encoding': 'gzip, br' } })
      if (r.status >= 500) errors++
      times.push(r.total)
      ttfbs.push(r.ttfb)
      bytes = r.bytes
      totalBytes += r.bytes
      encoding = r.headers.get('content-encoding') ?? ''
      cache = r.headers.get('cache-control') ?? ''
      status = r.status
    } catch {
      errors++
    }
  }
  if (!times.length) throw new Error('Cible injoignable pendant la mesure de performance')
  const elapsed = (performance.now() - t0) / 1000
  const sorted = [...times].sort((a, b) => a - b)
  const avg = times.reduce((a, b) => a + b, 0) / times.length
  const std = Math.sqrt(times.reduce((a, b) => a + (b - avg) ** 2, 0) / times.length)
  const errorRate = errors / N
  const m = (name: string, v: number, unit: string) => col.metric('SERVER', name, v, unit)
  m('Average Response Time', avg, 'ms')
  m('P50 Response Time', pct(sorted, 50), 'ms')
  m('P90 Response Time', pct(sorted, 90), 'ms')
  m('P95 Response Time', pct(sorted, 95), 'ms')
  m('P99 Response Time', pct(sorted, 99), 'ms')
  m('Min Response Time', sorted[0], 'ms')
  m('Max Response Time', sorted[sorted.length - 1], 'ms')
  m('Écart-type', std, 'ms')
  m('Time To First Byte (moyen)', ttfbs.reduce((a, b) => a + b, 0) / ttfbs.length, 'ms')
  m('Requests Per Second', N / elapsed, 'req/s')
  m('Error Rate', errorRate * 100, '%')
  m('Throughput', totalBytes / 1024 / elapsed, 'Ko/s')
  m('Poids de la page (HTML)', bytes / 1024, 'Ko')
  col.info.perf = { avg: r1(avg), p95: r1(pct(sorted, 95)), p99: r1(pct(sorted, 99)), errorRate: r1(errorRate * 100), encoding, cache, status, samples: times.map((t) => Math.round(t)) }
  col.test('PERF', 'Temps de réponse moyen < 1 s', avg < 1000, `${r1(avg)} ms en moyenne sur ${N} requêtes`)
  col.test('PERF', 'P95 < 2 s', pct(sorted, 95) < 2000, `P95 : ${r1(pct(sorted, 95))} ms`)
  col.test('PERF', 'Aucune erreur serveur pendant la mesure', errors === 0, `${errors} erreur(s) sur ${N}`)
  col.test('PERF', 'Réponses stables (écart-type < 50 % de la moyenne)', std < avg * 0.5, `Écart-type ${r1(std)} ms pour une moyenne de ${r1(avg)} ms`)
  col.test('PERF', 'Compression HTTP activée', !!encoding || bytes < 2048, encoding ? `Content-Encoding: ${encoding}` : 'Aucune compression (gzip/brotli) sur la page HTML')
  if (!encoding && bytes > 20_000) col.add({ severity: 'LOW', title: 'Page HTML servie sans compression', description: `La page de ${Math.round(bytes / 1024)} Ko est transmise sans gzip ni brotli.`, resource: app.url, evidence: `Content-Encoding absent, taille ${bytes} octets`, recommendation: 'Activer la compression gzip ou brotli sur le serveur ou le reverse proxy.', category: 'PERFORMANCE' })
  if (app.perfBudgetMs > 0) {
    const ok = avg <= app.perfBudgetMs
    col.test('PERF', `Budget de performance (${app.perfBudgetMs} ms)`, ok, `Temps moyen ${r1(avg)} ms pour un budget de ${app.perfBudgetMs} ms`)
    if (!ok) col.add({ severity: 'MEDIUM', title: 'Budget de performance dépassé', description: `Le temps de réponse moyen dépasse le budget défini pour cette application.`, resource: app.url, evidence: `${r1(avg)} ms mesurés > ${app.perfBudgetMs} ms`, recommendation: 'Analyser le temps serveur (TTFB), le cache et les requêtes lentes.', category: 'PERFORMANCE' })
  }

  // Analyse des ressources référencées (poids, cache)
  await ctx.progress(45, 'Performance : ressources')
  try {
    const page = await safeRequest(app.url, { scope: ctx.scope })
    const refs = new Set<string>()
    for (const m of page.body.matchAll(/<(?:script|link|img)\b[^>]*(?:src|href)\s*=\s*["']([^"'#\s]+)["']/gi)) {
      try {
        const u = new URL(m[1], page.url)
        if ((u.protocol === 'http:' || u.protocol === 'https:') && /\.(js|css|png|jpe?g|gif|webp|svg|woff2?|ttf)(\?|$)/i.test(u.pathname + u.search)) refs.add(u.href)
      } catch {}
      if (refs.size >= 15) break
    }
    let total = 0, noCache = 0, heavy: string[] = []
    const scripts = (page.body.match(/<script\b[^>]*src=/gi) ?? []).length, styles = (page.body.match(/<link\b[^>]*rel=["']?stylesheet/gi) ?? []).length, images = (page.body.match(/<img\b/gi) ?? []).length
    col.metric('RESOURCES', 'Scripts référencés', scripts, '')
    col.metric('RESOURCES', 'Feuilles de style référencées', styles, '')
    col.metric('RESOURCES', 'Images référencées', images, '')
    for (const u of refs) {
      if (await ctx.cancelled()) return
      try {
        const same = new URL(u).origin === ctx.scope.origin
        if (same && !inScope(ctx.scope, u)) continue
        const r = await safeRequest(u, { scope: same ? ctx.scope : undefined, maxBytes: 4_000_000, headers: { 'accept-encoding': 'gzip, br' } })
        total += r.bytes
        if (r.bytes > 500_000) heavy.push(`${Math.round(r.bytes / 1024)} Ko — ${cut(u, 100)}`)
        const cc = r.headers.get('cache-control') ?? ''
        if (!/max-age=\d{4,}|immutable/.test(cc)) noCache++
      } catch {}
    }
    col.metric('RESOURCES', 'Poids des ressources vérifiées', total / 1024, 'Ko')
    col.test('PERF', 'Aucune ressource de plus de 500 Ko', heavy.length === 0, heavy.length ? heavy.join('\n') : `${refs.size} ressource(s) vérifiée(s)`)
    col.test('PERF', 'Ressources statiques mises en cache', refs.size === 0 || noCache <= refs.size / 2, `${noCache} ressource(s) sur ${refs.size} sans Cache-Control long (max-age ≥ 1000 s ou immutable)`)
    if (heavy.length) col.add({ severity: 'LOW', title: 'Ressources trop lourdes', description: `${heavy.length} ressource(s) dépassent 500 Ko.`, resource: app.url, evidence: heavy.slice(0, 5).join('\n'), recommendation: 'Compresser, redimensionner (images), découper (code splitting) ou différer le chargement.', category: 'PERFORMANCE' })
    if (scripts > 25) col.add({ severity: 'INFO', title: 'Nombre élevé de scripts', description: `${scripts} scripts externes sont référencés sur la page.`, resource: app.url, evidence: `${scripts} balises <script src>`, recommendation: 'Regrouper et différer les scripts non critiques (defer/async).', category: 'PERFORMANCE' })
  } catch {}
}

/** Test de charge encadré (8.2) : utilisateurs virtuels et durée plafonnés par la formule, arrêt automatique si la cible souffre. */
export async function runLoad(ctx: ScanContext, col: Collector): Promise<void> {
  const app = ctx.app
  const limits = ctx.config.limits ?? { vus: 5, seconds: 15 }
  const vus = Math.max(1, Math.min(Number(ctx.config.vus) || 5, limits.vus))
  const seconds = Math.max(5, Math.min(Number(ctx.config.seconds) || 15, limits.seconds))
  const thresholds = { p95Ms: Number(ctx.config.p95Ms) || 2000, errorRate: Number(ctx.config.errorRate) || 5 }
  const paths: string[] = (Array.isArray(ctx.config.paths) ? ctx.config.paths : []).map((p: string) => String(p)).filter((p) => p.startsWith('/')).slice(0, 5)
  const targets = (paths.length ? paths : ['/']).map((p) => new URL(p, app.url).href).filter((u) => inScope(ctx.scope, u))
  if (!targets.length) throw new Error('Aucune cible de charge dans le périmètre autorisé')
  col.info.load = { vus, seconds, thresholds, targets }
  await ctx.progress(5, `Charge : ${vus} utilisateurs virtuels pendant ${seconds} s`)

  type Bucket = { n: number; errors: number; lat: number[]; bytes: number }
  const buckets: Bucket[] = Array.from({ length: seconds }, () => ({ n: 0, errors: 0, lat: [], bytes: 0 }))
  const start = performance.now()
  let stop = false, aborted = ''
  const worker = async (id: number) => {
    let i = id
    while (!stop) {
      const t = performance.now()
      const sec = Math.floor((t - start) / 1000)
      if (sec >= seconds) break
      const url = targets[i++ % targets.length]
      try {
        const r = await safeRequest(url, { readBody: true, maxBytes: 500_000, timeoutMs: 10000, headers: ctx.scope.headers })
        const b = buckets[Math.min(seconds - 1, Math.floor((performance.now() - start) / 1000))]
        b.n++
        b.lat.push(r.total)
        b.bytes += r.bytes
        if (r.status >= 500 || r.status === 429) b.errors++
      } catch {
        const b = buckets[Math.min(seconds - 1, Math.floor((performance.now() - start) / 1000))]
        b.n++
        b.errors++
      }
    }
  }
  const guard = (async () => {
    let bad = 0
    while (!stop) {
      await new Promise((r) => setTimeout(r, 1000))
      const sec = Math.floor((performance.now() - start) / 1000)
      if (sec >= seconds) break
      if (await ctx.cancelled()) {
        aborted = 'Annulé par l\'utilisateur'
        break
      }
      await ctx.progress(5 + Math.round((sec / seconds) * 85), `Charge : ${sec}/${seconds} s`)
      const b = buckets[Math.max(0, sec - 1)]
      // Protection de la cible : arrêt si plus de la moitié des requêtes échouent pendant 3 secondes consécutives
      bad = b.n >= 3 && b.errors / b.n > 0.5 ? bad + 1 : 0
      if (bad >= 3) {
        aborted = 'Arrêt automatique : la cible renvoie trop d\'erreurs (protection)'
        break
      }
    }
    stop = true
  })()
  await Promise.all([...Array.from({ length: vus }, (_, i) => worker(i)), guard])
  stop = true
  const all = buckets.flatMap((b) => b.lat).sort((a, b) => a - b)
  const n = buckets.reduce((a, b) => a + b.n, 0), errors = buckets.reduce((a, b) => a + b.errors, 0), bytes = buckets.reduce((a, b) => a + b.bytes, 0)
  const ran = Math.max(1, Math.min(seconds, Math.ceil((performance.now() - start) / 1000)))
  if (!all.length) throw new Error(aborted || 'Aucune réponse reçue pendant le test de charge')
  const avg = all.reduce((a, b) => a + b, 0) / all.length
  const errorRate = (errors / Math.max(1, n)) * 100
  const m = (name: string, v: number, unit: string) => col.metric('LOAD', name, v, unit)
  m('Utilisateurs virtuels', vus, '')
  m('Durée effective', ran, 's')
  m('Requêtes totales', n, '')
  m('Average Response Time', avg, 'ms')
  m('P95 Response Time', pct(all, 95), 'ms')
  m('P99 Response Time', pct(all, 99), 'ms')
  m('Max Response Time', all[all.length - 1], 'ms')
  m('Requests Per Second', n / ran, 'req/s')
  m('Error Rate', errorRate, '%')
  m('Throughput', bytes / 1024 / ran, 'Ko/s')
  col.info.load.series = buckets.slice(0, ran).map((b, i) => {
    const s = [...b.lat].sort((x, y) => x - y)
    return { t: i + 1, rps: b.n, errors: b.errors, p50: s.length ? Math.round(pct(s, 50)) : null, p95: s.length ? Math.round(pct(s, 95)) : null }
  })
  col.info.load.aborted = aborted || null
  col.info.load.score = perfScore(avg, errorRate / 100, pct(all, 95))
  col.test('LOAD', `P95 sous le seuil (${thresholds.p95Ms} ms)`, pct(all, 95) <= thresholds.p95Ms, `P95 : ${r1(pct(all, 95))} ms`)
  col.test('LOAD', `Taux d'erreur sous le seuil (${thresholds.errorRate} %)`, errorRate <= thresholds.errorRate, `${r1(errorRate)} % d'erreurs sur ${n} requêtes`)
  col.test('LOAD', 'Test mené à son terme', !aborted, aborted || `${ran} s, ${vus} VU, ${n} requêtes`)
  if (errorRate > thresholds.errorRate) col.add({ severity: errorRate > 25 ? 'HIGH' : 'MEDIUM', title: 'Dégradation sous charge', description: `Avec ${vus} utilisateurs virtuels, ${r1(errorRate)} % des requêtes échouent.`, resource: app.url, evidence: `${errors} erreurs sur ${n} requêtes en ${ran} s — P95 ${r1(pct(all, 95))} ms${aborted ? ` — ${aborted}` : ''}`, recommendation: 'Dimensionner l\'infrastructure, mettre en cache, limiter les requêtes coûteuses et activer l\'autoscaling.', category: 'PERFORMANCE' })
}
