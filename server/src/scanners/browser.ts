// Tests en navigateur réel avec Playwright (section 5) : erreurs JavaScript, ressources en échec, Core Web Vitals,
// accessibilité (axe-core), affichage mobile, validation des formulaires (sans soumission), captures et comparaison visuelle.
// Le navigateur est optionnel : si Playwright ou le navigateur n'est pas installé, les tests sont marqués SKIP.
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { config } from '../config.js'
import { hostAllowed, isPrivateIp, cut, errMsg } from './http.js'
import { Collector, type ScanContext } from './types.js'
import net from 'node:net'

const require = createRequire(import.meta.url)
const browsers = new Map<string, any>()
let pw: any = null

async function loadPlaywright() {
  if (pw !== null) return pw
  try {
    pw = await import('playwright')
  } catch {
    pw = false
  }
  return pw
}

/** Renvoie une instance de navigateur partagée, ou null s'il n'est pas disponible. */
export async function getBrowser(name: string): Promise<any | null> {
  if (!config.playwright.enabled) return null
  const lib = await loadPlaywright()
  if (!lib || !lib[name]) return null
  if (browsers.has(name)) return browsers.get(name)
  try {
    const b = await lib[name].launch({ headless: true, timeout: 20000 })
    b.on('disconnected', () => browsers.delete(name))
    browsers.set(name, b)
    return b
  } catch (e) {
    console.warn(`[browser] ${name} indisponible : ${errMsg(e)}`)
    browsers.set(name, null)
    return null
  }
}
export async function availableBrowsers(): Promise<string[]> {
  const out: string[] = []
  for (const n of ['chromium', 'firefox', 'webkit']) if (await getBrowser(n)) out.push(n)
  return out
}
export async function closeBrowsers() {
  for (const b of browsers.values()) await b?.close().catch(() => {})
  browsers.clear()
}

const axeSource = (() => {
  try {
    return fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8')
  } catch {
    return ''
  }
})()

const hostCache = new Map<string, boolean>()
async function allowed(hostname: string) {
  const h = hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(h)) return config.allowPrivateTargets || !isPrivateIp(h)
  if (!hostCache.has(h)) hostCache.set(h, await hostAllowed(h))
  return hostCache.get(h)!
}

const VITALS_SCRIPT = `() => new Promise((resolve) => {
  const out = {};
  try {
    const nav = performance.getEntriesByType('navigation')[0];
    if (nav) { out.ttfb = nav.responseStart; out.domContentLoaded = nav.domContentLoadedEventEnd; out.load = nav.loadEventEnd; out.transfer = nav.transferSize; }
    const paints = performance.getEntriesByType('paint');
    for (const p of paints) if (p.name === 'first-contentful-paint') out.fcp = p.startTime;
    const res = performance.getEntriesByType('resource');
    out.resources = res.length; out.bytes = res.reduce((a, r) => a + (r.transferSize || 0), 0) + (out.transfer || 0);
    out.byType = {}; for (const r of res) { const t = r.initiatorType || 'other'; out.byType[t] = out.byType[t] || { n: 0, bytes: 0 }; out.byType[t].n++; out.byType[t].bytes += r.transferSize || 0; }
    out.slow = res.filter(r => r.duration > 1000).map(r => ({ name: r.name.slice(0, 160), ms: Math.round(r.duration) })).slice(0, 5);
    out.heavy = res.filter(r => (r.transferSize || 0) > 500000).map(r => ({ name: r.name.slice(0, 160), kb: Math.round(r.transferSize / 1024) })).slice(0, 5);
    let lcp = 0, cls = 0;
    try { new PerformanceObserver((l) => { for (const e of l.getEntries()) lcp = e.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true }); } catch {}
    try { new PerformanceObserver((l) => { for (const e of l.getEntries()) if (!e.hadRecentInput) cls += e.value; }).observe({ type: 'layout-shift', buffered: true }); } catch {}
    setTimeout(() => { out.lcp = lcp; out.cls = Math.round(cls * 1000) / 1000; resolve(out); }, 1200);
  } catch (e) { resolve(out); }
})`

const DOM_CHECKS = `() => {
  const imgs = [...document.images];
  const broken = imgs.filter(i => i.complete && i.naturalWidth === 0 && i.getAttribute('src')).map(i => i.getAttribute('src').slice(0, 120));
  const overflow = document.documentElement.scrollWidth > window.innerWidth + 2;
  const small = [...document.querySelectorAll('a,button,input[type=submit],input[type=button]')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24); }).length;
  const forms = [...document.querySelectorAll('form')].map(f => {
    const required = [...f.querySelectorAll('[required]')];
    const submit = f.querySelector('button:not([type=button]),input[type=submit]');
    return { action: (f.getAttribute('action') || '').slice(0, 100), required: required.length, validBlocked: required.length ? !f.checkValidity() : null, hasSubmit: !!submit, labels: [...f.querySelectorAll('input:not([type=hidden]):not([type=submit]),select,textarea')].filter(i => !i.labels || i.labels.length === 0).filter(i => !i.getAttribute('aria-label') && !i.getAttribute('aria-labelledby') && !i.getAttribute('placeholder')).length };
  });
  const h1 = document.querySelectorAll('h1').length;
  const ids = [...document.querySelectorAll('[id]')].map(e => e.id); const dup = ids.filter((v, i) => ids.indexOf(v) !== i).length;
  return { broken, overflow, small, forms, h1, dup, title: document.title, text: (document.body?.innerText || '').length };
}`

export async function runBrowserQA(ctx: ScanContext, col: Collector): Promise<void> {
  const names = ctx.browsers.length ? ctx.browsers : ['chromium']
  let ran = false
  for (const name of names) {
    if (await ctx.cancelled()) return
    const browser = await getBrowser(name)
    if (!browser) {
      col.test('BROWSER', `Navigateur ${name}`, 'SKIP', `Navigateur ${name} non disponible sur ce serveur (installer avec : npx playwright install ${name}).`, 0, name)
      continue
    }
    ran = true
    await runInBrowser(ctx, col, browser, name).catch((e) => col.test('BROWSER', 'Session navigateur', false, `Échec : ${errMsg(e)}`, 0, name))
  }
  col.info.browserRan = ran
}

async function runInBrowser(ctx: ScanContext, col: Collector, browser: any, name: string) {
  const t0 = performance.now()
  const context = await browser.newContext({ viewport: { width: 1366, height: 850 }, userAgent: `Mozilla/5.0 SentinelX-Scanner/1.0 (${name})`, ignoreHTTPSErrors: false, extraHTTPHeaders: ctx.scope.headers, locale: 'fr-FR' })
  context.setDefaultTimeout(config.playwright.timeoutMs)
  const page = await context.newPage()
  const consoleErrors: string[] = [], pageErrors: string[] = [], failed: string[] = [], httpErrors: string[] = []
  let docRequests = 0
  // Garde SSRF : chaque requête du navigateur est vérifiée (destinations internes bloquées, budget décompté sur les documents)
  await context.route('**/*', async (route: any) => {
    const req = route.request()
    try {
      const u = new URL(req.url())
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return route.abort()
      if (!(await allowed(u.hostname))) return route.abort('blockedbyclient')
      if (req.resourceType() === 'document') {
        docRequests++
        if (ctx.scope.used + docRequests > ctx.scope.maxRequests) return route.abort()
      }
      return route.continue()
    } catch {
      return route.abort()
    }
  })
  page.on('console', (m: any) => { if (m.type() === 'error') consoleErrors.push(cut(m.text(), 200)) })
  page.on('pageerror', (e: any) => pageErrors.push(cut(String(e?.message ?? e), 200)))
  page.on('requestfailed', (r: any) => { const f = r.failure()?.errorText ?? ''; if (!/blockedbyclient|ERR_BLOCKED_BY_CLIENT|ERR_ABORTED/i.test(f)) failed.push(`${cut(r.url(), 120)} (${f})`) })
  page.on('response', (r: any) => { if (r.status() >= 400 && new URL(r.url()).origin === ctx.scope.origin) httpErrors.push(`${r.status()} ${cut(r.url(), 120)}`) })

  let resp: any
  try {
    resp = await page.goto(ctx.app.url, { waitUntil: 'load', timeout: config.playwright.timeoutMs })
  } catch (e) {
    col.test('BROWSER', 'Chargement de la page', false, `La page n'a pas pu être chargée dans ${name} : ${errMsg(e)}`, performance.now() - t0, name)
    await context.close()
    return
  }
  ctx.scope.used += docRequests
  const loadMs = performance.now() - t0
  col.test('BROWSER', 'Chargement complet de la page', !!resp && resp.status() < 400, `HTTP ${resp?.status()} — événement load en ${Math.round(loadMs)} ms`, loadMs, name)
  await page.waitForTimeout(800)

  // Erreurs et ressources
  col.test('BROWSER', 'Aucune erreur JavaScript', pageErrors.length === 0, pageErrors.length ? pageErrors.slice(0, 5).join('\n') : 'Aucune exception non interceptée', 0, name)
  col.test('BROWSER', 'Console sans erreur', consoleErrors.length === 0, consoleErrors.length ? `${consoleErrors.length} message(s) d'erreur :\n${consoleErrors.slice(0, 5).join('\n')}` : 'Aucun message d\'erreur en console', 0, name)
  col.test('BROWSER', 'Toutes les ressources se chargent', failed.length === 0 && httpErrors.length === 0, [...httpErrors, ...failed].slice(0, 8).join('\n') || 'Aucune ressource en échec', 0, name)

  // Vitals et ressources
  try {
    const v: any = await page.evaluate(`(${VITALS_SCRIPT})()`)
    col.info.vitals = v
    if (v.fcp) col.metric('VITALS', 'First Contentful Paint', v.fcp, 'ms')
    if (v.lcp) col.metric('VITALS', 'Largest Contentful Paint', v.lcp, 'ms')
    if (v.cls != null) col.metric('VITALS', 'Cumulative Layout Shift', v.cls, '')
    if (v.ttfb) col.metric('VITALS', 'Time To First Byte (navigateur)', v.ttfb, 'ms')
    if (v.domContentLoaded) col.metric('VITALS', 'DOM Content Loaded', v.domContentLoaded, 'ms')
    if (v.load) col.metric('VITALS', 'Load', v.load, 'ms')
    col.metric('RESOURCES', 'Nombre de ressources', v.resources ?? 0, '')
    col.metric('RESOURCES', 'Poids total transféré', (v.bytes ?? 0) / 1024, 'Ko')
    col.test('BROWSER', 'Largest Contentful Paint < 2,5 s', !v.lcp || v.lcp < 2500, v.lcp ? `LCP mesuré : ${Math.round(v.lcp)} ms (bon < 2500, à améliorer < 4000)` : 'LCP non mesurable', 0, name)
    col.test('BROWSER', 'Cumulative Layout Shift < 0,1', v.cls == null || v.cls < 0.1, v.cls != null ? `CLS mesuré : ${v.cls}` : 'CLS non mesurable', 0, name)
    col.test('BROWSER', 'Aucune ressource trop lourde (> 500 Ko)', !(v.heavy?.length), v.heavy?.length ? v.heavy.map((h: any) => `${h.kb} Ko — ${h.name}`).join('\n') : 'Aucune ressource de plus de 500 Ko', 0, name)
    col.test('BROWSER', 'Aucune requête lente (> 1 s)', !(v.slow?.length), v.slow?.length ? v.slow.map((s: any) => `${s.ms} ms — ${s.name}`).join('\n') : 'Toutes les ressources répondent en moins d\'une seconde', 0, name)
  } catch {}

  // DOM : images cassées, formulaires, structure
  try {
    const d: any = await page.evaluate(`(${DOM_CHECKS})()`)
    col.test('BROWSER', 'Images affichées correctement', d.broken.length === 0, d.broken.length ? `${d.broken.length} image(s) non chargée(s) : ${d.broken.slice(0, 5).join(', ')}` : 'Toutes les images sont rendues', 0, name)
    col.test('BROWSER', 'Un seul titre principal (h1)', d.h1 === 1, `${d.h1} balise(s) h1`, 0, name)
    col.test('BROWSER', 'Identifiants HTML uniques', d.dup === 0, d.dup ? `${d.dup} identifiant(s) dupliqué(s)` : 'Aucun doublon d\'attribut id', 0, name)
    col.test('BROWSER', 'Contenu textuel présent', d.text > 50, `${d.text} caractère(s) de texte visibles`, 0, name)
    for (const [i, f] of (d.forms as any[]).slice(0, 6).entries()) {
      const label = `Formulaire ${i + 1}${f.action ? ` (${f.action})` : ''}`
      if (f.required > 0) col.test('FORMS', `${label} : champs obligatoires bloquent la soumission vide`, f.validBlocked === true, `${f.required} champ(s) obligatoire(s) — validation HTML5 ${f.validBlocked ? 'active' : 'inactive'} (aucune soumission réelle effectuée)`, 0, name)
      else col.test('FORMS', `${label} : validation des champs`, 'SKIP', 'Aucun champ obligatoire déclaré : la validation côté client n\'a pas pu être vérifiée sans soumission.', 0, name)
      col.test('FORMS', `${label} : bouton de soumission présent`, f.hasSubmit, f.hasSubmit ? 'Bouton trouvé' : 'Aucun bouton de soumission', 0, name)
      col.test('FORMS', `${label} : champs étiquetés`, f.labels === 0, f.labels ? `${f.labels} champ(s) sans label ni aria-label` : 'Tous les champs ont une étiquette', 0, name)
    }
  } catch {}

  // Accessibilité (axe-core)
  if (axeSource) {
    try {
      await page.addScriptTag({ content: axeSource })
      const res: any = await page.evaluate(`axe.run(document, { resultTypes: ['violations'], runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'best-practice'] } })`)
      const v: any[] = res.violations ?? []
      const serious = v.filter((x) => x.impact === 'critical' || x.impact === 'serious')
      col.info.axe = { violations: v.length, serious: serious.length, items: v.slice(0, 15).map((x) => ({ id: x.id, impact: x.impact, help: x.help, nodes: x.nodes.length })) }
      col.test('ACCESSIBILITY', 'Aucune violation d\'accessibilité critique ou sérieuse', serious.length === 0, serious.length ? serious.slice(0, 6).map((x) => `[${x.impact}] ${x.help} (${x.nodes.length} élément(s))`).join('\n') : `${v.length} violation(s) mineure(s) au total`, 0, name)
      col.test('ACCESSIBILITY', 'Conformité WCAG 2.1 AA (axe-core)', v.length === 0, v.length ? `${v.length} règle(s) en échec : ${v.slice(0, 8).map((x) => x.id).join(', ')}` : 'Aucune violation détectée par axe-core', 0, name)
      for (const x of serious.slice(0, 5)) {
        col.add({ severity: x.impact === 'critical' ? 'MEDIUM' : 'LOW', title: `Accessibilité : ${x.help}`, description: x.description, resource: ctx.app.url, evidence: `${x.nodes.length} élément(s) — ex. : ${cut(x.nodes[0]?.html ?? '', 160)}`, recommendation: `${x.helpUrl}`, category: 'ACCESSIBILITY', cwe: '', owasp: '' })
      }
    } catch (e) {
      col.test('ACCESSIBILITY', 'Analyse axe-core', 'SKIP', `Analyse impossible : ${errMsg(e)}`, 0, name)
    }
  }

  // Capture et comparaison visuelle
  try {
    const file = path.join(config.screenshotsDir, `${ctx.scanId}-${name}.png`)
    await page.screenshot({ path: file, fullPage: false })
    col.info.screenshots = { ...(col.info.screenshots ?? {}), [name]: path.basename(file) }
    const baseline = path.join(config.screenshotsDir, `baseline-${ctx.app.id}-${name}.png`)
    if (fs.existsSync(baseline)) {
      const diff = await compareImages(baseline, file, path.join(config.screenshotsDir, `${ctx.scanId}-${name}-diff.png`))
      col.info.visualDiff = { ...(col.info.visualDiff ?? {}), [name]: diff }
      col.test('VISUAL', 'Comparaison visuelle avec la référence', diff.percent < 2, `${diff.percent} % de pixels différents par rapport à la capture de référence${diff.sizeChanged ? ' (dimensions différentes)' : ''}`, 0, name)
    } else {
      fs.copyFileSync(file, baseline)
      col.test('VISUAL', 'Capture de référence enregistrée', 'SKIP', 'Première capture : elle servira de référence pour les prochains audits.', 0, name)
    }
  } catch {}

  // Affichage mobile
  try {
    const mobile = await context.newPage()
    await mobile.setViewportSize({ width: 390, height: 844 })
    await mobile.goto(ctx.app.url, { waitUntil: 'load', timeout: config.playwright.timeoutMs })
    const d: any = await mobile.evaluate(`(${DOM_CHECKS})()`)
    col.test('BROWSER', 'Pas de défilement horizontal sur mobile (390 px)', !d.overflow, d.overflow ? 'La page déborde horizontalement sur un écran mobile' : 'Largeur adaptée', 0, name)
    col.test('BROWSER', 'Zones tactiles suffisantes (≥ 24 px)', d.small < 5, `${d.small} élément(s) interactif(s) de moins de 24 px`, 0, name)
    const mfile = path.join(config.screenshotsDir, `${ctx.scanId}-${name}-mobile.png`)
    await mobile.screenshot({ path: mfile })
    col.info.screenshots = { ...(col.info.screenshots ?? {}), [`${name}-mobile`]: path.basename(mfile) }
    await mobile.close()
  } catch {}

  await context.close()
}

async function compareImages(a: string, b: string, out: string): Promise<{ percent: number; sizeChanged: boolean }> {
  const { PNG } = await import('pngjs')
  const pixelmatch = (await import('pixelmatch')).default
  const A = PNG.sync.read(fs.readFileSync(a)), B = PNG.sync.read(fs.readFileSync(b))
  const w = Math.min(A.width, B.width), h = Math.min(A.height, B.height)
  const crop = (img: any) => {
    const o = new PNG({ width: w, height: h })
    PNG.bitblt(img, o, 0, 0, w, h, 0, 0)
    return o
  }
  const ca = crop(A), cb = crop(B), diff = new PNG({ width: w, height: h })
  const n = pixelmatch(ca.data, cb.data, diff.data, w, h, { threshold: 0.12 })
  fs.writeFileSync(out, PNG.sync.write(diff))
  return { percent: Math.round((n / (w * h)) * 10000) / 100, sizeChanged: A.width !== B.width || A.height !== B.height }
}
