// Moteur QA (section 5) : contrôles statiques sur le HTML, liens et ressources, puis tests en navigateur réel.
import { cut, errMsg, inScope, safeRequest, type Fetched } from './http.js'
import { runBrowserQA } from './browser.js'
import { Collector, type ScanContext } from './types.js'

export async function runQA(ctx: ScanContext, col: Collector): Promise<void> {
  const app = ctx.app
  const get = (url: string, o: any = {}) => safeRequest(url, { scope: ctx.scope, ...o })
  await ctx.progress(5, 'QA : page principale')
  let page: Fetched
  try {
    page = await get(app.url)
  } catch (e) {
    col.test('STATIC', 'Page principale accessible', false, errMsg(e))
    return
  }
  col.test('STATIC', 'Page principale accessible', page.status < 400, `HTTP ${page.status} en ${Math.round(page.total)} ms${page.redirected ? ` (après ${page.chain.length} redirection(s))` : ''}`, page.total)
  const html = page.body
  const ct = page.headers.get('content-type') ?? ''
  const isHtml = ct.includes('html')
  if (!isHtml) {
    col.test('STATIC', 'Réponse exploitable', true, `Type de contenu : ${ct || 'inconnu'} (contrôles HTML ignorés)`)
    return
  }
  // Structure du document
  col.test('STATIC', 'Doctype HTML5 déclaré', /^\s*<!doctype html/i.test(html), 'Un doctype HTML5 évite le mode « quirks » du navigateur')
  col.test('STATIC', 'Encodage déclaré (charset)', /<meta[^>]+charset/i.test(html) || /charset=/i.test(ct), ct.includes('charset') ? `Content-Type: ${ct}` : 'Balise meta charset attendue')
  col.test('STATIC', 'Balise <title> renseignée', /<title[^>]*>\s*[^<\s]/i.test(html), 'Le titre de page est requis pour la navigation et le référencement')
  col.test('STATIC', 'Langue déclarée sur <html>', /<html[^>]*\slang=/i.test(html), 'Attribut lang attendu sur la balise html')
  col.test('STATIC', 'Meta viewport (affichage mobile)', /<meta[^>]+name=["']?viewport/i.test(html), 'Nécessaire pour un affichage responsive')
  col.test('STATIC', 'Meta description présente', /<meta[^>]+name=["']?description["']?[^>]+content=["'][^"']{20,}/i.test(html), 'Description de 20 caractères minimum attendue (référencement, partage)')
  col.test('STATIC', 'Favicon déclaré', /<link[^>]+rel=["'][^"']*icon/i.test(html), 'Lien rel="icon" attendu')
  col.test('STATIC', 'URL canonique', /<link[^>]+rel=["']canonical/i.test(html), 'Lien rel="canonical" attendu pour éviter le contenu dupliqué')
  const h1 = (html.match(/<h1\b/gi) ?? []).length
  col.test('STATIC', 'Un titre principal h1', h1 === 1, `${h1} balise(s) h1 trouvée(s)`)
  const deprecated = html.match(/<(font|center|marquee|blink|frame|frameset)\b/gi) ?? []
  col.test('STATIC', 'Aucune balise HTML obsolète', deprecated.length === 0, deprecated.length ? `${deprecated.length} balise(s) : ${[...new Set(deprecated.map((d) => d.toLowerCase()))].join(', ')}` : 'Aucune balise dépréciée')
  const imgs = html.match(/<img\b[^>]*>/gi) ?? []
  const noAlt = imgs.filter((i) => !/\salt\s*=/i.test(i))
  col.test('STATIC', 'Images avec texte alternatif', noAlt.length === 0, `${noAlt.length} image(s) sans attribut alt sur ${imgs.length}`)
  const inlineHandlers = (html.match(/\son(click|load|error|mouseover)\s*=/gi) ?? []).length
  col.test('STATIC', 'Peu de gestionnaires d\'événements en ligne', inlineHandlers < 10, `${inlineHandlers} attribut(s) on* en ligne (complique la CSP et la maintenance)`)
  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) ?? []
  const required = (html.match(/<(input|select|textarea)\b[^>]*\srequired\b/gi) ?? []).length
  col.test('STATIC', 'Formulaires détectés', true, `${forms.length} formulaire(s), ${required} champ(s) obligatoire(s) déclaré(s)`)
  const inputsNoLabel = [...html.matchAll(/<input\b[^>]*>/gi)].filter((m) => !/type\s*=\s*["']?(hidden|submit|button|checkbox|radio)/i.test(m[0]) && !/aria-label|placeholder|\sid\s*=/i.test(m[0])).length
  col.test('STATIC', 'Champs de saisie identifiables', inputsNoLabel === 0, inputsNoLabel ? `${inputsNoLabel} champ(s) sans id, aria-label ni placeholder` : 'Tous les champs peuvent être étiquetés')
  col.test('STATIC', 'Poids du HTML raisonnable', page.bytes < 500_000, `${Math.round(page.bytes / 1024)} Ko de HTML`)

  // Liens et ressources : vérification non destructive (GET), limitée en volume
  await ctx.progress(20, 'QA : liens et ressources')
  const found = new Set<string>()
  const external = new Set<string>()
  const limit = ctx.profile === 'DEEP' ? 60 : 30
  for (const m of html.matchAll(/(?:href|src)\s*=\s*["']([^"'#\s]+)["']/gi)) {
    try {
      const u = new URL(m[1], page.url)
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue
      if (u.origin === ctx.scope.origin) {
        if (inScope(ctx.scope, u)) found.add(u.href)
      } else if (external.size < 10) external.add(u.href)
    } catch {}
    if (found.size >= limit) break
  }
  const links = [...found]
  const broken: string[] = []
  const slow: string[] = []
  const t0 = performance.now()
  let idx = 0
  await Promise.all(
    Array.from({ length: 5 }, async () => {
      while (idx < links.length) {
        if (await ctx.cancelled()) return
        const link = links[idx++]
        try {
          const r = await get(link, { readBody: false })
          if (r.status >= 400 && r.status !== 401 && r.status !== 403 && r.status !== 429) broken.push(`${r.status} ${link}`)
          if (r.total > 3000) slow.push(`${Math.round(r.total)} ms ${link}`)
        } catch (e) {
          const msg = errMsg(e)
          if (!/Budget de requêtes/.test(msg)) broken.push(`ERREUR ${link} (${msg})`)
        }
      }
    }),
  )
  col.test('STATIC', `Liens et ressources internes valides (${links.length} vérifiés)`, broken.length === 0, broken.length ? broken.slice(0, 8).join('\n') : 'Aucun lien cassé détecté', performance.now() - t0)
  col.test('STATIC', 'Ressources internes rapides (< 3 s)', slow.length === 0, slow.length ? slow.slice(0, 5).join('\n') : 'Toutes les ressources répondent en moins de 3 s')
  // Liens externes : contrôle léger (HEAD/GET sans corps), échecs non bloquants
  const extBroken: string[] = []
  for (const l of external) {
    try {
      const r = await safeRequest(l, { readBody: false, timeoutMs: 8000 })
      if (r.status >= 400 && r.status !== 401 && r.status !== 403 && r.status !== 429 && r.status !== 405) extBroken.push(`${r.status} ${l}`)
    } catch (e) {
      extBroken.push(`ERREUR ${cut(l, 100)} (${errMsg(e)})`)
    }
  }
  if (external.size) col.test('STATIC', `Liens externes joignables (${external.size} vérifiés)`, extBroken.length === 0, extBroken.length ? extBroken.slice(0, 5).join('\n') : 'Tous les liens externes répondent')
  // 404 personnalisée
  try {
    const nf = await get(`${ctx.scope.origin}/sentinelx-page-inexistante-${Date.now()}`, { maxBytes: 50000 })
    col.test('STATIC', 'Page 404 correcte', nf.status === 404 && nf.body.length > 200, nf.status !== 404 ? `Une page inexistante renvoie HTTP ${nf.status} au lieu de 404` : `HTTP 404 avec une page de ${Math.round(nf.bytes / 1024)} Ko`)
  } catch {}

  // Navigateur réel (Playwright)
  await ctx.progress(35, 'QA : tests en navigateur')
  await runBrowserQA(ctx, col)
}
