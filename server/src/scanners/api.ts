// Module API Security Testing (section 7) : analyse d'une spécification OpenAPI et contrôles dynamiques non destructifs,
// cartographiés sur l'OWASP API Security Top 10 (2023).
import YAML from 'yaml'
import { cut, errMsg, safeRequest } from './http.js'
import { Collector, type ScanContext, type Severity } from './types.js'

const DISCOVERY = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/v2/api-docs', '/api-docs', '/swagger/v1/swagger.json', '/.well-known/openapi.json', '/api/openapi.json', '/openapi.yaml', '/api/swagger.json', '/docs/openapi.json']
const UI_PATHS = ['/swagger-ui.html', '/swagger-ui/', '/docs', '/redoc', '/api/docs', '/swagger']
const SENSITIVE = /^(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?token|refresh[_-]?token|ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cvv|iban|private[_-]?key)$/i
const PRIVILEGED = /^(role|roles|is[_-]?admin|admin|is[_-]?staff|permissions|balance|price|credit|verified|is[_-]?verified|owner[_-]?id|user[_-]?id|tenant[_-]?id|org[_-]?id)$/i
const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

type Op = { method: string; path: string; op: any; secured: boolean; schemes: string[] }

export function parseSpec(text: string): any {
  const t = text.trim()
  if (t.startsWith('{')) return JSON.parse(t)
  return YAML.parse(t)
}

/** Résout une référence locale "#/components/schemas/X". */
function resolve(spec: any, obj: any, depth = 0): any {
  if (!obj || typeof obj !== 'object' || depth > 6) return obj
  if (obj.$ref && typeof obj.$ref === 'string' && obj.$ref.startsWith('#/')) {
    const target = obj.$ref.slice(2).split('/').reduce((a: any, k: string) => a?.[k.replace(/~1/g, '/').replace(/~0/g, '~')], spec)
    return resolve(spec, target, depth + 1)
  }
  return obj
}

function walkSchema(spec: any, schema: any, fn: (name: string, s: any, path: string) => void, path = '', seen = new Set<any>(), depth = 0) {
  const s = resolve(spec, schema)
  if (!s || typeof s !== 'object' || seen.has(s) || depth > 8) return
  seen.add(s)
  for (const k of ['allOf', 'oneOf', 'anyOf']) if (Array.isArray(s[k])) s[k].forEach((x: any) => walkSchema(spec, x, fn, path, seen, depth + 1))
  if (s.properties) for (const [name, p] of Object.entries<any>(s.properties)) {
    fn(name, resolve(spec, p), `${path}.${name}`)
    walkSchema(spec, p, fn, `${path}.${name}`, seen, depth + 1)
  }
  if (s.items) walkSchema(spec, s.items, fn, `${path}[]`, seen, depth + 1)
}

export function analyzeSpec(spec: any, baseUrl: string): { ops: Op[]; findings: Array<Parameters<Collector['add']>[0]>; info: any } {
  const findings: Array<Parameters<Collector['add']>[0]> = []
  const add = (severity: Severity, title: string, description: string, resource: string, evidence: string, recommendation: string, owasp: string, cwe = '') =>
    findings.push({ severity, title, description, resource, evidence: cut(evidence, 600), recommendation, category: 'API', cwe, owasp })
  const isV3 = !!spec.openapi
  const schemes: Record<string, any> = (isV3 ? spec.components?.securitySchemes : spec.securityDefinitions) ?? {}
  const globalSec: any[] = Array.isArray(spec.security) ? spec.security : []
  const paths: Record<string, any> = spec.paths ?? {}
  const ops: Op[] = []
  for (const [p, item] of Object.entries<any>(paths)) {
    if (!item || typeof item !== 'object') continue
    for (const m of METHODS) {
      const op = item[m]
      if (!op || typeof op !== 'object') continue
      const sec = Array.isArray(op.security) ? op.security : globalSec
      const secured = sec.some((s: any) => s && Object.keys(s).length > 0)
      ops.push({ method: m.toUpperCase(), path: p, op, secured, schemes: sec.flatMap((s: any) => Object.keys(s ?? {})) })
    }
  }
  const info: any = { title: spec.info?.title, version: spec.info?.version, operations: ops.length, secured: ops.filter((o) => o.secured).length, schemes: Object.keys(schemes) }
  const servers: string[] = isV3 ? (spec.servers ?? []).map((s: any) => s.url) : (spec.schemes ?? []).map((s: string) => `${s}://${spec.host ?? ''}${spec.basePath ?? ''}`)
  info.servers = servers

  // --- Configuration (API8) ---
  if (servers.some((s) => /^http:\/\//i.test(s))) add('MEDIUM', 'Serveur API déclaré en HTTP', 'La spécification référence un serveur non chiffré.', baseUrl, `servers : ${servers.join(', ')}`, 'Ne déclarer que des serveurs HTTPS.', 'API8:2023', 'CWE-319')
  if (!spec.info?.version) add('INFO', 'Version d\'API non renseignée', 'Le champ info.version est absent : la gestion des versions et de la dépréciation n\'est pas documentée.', baseUrl, 'info.version absent', 'Renseigner la version et documenter la politique de dépréciation.', 'API9:2023')
  // --- Authentification (API2) ---
  if (!Object.keys(schemes).length) add('HIGH', 'Aucun schéma d\'authentification déclaré', 'La spécification ne définit aucun securityScheme : soit l\'API est entièrement publique, soit son authentification n\'est pas documentée.', baseUrl, `${ops.length} opération(s), 0 securityScheme`, 'Déclarer les schémas (bearer JWT, OAuth2, clé API) et les appliquer aux opérations.', 'API2:2023', 'CWE-306')
  for (const [name, s] of Object.entries<any>(schemes)) {
    if (s.type === 'apiKey' && s.in === 'query') add('MEDIUM', `Clé API transmise dans l'URL (${name})`, 'Les clés en paramètre de requête sont journalisées par les proxys, navigateurs et serveurs.', baseUrl, `securityScheme ${name} : apiKey in query (${s.name})`, 'Transmettre la clé dans un en-tête HTTP.', 'API2:2023', 'CWE-598')
    if (s.type === 'http' && s.scheme === 'basic') add('LOW', `Authentification HTTP Basic (${name})`, 'Les identifiants sont transmis à chaque requête (base64) : acceptable uniquement en HTTPS, sans rotation possible.', baseUrl, `securityScheme ${name} : http basic`, 'Préférer des jetons à durée limitée (bearer) ou OAuth2.', 'API2:2023', 'CWE-522')
    if (s.type === 'oauth2' && s.flows?.implicit) add('LOW', `Flux OAuth2 implicite (${name})`, 'Le flux implicite est déconseillé (jetons exposés dans l\'URL).', baseUrl, `flows.implicit présent`, 'Utiliser Authorization Code avec PKCE.', 'API2:2023', 'CWE-598')
    if (s.type === 'oauth2' && s.flows?.password) add('INFO', `Flux OAuth2 password (${name})`, 'Le flux « password » est déprécié par l\'OAuth 2.1.', baseUrl, `flows.password présent`, 'Migrer vers Authorization Code + PKCE.', 'API2:2023')
  }
  const unsecured = ops.filter((o) => !o.secured)
  const unsecuredMut = unsecured.filter((o) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(o.method))
  if (Object.keys(schemes).length && unsecured.length) {
    add(unsecuredMut.length ? 'HIGH' : 'MEDIUM', `${unsecured.length} opération(s) sans exigence d'authentification`, `Des opérations ne déclarent aucun schéma de sécurité${unsecuredMut.length ? `, dont ${unsecuredMut.length} modifiante(s)` : ''}. Si ce n'est pas volontaire, il s'agit d'un défaut d'authentification ou d'autorisation de fonction.`, baseUrl, unsecured.slice(0, 12).map((o) => `${o.method} ${o.path}`).join('\n'), 'Appliquer une exigence de sécurité globale (security au niveau racine) et ne lister explicitement que les opérations réellement publiques.', unsecuredMut.length ? 'API5:2023' : 'API2:2023', 'CWE-306')
  }
  // --- Autorisation objet (API1) : identifiants en chemin ---
  const idOps = ops.filter((o) => /\{[^}]*(id|uuid|key|number)[^}]*\}/i.test(o.path))
  if (idOps.length) add('INFO', `${idOps.length} opération(s) manipulant un identifiant d'objet`, 'Ces opérations sont les candidates classiques aux failles d\'autorisation au niveau objet (BOLA/IDOR). Chaque accès doit vérifier que l\'objet appartient bien à l\'appelant.', baseUrl, idOps.slice(0, 10).map((o) => `${o.method} ${o.path}${o.secured ? '' : ' (non authentifié)'}`).join('\n'), 'Vérifier systématiquement la propriété de l\'objet côté serveur ; tester avec deux comptes de test (voir contrôles dynamiques).', 'API1:2023', 'CWE-639')
  // --- Propriétés d'objet (API3) ---
  const sensitiveOut: string[] = [], privilegedIn: string[] = [], unbounded: string[] = []
  for (const o of ops) {
    const responses = o.op.responses ?? {}
    for (const [code, r] of Object.entries<any>(responses)) {
      const rr = resolve(spec, r)
      const content = isV3 ? rr?.content : { 'application/json': { schema: rr?.schema } }
      for (const [, mt] of Object.entries<any>(content ?? {})) walkSchema(spec, mt?.schema, (name) => { if (SENSITIVE.test(name) && sensitiveOut.length < 20) sensitiveOut.push(`${o.method} ${o.path} → ${code} : ${name}`) })
    }
    const body = isV3 ? resolve(spec, o.op.requestBody)?.content : { 'application/json': { schema: (o.op.parameters ?? []).find((p: any) => p.in === 'body')?.schema } }
    for (const [, mt] of Object.entries<any>(body ?? {})) {
      walkSchema(spec, mt?.schema, (name, s) => {
        if (PRIVILEGED.test(name) && !s.readOnly && privilegedIn.length < 20) privilegedIn.push(`${o.method} ${o.path} : ${name}`)
        if (s.type === 'string' && !s.maxLength && !s.enum && !s.format && !s.pattern && unbounded.length < 30) unbounded.push(`${o.method} ${o.path} : ${name} (string sans maxLength)`)
        if (s.type === 'array' && !s.maxItems && unbounded.length < 30) unbounded.push(`${o.method} ${o.path} : ${name} (array sans maxItems)`)
      })
      const sch = resolve(spec, mt?.schema)
      if (sch && sch.type === 'object' && sch.additionalProperties !== false && !sch.properties) unbounded.push(`${o.method} ${o.path} : objet libre (additionalProperties)`)
    }
    for (const p of (o.op.parameters ?? []).map((x: any) => resolve(spec, x))) {
      const s = p?.schema ?? p
      if (!p || p.in === 'body') continue
      if (s?.type === 'string' && !s.maxLength && !s.enum && !s.pattern && !s.format && unbounded.length < 30) unbounded.push(`${o.method} ${o.path} : paramètre ${p.name} (string sans contrainte)`)
      if (s?.type === 'integer' && /limit|size|per_page|count/i.test(p.name) && s.maximum == null) unbounded.push(`${o.method} ${o.path} : paramètre ${p.name} sans maximum (pagination)`)
    }
    if (o.op.deprecated) info.deprecated = (info.deprecated ?? 0) + 1
  }
  if (sensitiveOut.length) add('MEDIUM', 'Données sensibles dans les réponses documentées', 'Des schémas de réponse exposent des propriétés sensibles (mots de passe, jetons, données bancaires…).', baseUrl, sensitiveOut.slice(0, 10).join('\n'), 'Retirer ces propriétés des réponses ou les marquer writeOnly ; filtrer côté serveur.', 'API3:2023', 'CWE-213')
  if (privilegedIn.length) add('MEDIUM', 'Propriétés privilégiées acceptées en entrée (mass assignment)', 'Des corps de requête acceptent des champs comme role, isAdmin, balance ou ownerId : un client pourrait les modifier directement.', baseUrl, privilegedIn.slice(0, 10).join('\n'), 'Marquer ces propriétés readOnly, utiliser des DTO d\'entrée stricts et ignorer les champs non autorisés.', 'API3:2023', 'CWE-915')
  if (unbounded.length) add('LOW', 'Entrées sans limite de taille ou de volume', `${unbounded.length} paramètre(s) ou propriété(s) sans contrainte (maxLength, maxItems, maximum) : risque de consommation de ressources excessive.`, baseUrl, unbounded.slice(0, 10).join('\n'), 'Déclarer et appliquer des bornes sur chaque entrée (taille des chaînes, taille des tableaux, pagination).', 'API4:2023', 'CWE-770')
  // --- Réponses d'erreur et limitation documentées ---
  const no401 = ops.filter((o) => o.secured && !o.op.responses?.['401'] && !o.op.responses?.['403']).length
  if (no401) add('INFO', `${no401} opération(s) sécurisée(s) sans réponse 401/403 documentée`, 'Les refus d\'authentification/autorisation ne sont pas documentés.', baseUrl, `${no401} opération(s)`, 'Documenter les réponses 401 et 403.', 'API8:2023')
  if (!ops.some((o) => o.op.responses?.['429'])) add('INFO', 'Limitation de débit non documentée (aucune réponse 429)', 'Aucune opération ne documente de réponse 429 : la protection contre la consommation excessive n\'est pas visible.', baseUrl, `0 réponse 429 sur ${ops.length} opérations`, 'Mettre en place une limitation de débit et la documenter (429 + en-têtes RateLimit).', 'API4:2023', 'CWE-770')
  if (info.deprecated) add('INFO', `${info.deprecated} opération(s) dépréciée(s) encore exposée(s)`, 'Les opérations dépréciées restent des surfaces d\'attaque souvent moins maintenues.', baseUrl, `${info.deprecated} opération(s) marquée(s) deprecated`, 'Planifier le retrait des opérations dépréciées.', 'API9:2023', 'CWE-1104')
  const uploads = ops.filter((o) => JSON.stringify(o.op.requestBody ?? '').includes('multipart/form-data') || JSON.stringify(o.op.requestBody ?? '').includes('"format":"binary"'))
  if (uploads.length) add('INFO', `${uploads.length} opération(s) de téléversement de fichier`, 'Les téléversements doivent être limités en taille, type et contenu.', baseUrl, uploads.slice(0, 5).map((o) => `${o.method} ${o.path}`).join('\n'), 'Limiter la taille, valider le type réel du fichier et le stocker hors de la racine web.', 'API4:2023', 'CWE-434')
  return { ops, findings, info }
}

export async function runApi(ctx: ScanContext, col: Collector): Promise<void> {
  const app = ctx.app
  const get = (url: string, o: any = {}) => safeRequest(url, { scope: ctx.scope, ...o })
  const base = new URL(app.url)
  const root = `${base.protocol}//${base.host}`
  await ctx.progress(5, 'API : récupération de la spécification')

  // 1. Spécification : URL déclarée ou découverte
  let spec: any = null, specUrl = ''
  const candidates = app.openapiUrl ? [app.openapiUrl] : DISCOVERY.flatMap((p) => [`${app.url.replace(/\/$/, '')}${p}`, `${root}${p}`])
  for (const c of [...new Set(candidates)]) {
    if (await ctx.cancelled()) return
    try {
      const r = await safeRequest(c, { scope: ctx.scope, sameOriginOnly: false, maxBytes: 5_000_000 })
      if (r.status !== 200) continue
      const parsed = parseSpec(r.body)
      if (parsed && (parsed.openapi || parsed.swagger) && parsed.paths) {
        spec = parsed
        specUrl = c
        break
      }
    } catch {}
  }
  if (!app.openapiUrl && spec) {
    col.add({ severity: 'INFO', title: 'Spécification OpenAPI accessible publiquement', description: 'La documentation de l\'API a été découverte sans authentification. Elle facilite la cartographie de la surface d\'attaque.', resource: specUrl, evidence: `HTTP 200 — ${spec.info?.title ?? ''} ${spec.info?.version ?? ''}`, recommendation: 'Restreindre l\'accès à la documentation si l\'API n\'est pas publique.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-200' })
  }
  for (const p of UI_PATHS) {
    try {
      const r = await get(`${root}${p}`, { maxBytes: 50000 })
      if (r.status === 200 && /swagger-ui|redoc|SwaggerUIBundle/i.test(r.body)) {
        col.add({ severity: 'INFO', title: 'Interface de documentation interactive exposée', description: 'Une interface Swagger UI / Redoc est accessible publiquement.', resource: `${root}${p}`, evidence: 'HTTP 200 — Swagger UI / Redoc détecté', recommendation: 'Désactiver ou protéger l\'interface en production.', category: 'API', owasp: 'API8:2023' })
        break
      }
    } catch {}
  }
  if (!spec) {
    col.test('API', 'Spécification OpenAPI trouvée', false, app.openapiUrl ? `La spécification déclarée (${app.openapiUrl}) n'a pas pu être chargée ou n'est pas valide.` : 'Aucune spécification OpenAPI découverte. Renseignez son URL dans la fiche application pour une analyse complète.')
    await genericApiChecks(ctx, col, app.url)
    return
  }
  col.test('API', 'Spécification OpenAPI chargée', true, `${specUrl} — ${spec.info?.title ?? ''} ${spec.info?.version ?? ''} (${spec.openapi ?? 'swagger ' + spec.swagger})`)

  // 2. Analyse statique
  await ctx.progress(20, 'API : analyse de la spécification')
  const { ops, findings, info } = analyzeSpec(spec, app.url)
  findings.forEach((f) => col.add(f))
  col.info.api = { ...info, specUrl }
  col.test('API', 'Opérations documentées', ops.length > 0, `${ops.length} opération(s), ${info.secured} avec exigence d'authentification`)
  col.test('API', 'Schémas d\'authentification déclarés', info.schemes.length > 0, info.schemes.length ? info.schemes.join(', ') : 'Aucun securityScheme')

  // 3. Contrôles dynamiques non destructifs (GET uniquement, sans identifiants)
  await ctx.progress(40, 'API : contrôles dynamiques')
  const serverUrl = (() => {
    const s = info.servers?.[0]
    try {
      return s ? new URL(s, app.url).href.replace(/\/$/, '') : app.url.replace(/\/$/, '')
    } catch {
      return app.url.replace(/\/$/, '')
    }
  })()
  const gets = ops.filter((o) => o.method === 'GET' && !/\{/.test(o.path) && !(o.op.parameters ?? []).some((p: any) => p.required && p.in !== 'header')).slice(0, ctx.profile === 'DEEP' ? 25 : 12)
  const authNotEnforced: string[] = [], leaks: string[] = [], serverErrors: string[] = []
  let rateHeaders = false, checked = 0
  for (const o of gets) {
    if (await ctx.cancelled()) return
    const url = `${serverUrl}${o.path}`
    try {
      const r = await safeRequest(url, { scope: ctx.scope, sameOriginOnly: false, maxBytes: 300000, headers: { accept: 'application/json' } })
      checked++
      if (['x-ratelimit-limit', 'ratelimit-limit', 'x-rate-limit-limit', 'retry-after'].some((h) => r.headers.get(h))) rateHeaders = true
      const declared = Object.keys(o.op.responses ?? {})
      col.test('API', `GET ${o.path} sans identifiants`, r.status < 500, `HTTP ${r.status}${declared.length ? ` (documenté : ${declared.join(', ')})` : ''}${o.secured ? ' — opération protégée' : ''}`, r.total)
      if (o.secured && r.status >= 200 && r.status < 300 && r.body.trim().length > 2) authNotEnforced.push(`GET ${o.path} → HTTP ${r.status} (${r.bytes} octets)`)
      if (r.status >= 500) serverErrors.push(`GET ${o.path} → HTTP ${r.status}`)
      if (r.status < 300 && /json/i.test(r.headers.get('content-type') ?? '')) {
        const keys = [...r.body.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s*:/g)].map((m) => m[1]).filter((k) => SENSITIVE.test(k))
        if (keys.length) leaks.push(`GET ${o.path} : ${[...new Set(keys)].join(', ')}`)
      }
    } catch (e) {
      col.test('API', `GET ${o.path}`, false, errMsg(e))
    }
  }
  if (authNotEnforced.length) col.add({ severity: 'HIGH', title: 'Authentification non appliquée sur des opérations protégées', description: 'Des opérations déclarées comme sécurisées répondent avec succès sans aucun identifiant.', resource: serverUrl, evidence: authNotEnforced.join('\n'), recommendation: 'Appliquer la vérification d\'authentification côté serveur sur chaque opération (middleware global), pas seulement dans la documentation.', category: 'API', owasp: 'API2:2023', cwe: 'CWE-306' })
  if (leaks.length) col.add({ severity: 'HIGH', title: 'Données sensibles renvoyées sans authentification', description: 'Des réponses publiques contiennent des champs sensibles (mot de passe, jeton, clé…).', resource: serverUrl, evidence: leaks.join('\n'), recommendation: 'Filtrer les propriétés renvoyées et protéger les opérations concernées.', category: 'API', owasp: 'API3:2023', cwe: 'CWE-200' })
  if (serverErrors.length) col.add({ severity: 'LOW', title: 'Erreurs serveur sur des appels simples', description: 'Des opérations GET renvoient une erreur 5xx sans paramètre particulier.', resource: serverUrl, evidence: serverErrors.join('\n'), recommendation: 'Corriger les erreurs et renvoyer des codes 4xx explicites pour les requêtes invalides.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-755' })
  if (checked && !rateHeaders) col.add({ severity: 'INFO', title: 'Aucun en-tête de limitation de débit observé', description: 'Les réponses n\'exposent pas d\'en-têtes RateLimit/X-RateLimit : la limitation est absente ou invisible.', resource: serverUrl, evidence: `${checked} réponse(s) analysée(s) sans en-tête RateLimit-*`, recommendation: 'Mettre en place une limitation de débit par client et exposer les en-têtes standard.', category: 'API', owasp: 'API4:2023', cwe: 'CWE-770' })

  // Limitation de débit : rafale courte (mode actif uniquement, lecture seule)
  if (ctx.active && gets.length) {
    await ctx.progress(60, 'API : test de limitation de débit')
    const target = `${serverUrl}${gets.find((g) => !g.secured)?.path ?? gets[0].path}`
    let got429 = false, n = 0
    const t0 = performance.now()
    await Promise.all(Array.from({ length: 4 }, async () => {
      for (let i = 0; i < 10 && !got429; i++) {
        try {
          const r = await safeRequest(target, { scope: ctx.scope, sameOriginOnly: false, readBody: false })
          n++
          if (r.status === 429) got429 = true
        } catch {
          break
        }
      }
    }))
    col.test('API', 'Limitation de débit (rafale de 40 requêtes)', got429 ? true : 'SKIP', got429 ? `HTTP 429 reçu après ${n} requêtes en ${Math.round(performance.now() - t0)} ms` : `${n} requêtes en ${Math.round(performance.now() - t0)} ms sans HTTP 429 : aucune limitation observée à ce volume (non concluant)`)
    if (!got429 && n >= 30) col.add({ severity: 'LOW', title: 'Aucune limitation de débit observée (40 requêtes)', description: 'Une rafale modérée n\'a déclenché aucune réponse 429. Des rafales plus importantes n\'ont pas été testées (limite volontaire).', resource: target, evidence: `${n} requêtes GET en ${Math.round(performance.now() - t0)} ms, aucun 429`, recommendation: 'Limiter le nombre de requêtes par client (IP, clé, compte) et renvoyer 429.', category: 'API', owasp: 'API4:2023', cwe: 'CWE-770' })
  }
  await genericApiChecks(ctx, col, serverUrl)
}

/** Contrôles génériques d'une API : en-têtes, erreurs, CORS, méthodes. */
async function genericApiChecks(ctx: ScanContext, col: Collector, serverUrl: string) {
  await ctx.progress(75, 'API : configuration générale')
  try {
    const r = await safeRequest(serverUrl, { scope: ctx.scope, sameOriginOnly: false, maxBytes: 100000, headers: { accept: 'application/json', origin: 'https://sentinelx-check.invalid' } })
    const h = r.headers
    if (!h.get('x-content-type-options')) col.add({ severity: 'LOW', title: 'API sans X-Content-Type-Options', description: 'Les réponses JSON peuvent être interprétées différemment par certains navigateurs.', resource: serverUrl, evidence: 'En-tête absent', recommendation: 'Ajouter X-Content-Type-Options: nosniff.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-16' })
    if (new URL(serverUrl).protocol === 'https:' && !h.get('strict-transport-security')) col.add({ severity: 'LOW', title: 'API sans HSTS', description: 'L\'API ne force pas HTTPS côté client.', resource: serverUrl, evidence: 'Strict-Transport-Security absent', recommendation: 'Ajouter l\'en-tête HSTS.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-319' })
    const acao = h.get('access-control-allow-origin')
    if (acao === 'https://sentinelx-check.invalid') col.add({ severity: h.get('access-control-allow-credentials') === 'true' ? 'HIGH' : 'MEDIUM', title: 'CORS : origine arbitraire reflétée par l\'API', description: 'Un site tiers peut appeler l\'API depuis le navigateur d\'un utilisateur.', resource: serverUrl, evidence: `Origin arbitraire → Access-Control-Allow-Origin: ${acao}`, recommendation: 'Valider l\'origine contre une liste blanche.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-942' })
    const trace = [/Traceback \(most recent call last\)/, /at [\w.$]+\([\w]+\.java:\d+\)/, /Stack trace:/, /System\.\w+Exception/].find((re) => re.test(r.body))
    if (trace) col.add({ severity: 'MEDIUM', title: 'Trace technique dans une réponse API', description: 'La réponse contient une trace de pile.', resource: serverUrl, evidence: cut(r.body.match(trace)?.[0] ?? '', 160), recommendation: 'Renvoyer des erreurs structurées sans détails internes.', category: 'API', owasp: 'API8:2023', cwe: 'CWE-209' })
    const rid = `${serverUrl}/sx-inexistant-${Date.now()}`
    const nf = await safeRequest(rid, { scope: ctx.scope, sameOriginOnly: false, maxBytes: 100000, headers: { accept: 'application/json' } })
    col.test('API', 'Ressource inexistante → 404 structuré', nf.status === 404, `HTTP ${nf.status}${/json/i.test(nf.headers.get('content-type') ?? '') ? ' (JSON)' : ''}`)
  } catch (e) {
    col.test('API', 'Serveur API joignable', false, errMsg(e))
  }
}
