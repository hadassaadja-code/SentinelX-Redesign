// Couche HTTP des moteurs : protection SSRF (section 14.3), périmètre autorisé et budget de requêtes (section 14.4).
import { Agent, fetch as ufetch } from 'undici'
import dns from 'node:dns'
import net from 'node:net'
import { config } from '../config.js'

const ALLOW_PRIVATE = config.allowPrivateTargets
export const UA = 'SentinelX-Scanner/1.0 (+audit autorisé)'

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || // inclut les métadonnées cloud 169.254.169.254
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) ||
      (a === 198 && (b === 18 || b === 19))
    )
  }
  const v = ip.toLowerCase()
  if (v.startsWith('::ffff:')) {
    const m = v.slice(7)
    return net.isIPv4(m) ? isPrivateIp(m) : true
  }
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('ff') || v.startsWith('64:ff9b')
}

/** Résolution DNS contrôlée : l'adresse réellement utilisée pour la connexion est vérifiée (pas de contournement par DNS ni rebinding). */
export function guardedLookup(hostname: string, options: any, cb: any) {
  dns.lookup(hostname, options, (err: any, address: any, family: any) => {
    if (err) return cb(err, address, family)
    const list = Array.isArray(address) ? address.map((a: any) => a.address) : [address]
    if (!ALLOW_PRIVATE && list.some(isPrivateIp)) return cb(new Error('Destination interne bloquée (protection SSRF)'), address, family)
    cb(null, address, family)
  })
}
/** Version promesse pour les navigateurs (Playwright) : vrai si l'hôte résout vers une adresse autorisée. */
export async function hostAllowed(hostname: string): Promise<boolean> {
  if (ALLOW_PRIVATE) return true
  const h = hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(h)) return !isPrivateIp(h)
  if (isInternalName(h)) return false
  try {
    const addrs = await dns.promises.lookup(h, { all: true })
    return addrs.length > 0 && !addrs.some((a) => isPrivateIp(a.address))
  } catch {
    return false
  }
}
const isInternalName = (host: string) => host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')

export const agent = new Agent({ connect: { lookup: guardedLookup as any, timeout: 8000 }, headersTimeout: 15000, bodyTimeout: 15000 })

export function assertAllowedUrl(raw: string | URL): URL {
  let u: URL
  try {
    u = typeof raw === 'string' ? new URL(raw) : raw
  } catch {
    throw new Error('URL invalide')
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Seuls http et https sont autorisés')
  if (u.username || u.password) throw new Error("Les identifiants dans l'URL ne sont pas autorisés")
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (!ALLOW_PRIVATE) {
    if (net.isIP(host) && isPrivateIp(host)) throw new Error('Adresse interne bloquée (protection SSRF)')
    if (isInternalName(host)) throw new Error("Nom d'hôte interne bloqué (protection SSRF)")
  }
  return u
}

// ---------- Périmètre et budget d'une campagne ----------
export type ScanScope = {
  origin: string // ex: https://www.example.com
  allowed: string[] // préfixes de chemin autorisés (vide = tout)
  excluded: string[]
  maxRequests: number
  used: number
  headers: Record<string, string> // en-têtes additionnels (jeton de test, etc.)
  onRequest?: () => void
}
export function buildScope(app: { url: string; allowedPaths: string; excludedPaths: string; maxRequestsPerScan: number }, headers: Record<string, string> = {}): ScanScope {
  const u = new URL(app.url)
  const lines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)
  return { origin: u.origin, allowed: lines(app.allowedPaths), excluded: lines(app.excludedPaths), maxRequests: Math.max(20, app.maxRequestsPerScan || 300), used: 0, headers }
}
export class ScopeError extends Error {}
/** Vrai si l'URL est dans le périmètre déclaré (même origine, chemins autorisés, non exclue). */
export function inScope(scope: ScanScope, url: string | URL, sameOriginOnly = true): boolean {
  const u = typeof url === 'string' ? new URL(url) : url
  if (sameOriginOnly && u.origin !== scope.origin) return false
  if (scope.excluded.some((p) => u.pathname.startsWith(p))) return false
  if (scope.allowed.length && !scope.allowed.some((p) => u.pathname.startsWith(p))) return false
  return true
}
export function consume(scope: ScanScope, n = 1) {
  if (scope.used + n > scope.maxRequests) throw new ScopeError(`Budget de requêtes de la campagne atteint (${scope.maxRequests})`)
  scope.used += n
  scope.onRequest?.()
}

export type Fetched = { url: string; status: number; headers: Headers; body: string; bytes: number; ttfb: number; total: number; chain: string[]; redirected: boolean }
export type ReqOpts = {
  method?: string; headers?: Record<string, string>; body?: string; readBody?: boolean; maxRedirects?: number; maxBytes?: number; timeoutMs?: number
  scope?: ScanScope; sameOriginOnly?: boolean; noFollow?: boolean; // noFollow : renvoie la réponse de redirection sans la suivre // si scope : compte dans le budget et vérifie le périmètre (sauf ressources externes explicitement tolérées)
}

/** Requête HTTP sécurisée : redirections suivies manuellement et revalidées, délai et taille limités, budget décompté. */
export async function safeRequest(rawUrl: string, opts: ReqOpts = {}): Promise<Fetched> {
  const { readBody = true, maxRedirects = 5, maxBytes = 2_000_000, timeoutMs = 15000, method = 'GET' } = opts
  let url = assertAllowedUrl(rawUrl)
  if (opts.scope) {
    if (opts.sameOriginOnly !== false && !inScope(opts.scope, url)) throw new ScopeError(`Hors périmètre autorisé : ${url.pathname}`)
    consume(opts.scope)
  }
  const chain: string[] = []
  const t0 = performance.now()
  for (let i = 0; i <= maxRedirects; i++) {
    assertAllowedUrl(url)
    const sameOrigin = opts.scope ? url.origin === opts.scope.origin : true
    const res: any = await ufetch(url, {
      method,
      redirect: 'manual',
      dispatcher: agent,
      headers: { 'user-agent': UA, accept: '*/*', ...(sameOrigin ? opts.scope?.headers ?? {} : {}), ...(opts.headers ?? {}) },
      body: opts.body,
      signal: AbortSignal.timeout(timeoutMs),
    })
    const ttfb = performance.now() - t0
    const loc = res.headers.get('location')
    if ([301, 302, 303, 307, 308].includes(res.status) && loc && !opts.noFollow) {
      chain.push(`${res.status} ${url.href}`)
      await res.body?.cancel().catch(() => {})
      url = new URL(loc, url)
      if (opts.scope) consume(opts.scope)
      continue
    }
    let body = ''
    let bytes = 0
    if (readBody && res.body) {
      const reader = res.body.getReader()
      const chunks: Uint8Array[] = []
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        bytes += value.length
        if (bytes > maxBytes) {
          await reader.cancel().catch(() => {})
          break
        }
        chunks.push(value)
      }
      body = Buffer.concat(chunks).toString('utf8')
    } else {
      await res.body?.cancel().catch(() => {})
    }
    return { url: url.href, status: res.status, headers: res.headers, body, bytes, ttfb, total: performance.now() - t0, chain, redirected: chain.length > 0 }
  }
  throw new Error('Trop de redirections')
}
/** Compatibilité : GET simple. */
export const safeFetch = (url: string, opts: ReqOpts = {}) => safeRequest(url, opts)

export const errMsg = (e: any) => String(e?.cause?.message ?? e?.message ?? e).slice(0, 200)
export const cut = (s: string, n = 300) => (s.length > n ? s.slice(0, n) + '…' : s)
