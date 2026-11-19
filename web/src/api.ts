export async function api<T = any>(path: string, opts: { method?: string; body?: any } = {}): Promise<T> {
  const hasBody = opts.body !== undefined
  const res = await fetch('/api' + path, {
    method: opts.method ?? 'GET',
    credentials: 'same-origin',
    headers: { 'x-requested-with': 'sentinelx', ...(hasBody ? { 'content-type': 'application/json' } : {}) },
    body: hasBody ? JSON.stringify(opts.body) : undefined,
  })
  const data = await res.json().catch(() => null)
  if (!res.ok) {
    const e: any = new Error(data?.error ?? `Erreur ${res.status}`)
    e.status = res.status
    e.code = data?.code
    throw e
  }
  return data as T
}

export const ROLE_FR: Record<string, string> = { ADMIN: 'Administrateur', TECH_LEAD: 'Responsable technique', ANALYST: 'Auditeur / Analyste', READER: 'Lecteur' }
export const SEV_FR: Record<string, string> = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Info' }
export const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
export const SEV_VAR: Record<string, string> = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info' }
export const STATUS_FR: Record<string, string> = {
  DETECTED: 'Détectée', CONFIRMED: 'Confirmée', ASSIGNED: 'Assignée', IN_PROGRESS: 'En cours',
  FIXED: 'Corrigée', RETESTED: 'Retestée', CLOSED: 'Clôturée', FALSE_POSITIVE: 'Faux positif',
}
export const SCAN_FR: Record<string, string> = { QUEUED: 'En file', RUNNING: 'En cours', DONE: 'Terminé', FAILED: 'Échec', CANCELED: 'Annulé' }
export const MODULE_FR: Record<string, string> = { QA: 'QA', SECURITY: 'Sécurité', API: 'API', PERFORMANCE: 'Performance' }
export const ENV_FR: Record<string, string> = { DEVELOPMENT: 'Development', STAGING: 'Staging', PRODUCTION: 'Production' }
export const GROUP_FR: Record<string, string> = { STATIC: 'Contrôles statiques', BROWSER: 'Navigateur', ACCESSIBILITY: 'Accessibilité', FORMS: 'Formulaires', VISUAL: 'Comparaison visuelle', API: 'API', PERF: 'Performance', LOAD: 'Test de charge' }
export const METRIC_GROUP_FR: Record<string, string> = { SERVER: 'Mesures serveur', VITALS: 'Core Web Vitals', LOAD: 'Test de charge', RESOURCES: 'Ressources' }
export const INCIDENT_FR: Record<string, string> = { OPEN: 'Ouvert', ACKNOWLEDGED: 'Pris en charge', RESOLVED: 'Résolu' }
export const CATEGORY_FR: Record<string, string> = { TRANSPORT: 'Transport', TLS: 'TLS', HEADERS: 'En-têtes', COOKIES: 'Cookies', AUTH: 'Authentification', CSRF: 'CSRF', INJECTION: 'Injection', EXPOSURE: 'Exposition', DISCLOSURE: 'Divulgation', DNS: 'DNS', CORS: 'CORS', CONFIG: 'Configuration', REDIRECT: 'Redirection', SUPPLYCHAIN: 'Chaîne logicielle', DEPENDENCIES: 'Dépendances', CONTENT: 'Contenu', GOVERNANCE: 'Gouvernance', API: 'API', ACCESSIBILITY: 'Accessibilité', PERFORMANCE: 'Performance' }
export const fmt = (d: any) => (d ? new Date(d).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : '—')
export const fmtDate = (d: any) => (d ? new Date(d).toLocaleDateString('fr-FR') : '—')
export const ago = (d: any) => {
  if (!d) return '—'
  const s = Math.round((Date.now() - new Date(d).getTime()) / 1000)
  if (s < 60) return "à l'instant"
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`
  return `il y a ${Math.round(s / 86400)} j`
}
export const pct = (n: number | null | undefined) => (n == null ? '—' : `${n} %`)
