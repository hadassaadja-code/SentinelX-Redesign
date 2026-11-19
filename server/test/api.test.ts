// Tests d'intégration de l'API (17.2) : inscription, isolation entre organisations via HTTP, permissions,
// CSRF, autorisation d'audit obligatoire, quotas. Nécessite un serveur démarré (SENTINELX_URL, défaut http://localhost:3000).
import { describe, it, expect, beforeAll } from 'vitest'

const BASE = process.env.SENTINELX_URL || 'http://127.0.0.1:3000'
const up = await fetch(`${BASE}/api/health`).then((r) => r.ok).catch((e) => { console.warn('Serveur injoignable, tests API ignorés :', e?.cause?.message ?? e?.message); return false })

class Client {
  cookie = ''
  async call(path: string, opts: { method?: string; body?: any; csrf?: boolean } = {}) {
    const r = await fetch(`${BASE}/api${path}`, { method: opts.method ?? 'GET', headers: { 'content-type': 'application/json', ...(opts.csrf === false ? {} : { 'x-requested-with': 'sentinelx' }), cookie: this.cookie }, body: opts.body ? JSON.stringify(opts.body) : undefined })
    const sc = r.headers.get('set-cookie')
    if (sc) this.cookie = sc.split(';')[0]
    const data = await r.json().catch(() => null)
    return { status: r.status, data }
  }
}
const suffix = Date.now().toString(36)
const pw = 'Correct-Horse-Test-42'

describe.skipIf(!up)('API SentinelX', () => {
  const a = new Client(), b = new Client(), reader = new Client()
  let projA: string, appA: string
  beforeAll(async () => {
    expect((await a.call('/auth/register', { method: 'POST', body: { name: 'Alice', orgName: `Org A ${suffix}`, email: `alice-${suffix}@test.local`, password: pw } })).status).toBe(200)
    expect((await b.call('/auth/register', { method: 'POST', body: { name: 'Bob', orgName: `Org B ${suffix}`, email: `bob-${suffix}@test.local`, password: pw } })).status).toBe(200)
    projA = (await a.call('/projects', { method: 'POST', body: { name: 'Projet A' } })).data.id
    appA = (await a.call('/applications', { method: 'POST', body: { projectId: projA, name: 'App A', url: 'https://example.com/' } })).data.id
  })
  it('refuse les requêtes modifiantes sans en-tête anti-CSRF', async () => {
    expect((await a.call('/projects', { method: 'POST', body: { name: 'x' }, csrf: false })).status).toBe(403)
  })
  it('rejette un mot de passe faible et un e-mail invalide', async () => {
    expect((await new Client().call('/auth/register', { method: 'POST', body: { name: 'X', orgName: 'Y', email: `x-${suffix}@test.local`, password: 'password1234' } })).status).toBe(400)
    expect((await new Client().call('/auth/register', { method: 'POST', body: { name: 'X', orgName: 'Y', email: 'pas-un-email', password: pw } })).status).toBe(400)
  })
  it('isole les organisations : B ne voit ni ne modifie les données de A', async () => {
    expect((await b.call('/projects')).data.map((p: any) => p.id)).not.toContain(projA)
    expect((await b.call(`/projects/${projA}`, { method: 'PATCH', body: { name: 'piraté' } })).status).toBe(404)
    expect((await b.call(`/applications/${appA}`, { method: 'DELETE' })).status).toBe(404)
    expect((await b.call(`/applications/${appA}/authorize`, { method: 'POST', body: { declaration: true } })).status).toBe(404)
    expect((await b.call('/scans', { method: 'POST', body: { applicationId: appA, modules: ['QA'] } })).status).toBe(404)
    expect((await a.call('/projects')).data.find((p: any) => p.id === projA).name).toBe('Projet A')
  })
  it('interdit tout audit sans autorisation déclarée, puis l\'accepte', async () => {
    expect((await a.call('/scans', { method: 'POST', body: { applicationId: appA, modules: ['QA'] } })).status).toBe(403)
    expect((await a.call(`/applications/${appA}/authorize`, { method: 'POST', body: { declaration: false } })).status).toBe(400)
    expect((await a.call(`/applications/${appA}/authorize`, { method: 'POST', body: { declaration: true, scopes: ['PASSIVE'] } })).status).toBe(200)
  })
  it('refuse les cibles internes (SSRF) et le module API hors formule', async () => {
    expect((await a.call('/applications', { method: 'POST', body: { projectId: projA, name: 'Interne', url: 'http://127.0.0.1:3000/' } })).status).toBe(400)
    expect((await a.call('/applications', { method: 'POST', body: { projectId: projA, name: 'Interne', url: 'http://169.254.169.254/latest/meta-data' } })).status).toBe(400)
    expect((await a.call('/scans', { method: 'POST', body: { applicationId: appA, modules: ['API'] } })).status).toBe(402)
  })
  it('applique les quotas de la formule Starter (2 applications)', async () => {
    expect((await a.call('/applications', { method: 'POST', body: { projectId: projA, name: 'App 2', url: 'https://example.org/' } })).status).toBe(200)
    expect((await a.call('/applications', { method: 'POST', body: { projectId: projA, name: 'App 3', url: 'https://example.net/' } })).status).toBe(402)
  })
  it('applique les permissions par rôle (lecteur)', async () => {
    expect((await a.call('/members', { method: 'POST', body: { name: 'Lecteur', email: `reader-${suffix}@test.local`, password: pw, role: 'READER' } })).status).toBe(200)
    expect((await reader.call('/auth/login', { method: 'POST', body: { email: `reader-${suffix}@test.local`, password: pw } })).status).toBe(200)
    expect((await reader.call('/projects')).status).toBe(200)
    expect((await reader.call('/projects', { method: 'POST', body: { name: 'x' } })).status).toBe(403)
    expect((await reader.call('/scans', { method: 'POST', body: { applicationId: appA, modules: ['QA'] } })).status).toBe(403)
    expect((await reader.call('/members/invite', { method: 'POST', body: { email: 'z@test.local' } })).status).toBe(403)
    expect((await reader.call('/audit-logs')).status).toBe(403)
  })
  it('bloque le compte après 5 échecs de connexion', async () => {
    const c = new Client()
    for (let i = 0; i < 5; i++) await c.call('/auth/login', { method: 'POST', body: { email: `bob-${suffix}@test.local`, password: 'mauvais-mot-de-passe' } })
    expect((await c.call('/auth/login', { method: 'POST', body: { email: `bob-${suffix}@test.local`, password: pw } })).status).toBe(429)
  })
  it('refuse l\'accès Super Administrateur aux comptes ordinaires', async () => {
    expect((await a.call('/admin/overview')).status).toBe(403)
    expect((await a.call('/admin/organizations')).status).toBe(403)
  })
  it('ne divulgue pas l\'existence d\'un compte lors d\'un mot de passe oublié', async () => {
    const r1 = await new Client().call('/auth/forgot', { method: 'POST', body: { email: `alice-${suffix}@test.local` } })
    const r2 = await new Client().call('/auth/forgot', { method: 'POST', body: { email: `inconnu-${suffix}@test.local` } })
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
    expect(r2.data.devLinks).toBeUndefined()
  })
})
