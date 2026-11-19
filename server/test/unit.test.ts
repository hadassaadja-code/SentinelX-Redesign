// Tests unitaires (17.1) : fonctions métier, validations, permissions, règles de sécurité des moteurs.
import { describe, it, expect } from 'vitest'
import { isPrivateIp, assertAllowedUrl, buildScope, inScope, consume } from '../src/scanners/http.js'
import { analyzeCsp } from '../src/scanners/security.js'
import { analyzeSpec, parseSpec } from '../src/scanners/api.js'
import { perfScore } from '../src/scanners/perf.js'
import { encrypt, decrypt, passwordProblems, totpCode, verifyTotp, generateTotpSecret, base32Decode, base32Encode, rateLimit, sha256 } from '../src/security.js'
import { roleCan, permissionsOf, PERMISSIONS } from '../src/core.js'

describe('protection SSRF', () => {
  it('bloque les adresses privées, de boucle locale et de métadonnées cloud', () => {
    for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.3.4', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.1.1', '::1', 'fc00::1', 'fe80::1', '::ffff:10.0.0.1']) expect(isPrivateIp(ip), ip).toBe(true)
    for (const ip of ['8.8.8.8', '93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946', '172.32.0.1']) expect(isPrivateIp(ip), ip).toBe(false)
  })
  it('refuse les URL non http(s), avec identifiants ou vers des hôtes internes', () => {
    expect(() => assertAllowedUrl('ftp://exemple.com')).toThrow()
    expect(() => assertAllowedUrl('https://user:pw@exemple.com')).toThrow()
    expect(() => assertAllowedUrl('http://localhost:3000')).toThrow()
    expect(() => assertAllowedUrl('http://127.0.0.1')).toThrow()
    expect(() => assertAllowedUrl('http://service.internal')).toThrow()
    expect(assertAllowedUrl('https://exemple.com/page').hostname).toBe('exemple.com')
  })
})

describe('périmètre et budget de campagne', () => {
  const scope = buildScope({ url: 'https://exemple.com/app', allowedPaths: '/app\n/api', excludedPaths: '/app/admin', maxRequestsPerScan: 25 })
  it('respecte les chemins autorisés et exclus, même origine uniquement', () => {
    expect(inScope(scope, 'https://exemple.com/app/page')).toBe(true)
    expect(inScope(scope, 'https://exemple.com/api/v1')).toBe(true)
    expect(inScope(scope, 'https://exemple.com/app/admin/users')).toBe(false)
    expect(inScope(scope, 'https://exemple.com/autre')).toBe(false)
    expect(inScope(scope, 'https://autre.com/app')).toBe(false)
  })
  it('décompte le budget et refuse au-delà', () => {
    for (let i = 0; i < 25; i++) consume(scope)
    expect(() => consume(scope)).toThrow(/Budget/)
  })
})

describe('analyse CSP', () => {
  it('signale unsafe-inline, unsafe-eval et directives absentes', () => {
    const issues = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *")
    expect(issues.join(' ')).toMatch(/unsafe-inline/)
    expect(issues.join(' ')).toMatch(/unsafe-eval/)
    expect(issues.join(' ')).toMatch(/toute origine/)
    expect(issues.join(' ')).toMatch(/frame-ancestors/)
  })
  it('accepte une politique stricte', () => {
    expect(analyzeCsp("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")).toEqual([])
  })
})

describe('analyse OpenAPI (OWASP API Top 10)', () => {
  const spec = parseSpec(`
openapi: 3.0.0
info: { title: Demo }
servers: [{ url: http://api.demo.test }]
components:
  securitySchemes:
    key: { type: apiKey, in: query, name: api_key }
paths:
  /users/{id}:
    get:
      security: [{ key: [] }]
      responses: { '200': { content: { application/json: { schema: { type: object, properties: { password: { type: string } } } } } } }
    delete:
      responses: { '204': {} }
  /users:
    post:
      requestBody: { content: { application/json: { schema: { type: object, properties: { name: { type: string }, isAdmin: { type: boolean } } } } } }
      responses: { '201': {} }
`)
  const { ops, findings } = analyzeSpec(spec, 'http://api.demo.test')
  const titles = findings.map((f) => f.title).join(' | ')
  it('cartographie les opérations', () => expect(ops.length).toBe(3))
  it('détecte le serveur HTTP, la clé en query, les opérations non protégées, le mass assignment et les données sensibles', () => {
    expect(titles).toMatch(/Serveur API déclaré en HTTP/)
    expect(titles).toMatch(/Clé API transmise dans l'URL/)
    expect(titles).toMatch(/sans exigence d'authentification/)
    expect(findings.find((f) => /sans exigence/.test(f.title))?.severity).toBe('HIGH')
    expect(titles).toMatch(/mass assignment/)
    expect(titles).toMatch(/Données sensibles dans les réponses/)
    expect(titles).toMatch(/identifiant d'objet/)
    expect(findings.every((f) => f.owasp.startsWith('API'))).toBe(true)
  })
})

describe('score de performance', () => {
  it('décroît avec la latence et les erreurs', () => {
    expect(perfScore(100, 0, 150)).toBe(100)
    expect(perfScore(1500, 0, 2000)).toBeLessThan(60)
    expect(perfScore(200, 0.5, 300)).toBe(75)
    expect(perfScore(5000, 1, 9000)).toBe(0)
  })
})

describe('primitives de sécurité', () => {
  it('chiffre et déchiffre (AES-256-GCM) et détecte toute altération', () => {
    const blob = encrypt('secret TOTP')
    expect(decrypt(blob)).toBe('secret TOTP')
    const [v, iv, tag, data] = blob.split('.')
    expect(() => decrypt(`${v}.${iv}.${tag}.${data.slice(0, -2)}xx`)).toThrow()
  })
  it('applique la politique de mots de passe', () => {
    expect(passwordProblems('court')).toMatch(/10 caractères/)
    expect(passwordProblems('password1234')).toMatch(/courant|deux types/)
    expect(passwordProblems('aaaaaaaaaaaa')).toBeTruthy()
    expect(passwordProblems('jeandupont2024!', ['Jean Dupont', 'jeandupont'])).toMatch(/nom/)
    expect(passwordProblems('Correct-Horse-42')).toBeNull()
  })
  it('génère et vérifie des codes TOTP (RFC 6238)', () => {
    // Vecteur de test RFC 6238 (SHA-1, secret "12345678901234567890") : T=59 s → 94287082
    const secret = base32Encode(Buffer.from('12345678901234567890'))
    expect(totpCode(secret, Math.floor(59 / 30))).toBe('287082')
    expect(totpCode(secret, Math.floor(1111111109 / 30))).toBe('081804')
    const s = generateTotpSecret()
    expect(base32Decode(s).length).toBe(20)
    expect(verifyTotp(s, totpCode(s))).toBe(true)
    expect(verifyTotp(s, '000000')).toBe(false)
    expect(verifyTotp(s, 'abc')).toBe(false)
  })
  it('limite le débit par fenêtre glissante', () => {
    const key = `t-${sha256(String(Math.random()))}`
    for (let i = 0; i < 3; i++) expect(rateLimit(key, 3, 1000).ok).toBe(true)
    expect(rateLimit(key, 3, 1000).ok).toBe(false)
  })
})

describe('matrice de permissions (2.3)', () => {
  it('respecte la hiérarchie des rôles', () => {
    expect(roleCan('READER', 'scan.read')).toBe(true)
    expect(roleCan('READER', 'scan.run')).toBe(false)
    expect(roleCan('ANALYST', 'scan.run')).toBe(true)
    expect(roleCan('ANALYST', 'scan.load')).toBe(false)
    expect(roleCan('TECH_LEAD', 'scan.load')).toBe(true)
    expect(roleCan('TECH_LEAD', 'member.manage')).toBe(false)
    expect(roleCan('ADMIN', 'member.manage')).toBe(true)
    expect(permissionsOf('ADMIN').length).toBe(Object.keys(PERMISSIONS).length)
    expect(permissionsOf('READER').every((p) => p.endsWith('.read') || p.endsWith('.download'))).toBe(true)
  })
})
