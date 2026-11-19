// Primitives de sécurité de la plateforme : chiffrement, jetons, TOTP, limitation de débit, politique de mots de passe.
import crypto from 'node:crypto'
import { config } from './config.js'

// ---------- Chiffrement symétrique (secrets TOTP, en-têtes d'audit) : AES-256-GCM ----------
const KEY = crypto.createHash('sha256').update(config.encryptionKey).digest()
export function encrypt(plain: string): string {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv)
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()])
  return `v1.${iv.toString('base64url')}.${c.getAuthTag().toString('base64url')}.${enc.toString('base64url')}`
}
export function decrypt(blob: string): string {
  const [v, iv, tag, data] = blob.split('.')
  if (v !== 'v1') throw new Error('Format chiffré inconnu')
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'base64url'))
  d.setAuthTag(Buffer.from(tag, 'base64url'))
  return Buffer.concat([d.update(Buffer.from(data, 'base64url')), d.final()]).toString('utf8')
}

// ---------- Jetons à usage unique ----------
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url')
export const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex')
export const safeEqual = (a: string, b: string) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))

// ---------- Politique de mots de passe ----------
const COMMON = new Set(['password', 'motdepasse', 'azertyuiop', 'qwertyuiop', '1234567890', '12345678910', 'password1!', 'administrateur', 'sentinelx1', 'sentinelx123', 'bienvenue1', 'welcome123'])
export function passwordProblems(p: string, context: string[] = []): string | null {
  if (p.length < 10) return 'Le mot de passe doit contenir au moins 10 caractères'
  if (p.length > 200) return 'Mot de passe trop long'
  if (COMMON.has(p.toLowerCase()) || /^(password|motdepasse|azerty|qwerty|123456|admin|sentinelx|bienvenue|welcome)/i.test(p)) return 'Ce mot de passe est trop courant'
  if (/^(.)\1+$/.test(p)) return 'Le mot de passe ne peut pas être constitué d\'un seul caractère répété'
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d]/].filter((r) => r.test(p)).length
  if (classes < 2) return 'Combinez au moins deux types de caractères (lettres, chiffres, symboles)'
  for (const c of context) if (c && c.length >= 4 && p.toLowerCase().includes(c.toLowerCase())) return 'Le mot de passe ne doit pas contenir votre nom ou votre e-mail'
  return null
}

// ---------- TOTP (RFC 6238), sans dépendance externe ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = ''
  for (const b of buf) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}
export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = 0, value = 0
  const out: number[] = []
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch)
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}
export const generateTotpSecret = () => base32Encode(crypto.randomBytes(20))
export function totpCode(secret: string, step = Math.floor(Date.now() / 30000)): string {
  const msg = Buffer.alloc(8)
  msg.writeUInt32BE(Math.floor(step / 2 ** 32), 0)
  msg.writeUInt32BE(step >>> 0, 4)
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest()
  const off = h[h.length - 1] & 0xf
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]
  return String(code % 1_000_000).padStart(6, '0')
}
/** Vérifie un code avec une tolérance d'un pas (30 s) avant et après. */
export function verifyTotp(secret: string, code: string): boolean {
  const c = String(code ?? '').replace(/\s/g, '')
  if (!/^\d{6}$/.test(c)) return false
  const now = Math.floor(Date.now() / 30000)
  return [-1, 0, 1].some((d) => safeEqual(totpCode(secret, now + d), c))
}
export const totpUri = (secret: string, email: string) => `otpauth://totp/SentinelX:${encodeURIComponent(email)}?secret=${secret}&issuer=SentinelX&digits=6&period=30`
export const generateRecoveryCodes = (n = 8) => Array.from({ length: n }, () => crypto.randomBytes(5).toString('hex').match(/.{1,5}/g)!.join('-'))

// ---------- Limitation de débit (fenêtre glissante en mémoire) ----------
// Suffisant pour un processus unique ; avec plusieurs instances, placer un rate-limit sur le reverse proxy ou Redis.
type Bucket = { hits: number[]; }
const buckets = new Map<string, Bucket>()
export function rateLimit(key: string, limit: number, windowMs = 60_000): { ok: boolean; retryAfter: number } {
  const now = Date.now()
  const b = buckets.get(key) ?? { hits: [] }
  b.hits = b.hits.filter((t) => now - t < windowMs)
  if (b.hits.length >= limit) {
    buckets.set(key, b)
    return { ok: false, retryAfter: Math.ceil((windowMs - (now - b.hits[0])) / 1000) }
  }
  b.hits.push(now)
  buckets.set(key, b)
  return { ok: true, retryAfter: 0 }
}
setInterval(() => {
  const now = Date.now()
  for (const [k, b] of buckets) if (!b.hits.some((t) => now - t < 120_000)) buckets.delete(k)
}, 60_000).unref()

/** Verrou par clé : rend atomique "vérifier le quota puis créer" (section 12.3). */
const locks = new Map<string, Promise<any>>()
export function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve()
  const next = prev.catch(() => {}).then(fn)
  locks.set(key, next.catch(() => {}))
  return next
}
