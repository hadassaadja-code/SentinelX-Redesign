// Configuration centralisée : toutes les variables d'environnement sont lues ici, avec repli de démonstration.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data')
fs.mkdirSync(DATA_DIR, { recursive: true })

const env = (k: string, d = '') => (process.env[k] ?? d).trim()
const bool = (k: string, d = false) => (process.env[k] === undefined ? d : /^(1|true|yes|on)$/i.test(process.env[k]!))
const int = (k: string, d: number) => (Number.isFinite(Number(process.env[k])) && process.env[k] !== undefined ? Number(process.env[k]) : d)

/** Secret persistant pour les JWT et le chiffrement : variable d'environnement, sinon fichier local généré. */
function persistentSecret(envKey: string, file: string): string {
  if (process.env[envKey]) return process.env[envKey]!
  const f = path.join(ROOT, file)
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim()
  const s = crypto.randomBytes(48).toString('hex')
  fs.writeFileSync(f, s, { mode: 0o600 })
  return s
}

export const config = {
  env: env('NODE_ENV', 'development'),
  isProd: env('NODE_ENV') === 'production',
  port: int('PORT', 3000),
  host: env('HOST', '127.0.0.1'),
  /** URL publique de l'application (liens dans les e-mails) */
  appUrl: env('APP_URL', `http://localhost:${int('PORT', 3000)}`),
  jwtSecret: persistentSecret('JWT_SECRET', '.jwt-secret'),
  encryptionKey: persistentSecret('ENCRYPTION_KEY', '.encryption-key'),
  sessionDays: int('SESSION_DAYS', 7),
  sessionIdleMinutes: int('SESSION_IDLE_MINUTES', 720),
  /** Mode laboratoire : autorise les cibles internes (jamais en production) */
  allowPrivateTargets: bool('ALLOW_PRIVATE_TARGETS', false) && env('NODE_ENV') !== 'production',
  registrationsOpen: bool('REGISTRATIONS_OPEN', true),
  requireEmailVerification: bool('REQUIRE_EMAIL_VERIFICATION', false),
  superAdminEmails: env('SUPERADMIN_EMAILS').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
  /** File de tâches : BullMQ si REDIS_URL est défini, sinon exécution dans le processus */
  redisUrl: env('REDIS_URL'),
  workerConcurrency: int('WORKER_CONCURRENCY', 2),
  /** Rôle du processus : "all" (API + worker), "api" ou "worker" */
  processRole: env('PROCESS_ROLE', 'all'),
  mail: {
    smtpUrl: env('SMTP_URL'), // ex: smtps://user:pass@smtp.example.com:465
    from: env('MAIL_FROM', 'SentinelX <no-reply@sentinelx.local>'),
    /** Sans SMTP, les liens (vérification, invitation, réinitialisation) sont renvoyés à l'interface pour la démonstration */
    exposeLinks: bool('MAIL_DEV_EXPOSE_LINKS', !env('SMTP_URL')),
  },
  stripe: {
    secretKey: env('STRIPE_SECRET_KEY'),
    webhookSecret: env('STRIPE_WEBHOOK_SECRET'),
    prices: {
      PROFESSIONAL: env('STRIPE_PRICE_PROFESSIONAL'),
      BUSINESS: env('STRIPE_PRICE_BUSINESS'),
    } as Record<string, string>,
    get enabled() {
      return !!env('STRIPE_SECRET_KEY')
    },
  },
  playwright: {
    enabled: bool('PLAYWRIGHT_ENABLED', true),
    timeoutMs: int('PLAYWRIGHT_TIMEOUT_MS', 30000),
  },
  rateLimit: {
    apiPerMinute: int('RATE_LIMIT_API', 300),
    authPerMinute: int('RATE_LIMIT_AUTH', 15),
  },
  screenshotsDir: path.join(DATA_DIR, 'screenshots'),
  reportsDir: path.join(DATA_DIR, 'reports'),
}
fs.mkdirSync(config.screenshotsDir, { recursive: true })
fs.mkdirSync(config.reportsDir, { recursive: true })
