// Noyau applicatif : formules et quotas, rôles et permissions, sessions, contexte de requête, journal, alertes.
import { hash, verify } from '@node-rs/argon2'
import jwt from 'jsonwebtoken'
import { config, ROOT } from './config.js'
import { prisma, asTenant, asPlatform, tenant } from './db.js'
import { sendMail, templates, type Mail } from './mail.js'
import { withLock } from './security.js'

export { ROOT, prisma, asTenant, asPlatform, withLock }

// ---------- Erreurs ----------
export class HttpError extends Error {
  status: number
  extra?: any
  constructor(status: number, message: string, extra?: any) {
    super(message)
    this.status = status
    this.extra = extra
  }
}

// ---------- Formules et quotas (section 12) ----------
export type Plan = {
  label: string; apps: number; members: number; scansPerMonth: number; concurrent: number; historyDays: number
  minMonitorInterval: number; security: string; api: boolean; browsers: string[]; loadVus: number; loadSeconds: number
  activeScans: boolean; priceMonthly: number
}
export const DEFAULT_PLANS: Record<string, Plan> = {
  STARTER: { label: 'Starter', apps: 2, members: 2, scansPerMonth: 20, concurrent: 1, historyDays: 7, minMonitorInterval: 60, security: 'Basique', api: false, browsers: ['chromium'], loadVus: 5, loadSeconds: 15, activeScans: false, priceMonthly: 0 },
  PROFESSIONAL: { label: 'Professional', apps: 10, members: 5, scansPerMonth: 200, concurrent: 2, historyDays: 30, minMonitorInterval: 15, security: 'Avancé', api: true, browsers: ['chromium', 'firefox'], loadVus: 20, loadSeconds: 60, activeScans: true, priceMonthly: 49 },
  BUSINESS: { label: 'Business', apps: 50, members: 25, scansPerMonth: 2000, concurrent: 5, historyDays: 90, minMonitorInterval: 5, security: 'Avancé', api: true, browsers: ['chromium', 'firefox', 'webkit'], loadVus: 50, loadSeconds: 180, activeScans: true, priceMonthly: 199 },
}
/** Formules effectives : valeurs par défaut, surchargées par le Super Administrateur (paramètre de plateforme "plans"). */
export let PLANS: Record<string, Plan> = JSON.parse(JSON.stringify(DEFAULT_PLANS))
export async function reloadPlans() {
  const s = await asPlatform(() => prisma.platformSetting.findUnique({ where: { key: 'plans' } })).catch(() => null)
  const over = s?.value ? safeJson(s.value, {}) : {}
  PLANS = JSON.parse(JSON.stringify(DEFAULT_PLANS))
  for (const k of Object.keys(PLANS)) if (over[k]) Object.assign(PLANS[k], over[k])
}
export function planOf(org: { plan: string; planOverrides?: string }): Plan {
  const base = PLANS[org.plan] ?? PLANS.STARTER
  const over = org.planOverrides ? safeJson(org.planOverrides, {}) : {}
  return { ...base, ...over }
}
export const safeJson = (s: string, d: any = null) => {
  try {
    return JSON.parse(s)
  } catch {
    return d
  }
}

// ---------- Rôles et permissions (section 2.3) : matrice centralisée ----------
export const ROLES = ['ADMIN', 'TECH_LEAD', 'ANALYST', 'READER'] as const
export type Role = (typeof ROLES)[number]
const ALL: Role[] = ['ADMIN', 'TECH_LEAD', 'ANALYST', 'READER']
const OPERATE: Role[] = ['ADMIN', 'TECH_LEAD', 'ANALYST']
const MANAGE: Role[] = ['ADMIN', 'TECH_LEAD']
const ADMIN: Role[] = ['ADMIN']
export const PERMISSIONS = {
  'project.read': ALL, 'project.manage': MANAGE, 'project.delete': ADMIN,
  'application.manage': MANAGE, 'application.authorize': MANAGE, 'application.delete': MANAGE,
  'scan.read': ALL, 'scan.run': OPERATE, 'scan.cancel': OPERATE, 'scan.load': MANAGE, 'scan.active': MANAGE,
  'finding.read': ALL, 'finding.update': OPERATE, 'finding.assign': MANAGE, 'finding.comment': OPERATE,
  'report.read': ALL, 'report.download': ALL, 'report.share': OPERATE,
  'monitoring.manage': MANAGE, 'monitoring.check': OPERATE, 'incident.update': OPERATE,
  'notification.read': ALL,
  'member.read': ALL, 'member.manage': ADMIN,
  'billing.read': ALL, 'billing.manage': ADMIN,
  'org.settings': ADMIN, 'audit.read': ADMIN,
} as const
export type Permission = keyof typeof PERMISSIONS
export const roleCan = (role: string, p: Permission) => (PERMISSIONS[p] as readonly string[]).includes(role)
export function can(ctx: Ctx, p: Permission) {
  if (!roleCan(ctx.role, p)) throw new HttpError(403, 'Permission insuffisante pour cette action')
}
/** Liste des permissions d'un rôle (envoyée au frontend pour adapter l'interface). */
export const permissionsOf = (role: string) => (Object.keys(PERMISSIONS) as Permission[]).filter((p) => roleCan(role, p))

// ---------- Mots de passe : Argon2id (section 3) ----------
export const hashPassword = (p: string) => hash(p, { algorithm: 2, memoryCost: 19456, timeCost: 2, parallelism: 1 })
export const verifyPassword = async (h: string, p: string) => {
  try {
    return await verify(h, p)
  } catch {
    return false
  }
}

// ---------- Sessions ----------
const COOKIE = 'sx_session'
export async function createSession(req: any, reply: any, userId: string, orgId: string | null) {
  const session = await prisma.session.create({
    data: {
      userId, orgId,
      userAgent: String(req.headers['user-agent'] ?? '').slice(0, 200),
      ip: req.ip ?? '',
      expiresAt: new Date(Date.now() + config.sessionDays * 86400_000),
    },
  })
  const token = jwt.sign({ sid: session.id }, config.jwtSecret, { algorithm: 'HS256', expiresIn: `${config.sessionDays}d` })
  reply.setCookie(COOKIE, token, { httpOnly: true, sameSite: 'strict', secure: config.isProd, path: '/', maxAge: config.sessionDays * 86400 })
  await prisma.user.update({ where: { id: userId }, data: { lastLoginAt: new Date(), failedLogins: 0, lockedUntil: null } })
  return session
}
export const clearSessionCookie = (reply: any) => reply.clearCookie(COOKIE, { path: '/' })

export type Ctx = {
  user: any; org: any; orgId: string; role: string; sessionId: string; plan: Plan; memberships: any[]; isSuperAdmin: boolean
}

/** Authentifie la requête : session valide, non révoquée, non expirée (absolue et inactivité), organisation active non suspendue. */
export async function getCtx(req: any, opts: { allowNoOrg?: boolean } = {}): Promise<Ctx> {
  const token = req.cookies?.[COOKIE]
  if (!token) throw new HttpError(401, 'Non authentifié')
  let payload: any
  try {
    payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    throw new HttpError(401, 'Session invalide')
  }
  const session = await prisma.session.findUnique({
    where: { id: String(payload.sid) },
    include: { user: { include: { memberships: { include: { org: true }, orderBy: { createdAt: 'asc' } } } } },
  })
  const now = Date.now()
  if (!session || session.revoked || session.expiresAt.getTime() < now) throw new HttpError(401, 'Session expirée')
  if (now - session.lastSeenAt.getTime() > config.sessionIdleMinutes * 60_000) {
    await prisma.session.update({ where: { id: session.id }, data: { revoked: true } })
    throw new HttpError(401, 'Session expirée par inactivité')
  }
  if (now - session.lastSeenAt.getTime() > 5 * 60_000) await prisma.session.update({ where: { id: session.id }, data: { lastSeenAt: new Date() } })
  const memberships = session.user.memberships
  const m = memberships.find((x) => x.orgId === session.orgId) ?? memberships[0]
  if (!m) {
    if (opts.allowNoOrg) return { user: session.user, org: null, orgId: '', role: '', sessionId: session.id, plan: PLANS.STARTER, memberships, isSuperAdmin: session.user.isSuperAdmin }
    throw new HttpError(403, 'Aucune organisation associée à ce compte')
  }
  if (m.org.status === 'SUSPENDED') throw new HttpError(403, 'Cette organisation est suspendue. Contactez le support.')
  if (m.org.require2fa && !session.user.totpEnabled && !opts.allowNoOrg) throw new HttpError(403, 'Votre organisation exige l\'authentification à deux facteurs. Activez-la dans vos paramètres.', { code: 'MFA_REQUIRED' })
  return { user: session.user, org: m.org, orgId: m.orgId, role: m.role, sessionId: session.id, plan: planOf(m.org), memberships, isSuperAdmin: session.user.isSuperAdmin }
}

/** Route authentifiée exécutée dans le contexte de l'organisation (isolation imposée par l'ORM). */
export function secured(perm: Permission | null, handler: (ctx: Ctx, req: any, reply: any) => Promise<any>) {
  return async (req: any, reply: any) => {
    const ctx = await getCtx(req)
    if (perm) can(ctx, perm)
    return asTenant(ctx.orgId, () => handler(ctx, req, reply))
  }
}
/** Route Super Administrateur : hors contexte d'organisation ; chaque accès est journalisé avec sa justification. */
export function platform(handler: (ctx: Ctx, req: any, reply: any) => Promise<any>) {
  return async (req: any, reply: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (!ctx.isSuperAdmin) throw new HttpError(403, 'Réservé au Super Administrateur')
    return asPlatform(() => handler(ctx, req, reply))
  }
}

// ---------- Utilitaires ----------
export const str = (v: any, max = 200) => String(v ?? '').trim().slice(0, max)
export const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
export const monthStart = () => new Date(new Date().getFullYear(), new Date().getMonth(), 1)

export async function audit(req: any, ctx: { orgId?: string; user?: any } | null, action: string, detail = '') {
  await asPlatform(() => prisma.auditLog.create({
    data: { orgId: ctx?.orgId || null, userId: ctx?.user?.id ?? null, action, detail: detail.slice(0, 500), ip: req?.ip ?? '' },
  })).catch(() => {})
}

export async function usage(orgId: string) {
  const [apps, members, scansThisMonth, running] = await Promise.all([
    prisma.application.count({ where: { orgId } }),
    prisma.organizationMember.count({ where: { orgId } }),
    prisma.scan.count({ where: { orgId, createdAt: { gte: monthStart() } } }),
    prisma.scan.count({ where: { orgId, status: { in: ['QUEUED', 'RUNNING'] } } }),
  ])
  return { apps, members, scansThisMonth, running }
}

export async function recordUsage(orgId: string, field: 'scans' | 'requests' | 'checks', n = 1) {
  const day = new Date().toISOString().slice(0, 10)
  await asPlatform(() => prisma.usageRecord.upsert({
    where: { orgId_day: { orgId, day } },
    create: { orgId, day, [field]: n },
    update: { [field]: { increment: n } },
  })).catch(() => {})
}

// ---------- Alertes : notification dans l'application + e-mail + webhook (section 11) ----------
export type Alert = { type: string; title: string; body?: string; link?: string; mail?: (to: string) => Mail; important?: boolean }
export async function alert(orgId: string, a: Alert) {
  await asPlatform(async () => {
    await prisma.notification.create({ data: { orgId, type: a.type, title: a.title, body: (a.body ?? '').slice(0, 500), link: a.link ?? '' } })
    const org = await prisma.organization.findUnique({ where: { id: orgId }, include: { members: { include: { user: true } } } })
    if (!org) return
    if (a.mail) {
      const to = new Set<string>()
      for (const m of org.members) if (m.user.notifyEmail && (m.role === 'ADMIN' || m.role === 'TECH_LEAD' || a.important)) to.add(m.user.email)
      for (const e of org.alertEmails.split(',').map((s) => s.trim()).filter((s) => EMAIL.test(s))) to.add(e)
      await Promise.all([...to].map((t) => sendMail(a.mail!(t))))
    }
    if (org.webhookUrl) await sendWebhook(org.webhookUrl, { source: 'sentinelx', organization: org.name, type: a.type, title: a.title, text: `${a.title}${a.body ? ` — ${a.body}` : ''}`, content: `**${a.title}**\n${a.body ?? ''}`, link: a.link ? `${config.appUrl}${a.link}` : undefined, at: new Date().toISOString() }).catch(() => {})
  })
}

/** Webhook sortant générique (clé "text" pour Slack, "content" pour Discord). Protégé contre le SSRF. */
export async function sendWebhook(url: string, payload: any) {
  const { safeRequest } = await import('./scanners/http.js')
  await safeRequest(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), readBody: false })
}

export { templates, sendMail, tenant }
