// Authentification et comptes (section 3) : inscription, connexion avec 2FA, sessions, vérification d'e-mail,
// réinitialisation, invitations, changement d'organisation.
import { config } from '../config.js'
import {
  prisma, asPlatform, HttpError, PLANS, planOf, ROLES, getCtx, str, EMAIL, audit, usage, permissionsOf,
  hashPassword, verifyPassword, createSession, clearSessionCookie, templates, sendMail,
} from '../core.js'
import { mailEnabled } from '../mail.js'
import { encrypt, decrypt, generateRecoveryCodes, generateTotpSecret, passwordProblems, randomToken, rateLimit, sha256, totpUri, verifyTotp } from '../security.js'
import { billingMode } from '../billing.js'
import { availableBrowsers } from '../scanners/browser.js'

const authLimit = (req: any) => {
  const r = rateLimit(`auth:${req.ip}`, config.rateLimit.authPerMinute)
  if (!r.ok) throw new HttpError(429, `Trop de tentatives. Réessayez dans ${r.retryAfter} s.`)
}
const checkPassword = (p: string, context: string[] = []) => {
  const pb = passwordProblems(p, context)
  if (pb) throw new HttpError(400, pb)
}
async function issueToken(kind: string, data: { userId?: string; orgId?: string; email?: string; data?: any }, ttlMs: number) {
  const token = randomToken()
  await asPlatform(() => prisma.token.create({ data: { kind, tokenHash: sha256(token), userId: data.userId, orgId: data.orgId, email: data.email?.toLowerCase(), data: JSON.stringify(data.data ?? {}), expiresAt: new Date(Date.now() + ttlMs) } }))
  return token
}
async function consumeToken(kind: string, token: string) {
  const t = await asPlatform(() => prisma.token.findUnique({ where: { tokenHash: sha256(String(token ?? '')) } }))
  if (!t || t.kind !== kind || t.usedAt || t.expiresAt < new Date()) throw new HttpError(400, 'Lien invalide ou expiré')
  await asPlatform(() => prisma.token.update({ where: { id: t.id }, data: { usedAt: new Date() } }))
  return t
}
const devLinks = (links: Record<string, string>) => (config.mail.exposeLinks ? links : undefined)

async function sendVerification(user: any) {
  const token = await issueToken('VERIFY_EMAIL', { userId: user.id, email: user.email }, 24 * 3600_000)
  await sendMail(templates.verifyEmail(user.email, token))
  return `${config.appUrl}/verify-email?token=${token}`
}

export default async function authRoutes(app: any) {
  app.post('/auth/register', async (req: any, reply: any) => {
    authLimit(req)
    const open = await asPlatform(() => prisma.platformSetting.findUnique({ where: { key: 'registrationsOpen' } }))
    if ((open ? open.value === 'true' : config.registrationsOpen) === false) throw new HttpError(403, 'Les inscriptions sont fermées pour le moment')
    const b = req.body ?? {}
    const name = str(b.name, 80), email = str(b.email, 160).toLowerCase(), orgName = str(b.orgName, 80), password = String(b.password ?? '')
    if (!name || !orgName) throw new HttpError(400, 'Nom et organisation requis')
    if (!EMAIL.test(email)) throw new HttpError(400, 'Adresse e-mail invalide')
    checkPassword(password, [name, email.split('@')[0]])
    if (await prisma.user.findUnique({ where: { email } })) throw new HttpError(409, 'Un compte existe déjà avec cet e-mail')
    const passwordHash = await hashPassword(password)
    const user = await prisma.user.create({ data: { name, email, passwordHash, isSuperAdmin: config.superAdminEmails.includes(email) } })
    const org = await prisma.organization.create({ data: { name: orgName, members: { create: { userId: user.id, role: 'ADMIN' } } } })
    await createSession(req, reply, user.id, org.id)
    const link = await sendVerification(user)
    await audit(req, { orgId: org.id, user }, 'auth.register', `Organisation « ${orgName} » créée`)
    return { ok: true, devLinks: devLinks({ verify: link }) }
  })

  app.post('/auth/login', async (req: any, reply: any) => {
    authLimit(req)
    const email = str(req.body?.email, 160).toLowerCase(), password = String(req.body?.password ?? '')
    const r = rateLimit(`login:${req.ip}:${email}`, 10, 15 * 60_000)
    if (!r.ok) throw new HttpError(429, 'Trop de tentatives. Réessayez dans 15 minutes.')
    const user = await prisma.user.findUnique({ where: { email }, include: { memberships: true } })
    if (user?.lockedUntil && user.lockedUntil > new Date()) throw new HttpError(429, `Compte temporairement bloqué après plusieurs échecs. Réessayez dans ${Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000)} min.`)
    const ok = user ? await verifyPassword(user.passwordHash, password) : false
    if (!user || !ok) {
      if (user) {
        const failed = user.failedLogins + 1
        await prisma.user.update({ where: { id: user.id }, data: { failedLogins: failed, lockedUntil: failed >= 5 ? new Date(Date.now() + 15 * 60_000) : null } })
      }
      await audit(req, user ? { orgId: user.memberships[0]?.orgId, user } : null, 'auth.login_failed', email)
      throw new HttpError(401, 'E-mail ou mot de passe incorrect')
    }
    if (user.totpEnabled) {
      const ticket = await issueToken('MFA_LOGIN', { userId: user.id, email }, 5 * 60_000)
      return { mfaRequired: true, ticket }
    }
    await createSession(req, reply, user.id, user.memberships[0]?.orgId ?? null)
    await audit(req, { orgId: user.memberships[0]?.orgId, user }, 'auth.login')
    return { ok: true }
  })

  app.post('/auth/login/mfa', async (req: any, reply: any) => {
    authLimit(req)
    const ticketHash = sha256(String(req.body?.ticket ?? ''))
    const t = await asPlatform(() => prisma.token.findUnique({ where: { tokenHash: ticketHash } }))
    if (!t || t.kind !== 'MFA_LOGIN' || t.usedAt || t.expiresAt < new Date() || !t.userId) throw new HttpError(400, 'Session de connexion expirée, recommencez.')
    const user = await prisma.user.findUnique({ where: { id: t.userId }, include: { memberships: true } })
    if (!user?.totpSecret) throw new HttpError(400, 'Configuration 2FA introuvable')
    const code = String(req.body?.code ?? '').trim()
    let ok = verifyTotp(decrypt(user.totpSecret), code)
    if (!ok) {
      // Code de récupération (usage unique)
      const codes: string[] = JSON.parse(user.recoveryCodes || '[]')
      const h = sha256(code.toLowerCase().replace(/\s/g, ''))
      if (codes.includes(h)) {
        ok = true
        await prisma.user.update({ where: { id: user.id }, data: { recoveryCodes: JSON.stringify(codes.filter((c) => c !== h)) } })
        await audit(req, { orgId: user.memberships[0]?.orgId, user }, 'auth.recovery_code_used', `${codes.length - 1} code(s) restant(s)`)
      }
    }
    if (!ok) {
      const r = rateLimit(`mfa:${t.id}`, 5, 5 * 60_000)
      if (!r.ok) await asPlatform(() => prisma.token.update({ where: { id: t.id }, data: { usedAt: new Date() } }))
      throw new HttpError(401, 'Code incorrect')
    }
    await asPlatform(() => prisma.token.update({ where: { id: t.id }, data: { usedAt: new Date() } }))
    await createSession(req, reply, user.id, user.memberships[0]?.orgId ?? null)
    await audit(req, { orgId: user.memberships[0]?.orgId, user }, 'auth.login', '2FA')
    return { ok: true }
  })

  app.post('/auth/logout', async (req: any, reply: any) => {
    try {
      const ctx = await getCtx(req, { allowNoOrg: true })
      await prisma.session.update({ where: { id: ctx.sessionId }, data: { revoked: true } })
      await audit(req, ctx, 'auth.logout')
    } catch {}
    clearSessionCookie(reply)
    return { ok: true }
  })

  app.get('/auth/me', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const [unread, u, browsers] = await Promise.all([
      ctx.orgId ? prisma.notification.count({ where: { orgId: ctx.orgId, read: false } }) : 0,
      ctx.orgId ? usage(ctx.orgId) : null,
      availableBrowsers().catch(() => []),
    ])
    return {
      user: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email, emailVerified: !!ctx.user.emailVerifiedAt, totpEnabled: ctx.user.totpEnabled, isSuperAdmin: ctx.user.isSuperAdmin, notifyEmail: ctx.user.notifyEmail, notifyDigest: ctx.user.notifyDigest },
      org: ctx.org ? { id: ctx.org.id, name: ctx.org.name, plan: ctx.org.plan, status: ctx.org.status, require2fa: ctx.org.require2fa, subscriptionStatus: ctx.org.subscriptionStatus, currentPeriodEnd: ctx.org.currentPeriodEnd } : null,
      role: ctx.role, plan: ctx.plan, usage: u, unread, permissions: permissionsOf(ctx.role),
      memberships: ctx.memberships.map((m: any) => ({ orgId: m.orgId, name: m.org.name, role: m.role, current: m.orgId === ctx.orgId })),
      features: { billing: billingMode(), mail: mailEnabled, devLinks: config.mail.exposeLinks, browsers, requireEmailVerification: config.requireEmailVerification },
    }
  })

  app.post('/auth/switch-org', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const orgId = str(req.body?.orgId)
    if (!ctx.memberships.some((m: any) => m.orgId === orgId)) throw new HttpError(403, 'Vous n\'appartenez pas à cette organisation')
    await prisma.session.update({ where: { id: ctx.sessionId }, data: { orgId } })
    return { ok: true }
  })

  app.patch('/auth/profile', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const data: any = {}
    if (req.body?.name !== undefined) {
      data.name = str(req.body.name, 80)
      if (!data.name) throw new HttpError(400, 'Nom requis')
    }
    if (req.body?.notifyEmail !== undefined) data.notifyEmail = !!req.body.notifyEmail
    if (req.body?.notifyDigest !== undefined) data.notifyDigest = !!req.body.notifyDigest
    await prisma.user.update({ where: { id: ctx.user.id }, data })
    return { ok: true }
  })

  app.post('/auth/password', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const next = String(req.body?.next ?? '')
    if (!(await verifyPassword(ctx.user.passwordHash, String(req.body?.current ?? '')))) throw new HttpError(400, 'Mot de passe actuel incorrect')
    checkPassword(next, [ctx.user.name, ctx.user.email.split('@')[0]])
    await prisma.user.update({ where: { id: ctx.user.id }, data: { passwordHash: await hashPassword(next) } })
    await prisma.session.updateMany({ where: { userId: ctx.user.id, id: { not: ctx.sessionId } }, data: { revoked: true } })
    await audit(req, ctx, 'auth.password_changed', 'Autres sessions révoquées')
    return { ok: true }
  })

  app.get('/auth/sessions', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const list = await prisma.session.findMany({ where: { userId: ctx.user.id, revoked: false, expiresAt: { gt: new Date() } }, orderBy: { createdAt: 'desc' } })
    return list.map((s) => ({ id: s.id, userAgent: s.userAgent, ip: s.ip, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, current: s.id === ctx.sessionId }))
  })
  app.delete('/auth/sessions/:id', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    const r = await prisma.session.updateMany({ where: { id: req.params.id, userId: ctx.user.id }, data: { revoked: true } })
    if (!r.count) throw new HttpError(404, 'Session introuvable')
    await audit(req, ctx, 'auth.session_revoked')
    return { ok: true }
  })
  app.post('/auth/sessions/revoke-all', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    await prisma.session.updateMany({ where: { userId: ctx.user.id, id: { not: ctx.sessionId } }, data: { revoked: true } })
    await audit(req, ctx, 'auth.sessions_revoked_all')
    return { ok: true }
  })

  // ----- Vérification d'e-mail -----
  app.post('/auth/verify-email/send', async (req: any) => {
    authLimit(req)
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (ctx.user.emailVerifiedAt) return { ok: true, already: true }
    const link = await sendVerification(ctx.user)
    return { ok: true, devLinks: devLinks({ verify: link }) }
  })
  app.post('/auth/verify-email', async (req: any) => {
    authLimit(req)
    const t = await consumeToken('VERIFY_EMAIL', req.body?.token)
    await prisma.user.update({ where: { id: t.userId! }, data: { emailVerifiedAt: new Date() } })
    await audit(req, { user: { id: t.userId } }, 'auth.email_verified', t.email ?? '')
    return { ok: true }
  })

  // ----- Mot de passe oublié -----
  app.post('/auth/forgot', async (req: any) => {
    authLimit(req)
    const email = str(req.body?.email, 160).toLowerCase()
    const user = await prisma.user.findUnique({ where: { email } })
    let link: string | undefined
    if (user) {
      const token = await issueToken('RESET_PASSWORD', { userId: user.id, email }, 3600_000)
      await sendMail(templates.resetPassword(email, token))
      link = `${config.appUrl}/reset-password?token=${token}`
      await audit(req, { user }, 'auth.reset_requested')
    }
    // Réponse identique que le compte existe ou non (pas d'énumération)
    return { ok: true, devLinks: link ? devLinks({ reset: link }) : undefined }
  })
  app.post('/auth/reset', async (req: any) => {
    authLimit(req)
    const password = String(req.body?.password ?? '')
    const t = await consumeToken('RESET_PASSWORD', req.body?.token)
    const user = await prisma.user.findUnique({ where: { id: t.userId! } })
    if (!user) throw new HttpError(400, 'Compte introuvable')
    checkPassword(password, [user.name, user.email.split('@')[0]])
    await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await hashPassword(password), failedLogins: 0, lockedUntil: null, emailVerifiedAt: user.emailVerifiedAt ?? new Date() } })
    await prisma.session.updateMany({ where: { userId: user.id }, data: { revoked: true } })
    await audit(req, { user }, 'auth.password_reset', 'Toutes les sessions révoquées')
    return { ok: true }
  })

  // ----- Authentification à deux facteurs (TOTP) -----
  app.post('/auth/2fa/setup', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (ctx.user.totpEnabled) throw new HttpError(400, 'La 2FA est déjà activée')
    const secret = generateTotpSecret()
    await prisma.user.update({ where: { id: ctx.user.id }, data: { totpSecret: encrypt(secret) } })
    return { secret, uri: totpUri(secret, ctx.user.email) }
  })
  app.post('/auth/2fa/enable', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (!ctx.user.totpSecret) throw new HttpError(400, 'Lancez d\'abord la configuration')
    if (!verifyTotp(decrypt(ctx.user.totpSecret), String(req.body?.code ?? ''))) throw new HttpError(400, 'Code incorrect. Vérifiez l\'heure de votre appareil.')
    const codes = generateRecoveryCodes()
    await prisma.user.update({ where: { id: ctx.user.id }, data: { totpEnabled: true, recoveryCodes: JSON.stringify(codes.map((c) => sha256(c.toLowerCase()))) } })
    await prisma.session.updateMany({ where: { userId: ctx.user.id, id: { not: ctx.sessionId } }, data: { revoked: true } })
    await audit(req, ctx, 'auth.2fa_enabled')
    return { ok: true, recoveryCodes: codes }
  })
  app.post('/auth/2fa/disable', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (!(await verifyPassword(ctx.user.passwordHash, String(req.body?.password ?? '')))) throw new HttpError(400, 'Mot de passe incorrect')
    if (!ctx.user.totpSecret || !verifyTotp(decrypt(ctx.user.totpSecret), String(req.body?.code ?? ''))) throw new HttpError(400, 'Code 2FA incorrect')
    if (ctx.org?.require2fa) throw new HttpError(403, 'Votre organisation impose la 2FA : elle ne peut pas être désactivée')
    await prisma.user.update({ where: { id: ctx.user.id }, data: { totpEnabled: false, totpSecret: null, recoveryCodes: '[]' } })
    await audit(req, ctx, 'auth.2fa_disabled')
    return { ok: true }
  })
  app.post('/auth/2fa/recovery', async (req: any) => {
    const ctx = await getCtx(req, { allowNoOrg: true })
    if (!ctx.user.totpEnabled || !ctx.user.totpSecret || !verifyTotp(decrypt(ctx.user.totpSecret), String(req.body?.code ?? ''))) throw new HttpError(400, 'Code 2FA incorrect')
    const codes = generateRecoveryCodes()
    await prisma.user.update({ where: { id: ctx.user.id }, data: { recoveryCodes: JSON.stringify(codes.map((c) => sha256(c.toLowerCase()))) } })
    await audit(req, ctx, 'auth.recovery_codes_regenerated')
    return { ok: true, recoveryCodes: codes }
  })

  // ----- Invitations -----
  app.get('/auth/invite', async (req: any) => {
    const t = await asPlatform(() => prisma.token.findUnique({ where: { tokenHash: sha256(String(req.query?.token ?? '')) } }))
    if (!t || t.kind !== 'INVITE' || t.usedAt || t.expiresAt < new Date()) throw new HttpError(400, 'Invitation invalide ou expirée')
    const org = await asPlatform(() => prisma.organization.findUnique({ where: { id: t.orgId! } }))
    const existing = await prisma.user.findUnique({ where: { email: t.email! } })
    const d = JSON.parse(t.data)
    return { email: t.email, orgName: org?.name, role: d.role, inviter: d.inviter, existingAccount: !!existing }
  })
  app.post('/auth/invite/accept', async (req: any, reply: any) => {
    authLimit(req)
    const t = await consumeToken('INVITE', req.body?.token)
    const d = JSON.parse(t.data)
    const role = ROLES.includes(d.role) ? d.role : 'READER'
    const org = await asPlatform(() => prisma.organization.findUnique({ where: { id: t.orgId! } }))
    if (!org) throw new HttpError(400, 'Organisation introuvable')
    let user = await prisma.user.findUnique({ where: { email: t.email! } })
    if (!user) {
      const name = str(req.body?.name, 80), password = String(req.body?.password ?? '')
      if (!name) throw new HttpError(400, 'Nom requis')
      checkPassword(password, [name, t.email!.split('@')[0]])
      user = await prisma.user.create({ data: { name, email: t.email!, passwordHash: await hashPassword(password), emailVerifiedAt: new Date() } })
    }
    const members = await prisma.organizationMember.count({ where: { orgId: org.id } })
    if (members >= planOf(org).members) throw new HttpError(402, 'Le quota de collaborateurs de cette organisation est atteint')
    await prisma.organizationMember.upsert({ where: { orgId_userId: { orgId: org.id, userId: user.id } }, create: { orgId: org.id, userId: user.id, role }, update: {} })
    await createSession(req, reply, user.id, org.id)
    await audit(req, { orgId: org.id, user }, 'member.joined', `${user.email} (${role})`)
    return { ok: true }
  })

  app.get('/plans', async () => PLANS)
}
