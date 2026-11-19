// Envoi d'e-mails (section 11). SMTP si SMTP_URL est défini ; sinon l'e-mail est journalisé dans la boîte d'envoi
// (visible par le Super Administrateur) et les liens sont renvoyés à l'interface en mode démonstration.
import nodemailer from 'nodemailer'
import { config } from './config.js'
import { prisma, asPlatform } from './db.js'

const transport = config.mail.smtpUrl ? nodemailer.createTransport(config.mail.smtpUrl) : null
export const mailEnabled = !!transport

const esc = (s: any) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

function layout(title: string, lines: string[], cta?: { label: string; url: string }) {
  const body = lines.map((l) => `<p style="margin:0 0 12px;font-size:15px;line-height:1.55;color:#1f2937">${l}</p>`).join('')
  const btn = cta ? `<p style="margin:22px 0"><a href="${esc(cta.url)}" style="background:#5b4bdb;color:#fff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:700;display:inline-block">${esc(cta.label)}</a></p><p style="font-size:12px;color:#64748b">Si le bouton ne fonctionne pas : <br>${esc(cta.url)}</p>` : ''
  return `<!doctype html><html lang="fr"><body style="margin:0;background:#f4f5fb;padding:28px;font-family:Segoe UI,Helvetica,Arial,sans-serif"><div style="max-width:560px;margin:0 auto;background:#fff;border-radius:16px;padding:28px;border:1px solid #e2e5f2"><div style="font-weight:800;font-size:20px;color:#0f2339;margin-bottom:18px">SentinelX</div><h1 style="font-size:19px;margin:0 0 14px;color:#0f2339">${esc(title)}</h1>${body}${btn}<p style="font-size:12px;color:#94a3b8;margin-top:26px">Message automatique de la plateforme SentinelX.</p></div></body></html>`
}

export type Mail = { to: string; subject: string; lines: string[]; cta?: { label: string; url: string } }

/** Envoie (ou journalise) un e-mail. Ne lève jamais : une panne de courrier ne doit pas bloquer l'application. */
export async function sendMail(m: Mail): Promise<void> {
  const text = m.lines.map((l) => l.replace(/<[^>]+>/g, '')).join('\n\n') + (m.cta ? `\n\n${m.cta.label} : ${m.cta.url}` : '')
  const html = layout(m.subject, m.lines, m.cta)
  const rec = await asPlatform(() => prisma.emailOutbox.create({ data: { to: m.to, subject: m.subject, text, html, status: transport ? 'QUEUED' : 'LOGGED' } })).catch(() => null)
  if (!transport) {
    if (!config.isProd) console.log(`[mail] (non envoyé, pas de SMTP) à ${m.to} — ${m.subject}${m.cta ? ` — ${m.cta.url}` : ''}`)
    return
  }
  try {
    await transport.sendMail({ from: config.mail.from, to: m.to, subject: m.subject, text, html })
    if (rec) await asPlatform(() => prisma.emailOutbox.update({ where: { id: rec.id }, data: { status: 'SENT', sentAt: new Date() } })).catch(() => {})
  } catch (e: any) {
    console.error('[mail]', e?.message)
    if (rec) await asPlatform(() => prisma.emailOutbox.update({ where: { id: rec.id }, data: { status: 'FAILED', error: String(e?.message ?? e).slice(0, 300) } })).catch(() => {})
  }
}

export const link = (p: string) => `${config.appUrl.replace(/\/$/, '')}${p}`

// ---------- Modèles ----------
export const templates = {
  verifyEmail: (to: string, token: string): Mail => ({
    to, subject: 'Confirmez votre adresse e-mail',
    lines: ['Bienvenue sur SentinelX. Confirmez votre adresse e-mail pour sécuriser votre compte.', 'Ce lien est valable 24 heures.'],
    cta: { label: 'Confirmer mon adresse', url: link(`/verify-email?token=${token}`) },
  }),
  resetPassword: (to: string, token: string): Mail => ({
    to, subject: 'Réinitialisation de votre mot de passe',
    lines: ['Une réinitialisation de mot de passe a été demandée pour votre compte SentinelX.', 'Si vous n\'êtes pas à l\'origine de cette demande, ignorez ce message : votre mot de passe reste inchangé.', 'Ce lien est valable 1 heure.'],
    cta: { label: 'Choisir un nouveau mot de passe', url: link(`/reset-password?token=${token}`) },
  }),
  invite: (to: string, token: string, orgName: string, inviter: string, role: string): Mail => ({
    to, subject: `Invitation à rejoindre ${orgName} sur SentinelX`,
    lines: [`${esc(inviter)} vous invite à rejoindre l'organisation <b>${esc(orgName)}</b> avec le rôle ${esc(role)}.`, 'Ce lien est valable 7 jours.'],
    cta: { label: 'Accepter l\'invitation', url: link(`/invite?token=${token}`) },
  }),
  scanDone: (to: string, appName: string, score: number | null, scanId: string, critical: number): Mail => ({
    to, subject: `Audit terminé : ${appName}${critical ? ` — ${critical} vulnérabilité(s) critique(s)` : ''}`,
    lines: [`L'audit de <b>${esc(appName)}</b> est terminé${score != null ? ` avec un score global de <b>${score}/100</b>` : ''}.`, critical ? `<b style="color:#b91c1c">${critical} vulnérabilité(s) critique(s)</b> nécessitent une correction prioritaire.` : 'Le rapport détaillé est disponible dans votre espace.'],
    cta: { label: 'Voir le rapport', url: link(`/app/scans/${scanId}`) },
  }),
  appDown: (to: string, appName: string, reason: string): Mail => ({
    to, subject: `Application indisponible : ${appName}`,
    lines: [`Le monitoring a détecté que <b>${esc(appName)}</b> ne répond plus correctement.`, `Motif : ${esc(reason)}`],
    cta: { label: 'Ouvrir le monitoring', url: link('/app/monitoring') },
  }),
  appUp: (to: string, appName: string, downtimeMin: number): Mail => ({
    to, subject: `Incident résolu : ${appName}`,
    lines: [`<b>${esc(appName)}</b> répond de nouveau. Durée de l'interruption : environ ${downtimeMin} minute(s).`],
    cta: { label: 'Voir l\'historique', url: link('/app/monitoring') },
  }),
  sslExpiring: (to: string, appName: string, days: number): Mail => ({
    to, subject: `Certificat TLS bientôt expiré : ${appName}`,
    lines: [`Le certificat de <b>${esc(appName)}</b> expire dans ${days} jour(s). Renouvelez-le pour éviter une interruption.`],
    cta: { label: 'Voir l\'application', url: link('/app/monitoring') },
  }),
  quotaReached: (to: string, what: string): Mail => ({
    to, subject: 'Quota atteint sur votre organisation',
    lines: [`Le quota suivant est atteint : <b>${esc(what)}</b>. Passez à une formule supérieure pour continuer.`],
    cta: { label: 'Voir les formules', url: link('/app/billing') },
  }),
  subscriptionEnding: (to: string, orgName: string, date: string): Mail => ({
    to, subject: `Abonnement ${orgName} : fin de période le ${date}`,
    lines: [`L'abonnement de <b>${esc(orgName)}</b> arrive en fin de période le ${esc(date)}. Vérifiez votre moyen de paiement pour éviter une interruption.`],
    cta: { label: 'Gérer l\'abonnement', url: link('/app/billing') },
  }),
  digest: (to: string, orgName: string, lines: string[]): Mail => ({
    to, subject: `Synthèse hebdomadaire — ${orgName}`,
    lines: [`Voici l'activité de la semaine pour <b>${esc(orgName)}</b> :`, ...lines],
    cta: { label: 'Ouvrir le tableau de bord', url: link('/app') },
  }),
}
