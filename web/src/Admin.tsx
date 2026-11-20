import React, { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import QRCode from 'qrcode'
import { api, ROLE_FR, fmt, fmtDate, ago } from './api'
import { CopyBtn, DevLinks, Empty, Err, Icon, Loading, Modal, Ok, PageHead, Skeleton, Tabs, useAction, useAuth, useCan, useLoad, THEMES, THEME_FR, useTheme } from './ui'

// ================= NOTIFICATIONS =================
export function Notifications() {
  const { me, reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/notifications'))
  const act = useAction()
  const [prefs, setPrefs] = useState({ notifyEmail: me.user.notifyEmail, notifyDigest: me.user.notifyDigest })
  const readAll = async () => {
    await api('/notifications/read-all', { method: 'POST' }).catch(() => {})
    reload()
    reloadMe()
  }
  const savePrefs = async (p: any) => {
    setPrefs(p)
    if (await act.run(() => api('/auth/profile', { method: 'PATCH', body: p }))) reloadMe()
  }
  return (
    <>
      <PageHead title="Notifications" sub="Audits terminés, vulnérabilités critiques, indisponibilités, certificats, quotas et abonnement.">
        <button className="btn ghost" onClick={readAll}>Tout marquer comme lu</button>
      </PageHead>
      <Err msg={error || act.error} />
      <div className="card">
        <h2>Mes préférences</h2>
        <label className="chk"><input type="checkbox" checked={prefs.notifyEmail} onChange={(e) => savePrefs({ ...prefs, notifyEmail: e.target.checked })} />Recevoir les alertes par e-mail (audits terminés, vulnérabilités critiques, indisponibilités){!me.features.mail && <span className="muted small"> — aucun serveur SMTP configuré : les e-mails sont journalisés</span>}</label>
        <label className="chk"><input type="checkbox" checked={prefs.notifyDigest} onChange={(e) => savePrefs({ ...prefs, notifyDigest: e.target.checked })} />Recevoir la synthèse hebdomadaire</label>
        <p className="muted small" style={{ margin: '8px 0 0' }}>Les administrateurs peuvent ajouter des adresses d'alerte et un webhook (Slack, Discord, outil interne) dans <Link to="/app/settings">Paramètres → Organisation</Link>.</p>
      </div>
      <div className="card">
        {!data ? <Skeleton kind="table" n={5} /> : data.length === 0 ? <Empty icon="bell">Aucune notification.</Empty> : (
          <table><tbody>
            {data.map((n) => (
              <tr key={n.id} style={{ opacity: n.read ? 0.6 : 1 }}>
                <td style={{ width: 14 }}>{!n.read && <span className="dot UP" style={{ background: 'var(--accent)', boxShadow: 'none' }} />}</td>
                <td><b>{n.title}</b>{n.body && <div className="muted small">{n.body}</div>}</td>
                <td className="muted small" title={fmt(n.createdAt)}>{ago(n.createdAt)}</td>
                <td>{n.link && <Link to={n.link} onClick={() => api(`/notifications/${n.id}/read`, { method: 'POST' }).then(reloadMe).catch(() => {})}>Ouvrir</Link>}</td>
              </tr>
            ))}
          </tbody></table>
        )}
      </div>
    </>
  )
}

// ================= MEMBRES =================
export function Members() {
  const can = useCan()
  const { me, reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/members'))
  const invites = useLoad<any[]>(() => (can.admin ? api('/members/invitations') : Promise.resolve([])), [can.admin])
  const act = useAction()
  const [inv, setInv] = useState({ email: '', role: 'ANALYST' })
  const [links, setLinks] = useState<any>(null)
  const [direct, setDirect] = useState(false)
  const [df, setDf] = useState({ name: '', email: '', password: '', role: 'ANALYST' })
  const refresh = () => { reload(); invites.reload(); reloadMe() }
  const call = async (fn: () => Promise<any>) => { if (await act.run(fn)) refresh() }
  const invite = async (e: React.FormEvent) => {
    e.preventDefault()
    let r: any
    if (await act.run(async () => { r = await api('/members/invite', { method: 'POST', body: inv }) }, { success: 'Invitation envoyée.' })) {
      setInv({ email: '', role: 'ANALYST' })
      setLinks(r?.devLinks ?? null)
      refresh()
    }
  }
  return (
    <>
      <PageHead title="Membres et rôles" sub={`${me.usage.members} collaborateur(s) sur ${me.plan.members} autorisés par la formule ${me.plan.label}.`} />
      <Err msg={error || act.error} />
      {can.admin && (
        <form className="card" onSubmit={invite}>
          <h2>Inviter un collaborateur</h2>
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <label className="f">E-mail<input required type="email" value={inv.email} onChange={(e) => setInv({ ...inv, email: e.target.value })} /></label>
            <label className="f">Rôle<select value={inv.role} onChange={(e) => setInv({ ...inv, role: e.target.value })}>{Object.keys(ROLE_FR).map((r) => <option key={r} value={r}>{ROLE_FR[r]}</option>)}</select></label>
            <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy}><Icon name="plus" />Envoyer l'invitation</button>
            <button type="button" className="btn ghost" onClick={() => setDirect(!direct)}>Créer directement</button>
          </div>
          <p className="muted small" style={{ margin: '10px 0 0' }}>L'invitation est valable 7 jours. Une personne déjà inscrite peut rejoindre plusieurs organisations.</p>
          {links && <div style={{ marginTop: 10 }}><DevLinks links={links} /></div>}
          {direct && (
            <div className="subform" style={{ display: 'block' }}>
              <div className="row" style={{ alignItems: 'flex-end' }}>
                <label className="f">Nom<input required value={df.name} onChange={(e) => setDf({ ...df, name: e.target.value })} /></label>
                <label className="f">E-mail<input required type="email" value={df.email} onChange={(e) => setDf({ ...df, email: e.target.value })} /></label>
                <label className="f">Mot de passe provisoire<input required type="password" minLength={10} autoComplete="new-password" value={df.password} onChange={(e) => setDf({ ...df, password: e.target.value })} /></label>
                <label className="f">Rôle<select value={df.role} onChange={(e) => setDf({ ...df, role: e.target.value })}>{Object.keys(ROLE_FR).map((r) => <option key={r} value={r}>{ROLE_FR[r]}</option>)}</select></label>
                <button type="button" className="btn" disabled={act.busy} onClick={async () => { if (await act.run(() => api('/members', { method: 'POST', body: df }))) { setDf({ name: '', email: '', password: '', role: 'ANALYST' }); setDirect(false); refresh() } }}>Ajouter</button>
              </div>
              <p className="muted small" style={{ margin: '8px 0 0' }}>Communiquez le mot de passe provisoire au collaborateur, qui pourra le changer dans ses paramètres.</p>
            </div>
          )}
        </form>
      )}
      <div className="card">
        {!data ? <Skeleton kind="table" n={4} /> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Membre</th><th>Rôle</th><th>Sécurité</th><th>Dernière connexion</th><th></th></tr></thead>
              <tbody>
                {data.map((m) => (
                  <tr key={m.memberId}>
                    <td><b>{m.name}</b> {m.self && <span className="badge">Vous</span>}<div className="muted small">{m.email}</div></td>
                    <td>
                      {can.admin ? (
                        <select value={m.role} onChange={(e) => act.run(() => api(`/members/${m.memberId}`, { method: 'PATCH', body: { role: e.target.value } }), { success: 'Rôle mis à jour.' }).then((ok) => ok && refresh())} aria-label="Rôle">
                          {Object.keys(ROLE_FR).map((r) => <option key={r} value={r}>{ROLE_FR[r]}</option>)}
                        </select>
                      ) : <span className="badge">{ROLE_FR[m.role]}</span>}
                    </td>
                    <td className="small"><span className={`badge ${m.totpEnabled ? 'ok' : ''}`}>{m.totpEnabled ? '2FA active' : '2FA inactive'}</span> <span className={`badge ${m.emailVerified ? 'ok' : 'bad'}`}>{m.emailVerified ? 'E-mail confirmé' : 'E-mail non confirmé'}</span></td>
                    <td className="muted small">{m.lastLoginAt ? ago(m.lastLoginAt) : 'jamais'}</td>
                    <td style={{ textAlign: 'right' }}>{can.admin && !m.self && <button className="btn danger sm" onClick={() => window.confirm(`Retirer ${m.name} de l'organisation ?`) && call(() => api(`/members/${m.memberId}`, { method: 'DELETE' }))}>Retirer</button>}</td>
                  </tr>
                ))}
                {(invites.data ?? []).map((i) => (
                  <tr key={i.id} style={{ opacity: 0.75 }}>
                    <td><b>{i.email}</b><div className="muted small">Invitation envoyée le {fmtDate(i.createdAt)}, expire le {fmtDate(i.expiresAt)}</div></td>
                    <td><span className="badge">{ROLE_FR[i.role]}</span></td>
                    <td><span className="badge run">En attente</span></td>
                    <td></td>
                    <td style={{ textAlign: 'right' }}><button className="btn ghost sm" onClick={() => call(() => api(`/members/invitations/${i.id}`, { method: 'DELETE' }))}>Annuler</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="card">
        <h2>Permissions par rôle</h2>
        <table><tbody>
          <tr><td><b>Administrateur</b></td><td className="muted">Membres, rôles, projets, audits, paramètres, facturation et journal.</td></tr>
          <tr><td><b>Responsable technique</b></td><td className="muted">Projets, applications, autorisations, campagnes, tests de charge, affectation des anomalies, monitoring.</td></tr>
          <tr><td><b>Auditeur / Analyste</b></td><td className="muted">Lancer les audits autorisés, qualifier et commenter les constats, produire et partager les rapports, prendre en charge les incidents.</td></tr>
          <tr><td><b>Lecteur</b></td><td className="muted">Consultation uniquement (résultats, rapports, notifications).</td></tr>
        </tbody></table>
      </div>
    </>
  )
}

// ================= ABONNEMENT =================
export function Billing() {
  const can = useCan()
  const { reload: reloadMe } = useAuth()
  const [params] = useSearchParams()
  const { data, error, reload } = useLoad<any>(() => api('/billing'))
  const act = useAction()
  if (!data) return error ? <Err msg={error} /> : <Loading />
  const cur = data.plans[data.current]
  const choose = async (k: string) => {
    let r: any
    if (await act.run(async () => { r = await api('/billing/plan', { method: 'POST', body: { plan: k } }) }, { success: 'Formule mise à jour.' })) {
      if (r?.checkoutUrl) window.location.href = r.checkoutUrl
      else { reload(); reloadMe() }
    }
  }
  const portal = async () => {
    let r: any
    if (await act.run(async () => { r = await api('/billing/portal', { method: 'POST' }) })) window.location.href = r.url
  }
  const Usage = ({ label, used, max }: { label: string; used: number; max: number }) => (
    <div style={{ marginBottom: 12 }}>
      <div className="row between small"><span>{label}</span><b>{used} / {max}</b></div>
      <div className="bar" style={{ marginTop: 4 }}><i style={{ width: `${Math.min(100, (used / max) * 100)}%`, background: used >= max ? 'var(--danger)' : undefined }} /></div>
    </div>
  )
  const STATUS: Record<string, string> = { DEMO: 'Démonstration', ACTIVE: 'Actif', TRIALING: "Période d'essai", PAST_DUE: 'Paiement en retard', CANCELED: 'Résilié' }
  return (
    <>
      <PageHead title="Abonnement" sub={`Formule actuelle : ${cur.label} · ${STATUS[data.status] ?? data.status}${data.currentPeriodEnd ? ` · fin de période le ${fmtDate(data.currentPeriodEnd)}` : ''}`}>
        {data.mode === 'stripe' && can.admin && <button className="btn ghost" onClick={portal}>Gérer le paiement et les factures</button>}
      </PageHead>
      <Err msg={error || act.error} />
      {params.get('checkout') === 'success' && <Ok msg="Paiement confirmé. Votre formule sera mise à jour dès réception de la confirmation du fournisseur de paiement." />}
      {params.get('checkout') === 'cancel' && <div className="note">Paiement annulé : votre formule reste inchangée.</div>}
      {data.mode === 'demo' && <div className="note">Mode démonstration : le changement de formule est immédiat et sans paiement. Configurez STRIPE_SECRET_KEY pour activer la facturation réelle.</div>}
      {data.overrides.length > 0 && <div className="note">Quotas personnalisés par le Super Administrateur : {data.overrides.join(', ')}.</div>}
      <div className="card">
        <h2>Consommation</h2>
        <Usage label="Applications" used={data.usage.apps} max={data.effective.apps} />
        <Usage label="Collaborateurs" used={data.usage.members} max={data.effective.members} />
        <Usage label="Audits ce mois-ci" used={data.usage.scansThisMonth} max={data.effective.scansPerMonth} />
      </div>
      <div className="grid g3">
        {Object.keys(data.plans).map((k) => {
          const p = data.plans[k]
          const isCur = k === data.current
          return (
            <div className="card" key={k} style={{ borderColor: isCur ? 'var(--accent)' : undefined, marginBottom: 0 }}>
              <div className="row between"><h2 style={{ margin: 0 }}>{p.label}</h2>{isCur && <span className="badge run">Formule actuelle</span>}</div>
              <div className="price">{p.priceMonthly ? <><b>{p.priceMonthly} €</b> / mois</> : <b>Gratuit</b>}</div>
              <table style={{ margin: '10px 0' }}><tbody>
                <tr><td className="muted">Applications</td><td><b>{p.apps}</b></td></tr>
                <tr><td className="muted">Collaborateurs</td><td><b>{p.members}</b></td></tr>
                <tr><td className="muted">Audits par mois</td><td><b>{p.scansPerMonth}</b></td></tr>
                <tr><td className="muted">Audits simultanés</td><td><b>{p.concurrent}</b></td></tr>
                <tr><td className="muted">Historique</td><td><b>{p.historyDays} jours</b></td></tr>
                <tr><td className="muted">Monitoring</td><td><b>dès {p.minMonitorInterval} min</b></td></tr>
                <tr><td className="muted">Sécurité</td><td><b>{p.security}</b>{p.activeScans && <span className="muted small"> + contrôles actifs</span>}</td></tr>
                <tr><td className="muted">Tests API</td><td><b>{p.api ? 'Oui' : 'Non'}</b></td></tr>
                <tr><td className="muted">Navigateurs</td><td><b>{p.browsers.join(', ')}</b></td></tr>
                <tr><td className="muted">Tests de charge</td><td><b>{p.loadVus} VU / {p.loadSeconds} s</b></td></tr>
              </tbody></table>
              {can.admin && !isCur && <button className="btn" disabled={act.busy} onClick={() => choose(k)}>{data.mode === 'stripe' && p.priceMonthly ? `Souscrire ${p.label}` : `Choisir ${p.label}`}</button>}
            </div>
          )
        })}
      </div>
      {data.payments.length > 0 && (
        <div className="card" style={{ marginTop: 18 }}>
          <h2>Historique des paiements</h2>
          <table><thead><tr><th>Date</th><th>Formule</th><th>Montant</th><th>Statut</th><th></th></tr></thead><tbody>
            {data.payments.map((p: any) => <tr key={p.id}><td className="muted small">{fmt(p.createdAt)}</td><td>{p.plan}</td><td><b>{(p.amount / 100).toFixed(2)} {p.currency.toUpperCase()}</b></td><td><span className={`badge ${p.status === 'PAID' ? 'ok' : 'bad'}`}>{p.status === 'PAID' ? 'Payé' : p.status === 'FAILED' ? 'Échec' : p.status}</span></td><td>{p.invoiceUrl && <a href={p.invoiceUrl} target="_blank" rel="noopener noreferrer">Facture</a>}</td></tr>)}
          </tbody></table>
        </div>
      )}
    </>
  )
}

// ================= PARAMÈTRES =================
export function Settings() {
  const can = useCan()
  const { me, reload: reloadMe } = useAuth()
  const [params] = useSearchParams()
  const [theme, , setTheme] = useTheme()
  const [tab, setTab] = useState(params.get('mfa') ? 'security' : 'profile')
  const sessions = useLoad<any[]>(() => api('/auth/sessions'))
  const prof = useAction()
  const pwd = useAction()
  const [name, setName] = useState(me.user.name)
  const [p, setP] = useState({ current: '', next: '' })
  const [done, setDone] = useState('')
  const tabs = [{ id: 'profile', label: 'Profil' }, { id: 'security', label: 'Sécurité du compte' }, ...(can.admin ? [{ id: 'org', label: 'Organisation' }, { id: 'logs', label: 'Journal des actions' }] : [])]
  return (
    <>
      <PageHead title="Paramètres" sub="Profil, sécurité du compte (2FA, sessions), organisation et journal." />
      {params.get('mfa') && <div className="note warn">Votre organisation exige l'authentification à deux facteurs : activez-la ci-dessous pour continuer.</div>}
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === 'profile' && (
        <div className="grid g2">
          <form className="card" onSubmit={async (e) => { e.preventDefault(); if (await prof.run(() => api('/auth/profile', { method: 'PATCH', body: { name } }), { success: 'Profil enregistré.' })) reloadMe() }}>
            <h2>Profil</h2>
            <Err msg={prof.error} />
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="f">Nom<input required value={name} onChange={(e) => setName(e.target.value)} /></label>
              <button className="btn" disabled={prof.busy}>Enregistrer</button>
            </div>
            <p className="muted small" style={{ marginTop: 10 }}>{me.user.email} {me.user.emailVerified ? <span className="badge ok">confirmé</span> : <span className="badge bad">non confirmé</span>}</p>
            <label className="f" style={{ maxWidth: 260 }}>Thème de l'interface
              <select value={theme} onChange={(e) => setTheme(e.target.value)}>
                {THEMES.map((t) => <option key={t} value={t}>{THEME_FR[t]}</option>)}
              </select>
            </label>
          </form>
          <form className="card" onSubmit={async (e) => { e.preventDefault(); setDone(''); if (await pwd.run(() => api('/auth/password', { method: 'POST', body: p }), { success: 'Mot de passe modifié.' })) { setP({ current: '', next: '' }); setDone('Mot de passe modifié. Vos autres sessions ont été fermées.'); sessions.reload() } }}>
            <h2>Mot de passe</h2>
            <Err msg={pwd.error} />
            <Ok msg={done} />
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="f">Actuel<input required type="password" autoComplete="current-password" value={p.current} onChange={(e) => setP({ ...p, current: e.target.value })} /></label>
              <label className="f">Nouveau (10 caractères min.)<input required type="password" minLength={10} autoComplete="new-password" value={p.next} onChange={(e) => setP({ ...p, next: e.target.value })} /></label>
              <button className="btn" disabled={pwd.busy}>Modifier</button>
            </div>
          </form>
        </div>
      )}
      {tab === 'security' && (
        <>
          <TwoFactor />
          <div className="card">
            <div className="row between"><h2>Sessions actives</h2><button className="btn ghost sm" onClick={async () => { await api('/auth/sessions/revoke-all', { method: 'POST' }).catch(() => {}); sessions.reload() }}>Fermer toutes les autres sessions</button></div>
            <Err msg={sessions.error} />
            {!sessions.data ? <Loading /> : (
              <table><tbody>
                {sessions.data.map((s) => (
                  <tr key={s.id}>
                    <td className="small">{s.userAgent || 'Navigateur inconnu'}</td>
                    <td className="muted small">{s.ip}</td>
                    <td className="muted small">ouverte le {fmt(s.createdAt)} · active {ago(s.lastSeenAt)}</td>
                    <td style={{ textAlign: 'right' }}>{s.current ? <span className="badge ok">Session actuelle</span> : <button className="btn danger sm" onClick={async () => { await api(`/auth/sessions/${s.id}`, { method: 'DELETE' }).catch(() => {}); sessions.reload() }}>Révoquer</button>}</td>
                  </tr>
                ))}
              </tbody></table>
            )}
          </div>
        </>
      )}
      {tab === 'org' && can.admin && <OrgSettings />}
      {tab === 'logs' && can.admin && <AuditLogs />}
    </>
  )
}

function TwoFactor() {
  const { me, reload } = useAuth()
  const act = useAction()
  const [setup, setSetup] = useState<any>(null)
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [disable, setDisable] = useState({ password: '', code: '' })
  useEffect(() => {
    if (setup?.uri) QRCode.toDataURL(setup.uri, { margin: 1, width: 180 }).then(setQr).catch(() => setQr(''))
  }, [setup])
  const start = async () => act.run(async () => setSetup(await api('/auth/2fa/setup', { method: 'POST' })))
  const enable = async (e: React.FormEvent) => {
    e.preventDefault()
    let r: any
    if (await act.run(async () => { r = await api('/auth/2fa/enable', { method: 'POST', body: { code } }) }, { success: 'Authentification à deux facteurs activée.' })) {
      setCodes(r.recoveryCodes)
      setSetup(null)
      reload()
    }
  }
  return (
    <div className="card">
      <h2>Authentification à deux facteurs (2FA) {me.user.totpEnabled ? <span className="badge ok">Active</span> : <span className="badge">Inactive</span>}</h2>
      <Err msg={act.error} />
      {codes && (
        <Modal title="Codes de récupération" onClose={() => setCodes(null)}>
          <p className="small">Conservez ces codes en lieu sûr : chacun permet de se connecter une seule fois si vous perdez l'accès à votre application d'authentification.</p>
          <div className="codes">{codes.map((c) => <code key={c}>{c}</code>)}</div>
          <CopyBtn text={codes.join('\n')} label="Copier les codes" />
        </Modal>
      )}
      {!me.user.totpEnabled && !setup && (
        <>
          <p className="muted small">Ajoutez une seconde étape de connexion avec une application d'authentification (Google Authenticator, Authy, 1Password, Bitwarden…).</p>
          <button className="btn" onClick={start} disabled={act.busy}>Activer la 2FA</button>
        </>
      )}
      {setup && (
        <form onSubmit={enable} className="row" style={{ alignItems: 'flex-start', gap: 22 }}>
          <div>{qr ? <img src={qr} alt="QR code 2FA" width={180} height={180} style={{ borderRadius: 10, border: '1px solid var(--line)' }} /> : <Loading />}</div>
          <div style={{ flex: 1, minWidth: 240 }}>
            <p className="small">1. Scannez le QR code, ou saisissez la clé manuellement : <code className="mono">{setup.secret}</code> <CopyBtn text={setup.secret} /></p>
            <p className="small">2. Saisissez le code à 6 chiffres affiché par l'application :</p>
            <div className="row"><input required inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} style={{ width: 140 }} /><button className="btn" disabled={act.busy}>Confirmer</button><button type="button" className="btn ghost" onClick={() => setSetup(null)}>Annuler</button></div>
          </div>
        </form>
      )}
      {me.user.totpEnabled && (
        <>
          <p className="muted small">La 2FA est active : un code est demandé à chaque connexion. {me.org?.require2fa && 'Votre organisation l\'impose à tous ses membres.'}</p>
          <div className="row">
            <button className="btn ghost sm" onClick={async () => { const c = window.prompt('Code 2FA actuel :'); if (c) { let r: any; if (await act.run(async () => { r = await api('/auth/2fa/recovery', { method: 'POST', body: { code: c } }) })) setCodes(r.recoveryCodes) } }}>Régénérer les codes de récupération</button>
          </div>
          {!me.org?.require2fa && (
            <form className="row" style={{ marginTop: 12, alignItems: 'flex-end' }} onSubmit={async (e) => { e.preventDefault(); if (await act.run(() => api('/auth/2fa/disable', { method: 'POST', body: disable }))) { setDisable({ password: '', code: '' }); reload() } }}>
              <label className="f">Mot de passe<input type="password" required autoComplete="current-password" value={disable.password} onChange={(e) => setDisable({ ...disable, password: e.target.value })} /></label>
              <label className="f">Code 2FA<input required inputMode="numeric" value={disable.code} onChange={(e) => setDisable({ ...disable, code: e.target.value })} /></label>
              <button className="btn danger" disabled={act.busy}>Désactiver la 2FA</button>
            </form>
          )}
        </>
      )}
    </div>
  )
}

function OrgSettings() {
  const { me, reload: reloadMe } = useAuth()
  const org = useLoad<any>(() => api('/org'))
  const act = useAction()
  const [f, setF] = useState<any>(null)
  const [ok, setOk] = useState('')
  useEffect(() => { if (org.data && !f) setF({ name: org.data.name, require2fa: org.data.require2fa, alertEmails: org.data.alertEmails, webhookUrl: org.data.webhookUrl }) }, [org.data, f])
  if (!f) return <Loading />
  return (
    <form className="card" onSubmit={async (e) => { e.preventDefault(); setOk(''); if (await act.run(() => api('/org', { method: 'PATCH', body: f }), { success: 'Paramètres enregistrés.' })) { setOk('Paramètres enregistrés.'); org.reload(); reloadMe() } }}>
      <h2>Organisation</h2>
      <Err msg={act.error} /><Ok msg={ok} />
      <div className="grid g2">
        <label className="f">Nom de l'organisation<input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="f">Adresses d'alerte supplémentaires (séparées par des virgules)<input value={f.alertEmails} onChange={(e) => setF({ ...f, alertEmails: e.target.value })} placeholder="securite@exemple.com, ops@exemple.com" /></label>
        <label className="f" style={{ gridColumn: '1 / -1' }}>Webhook sortant (Slack, Discord, outil interne — JSON avec les clés text, content, title, link)<input type="url" value={f.webhookUrl} onChange={(e) => setF({ ...f, webhookUrl: e.target.value })} placeholder="https://hooks.slack.com/services/…" /></label>
      </div>
      <label className="chk" style={{ marginTop: 10 }}><input type="checkbox" checked={f.require2fa} onChange={(e) => setF({ ...f, require2fa: e.target.checked })} disabled={!me.user.totpEnabled} /><span>Exiger la 2FA pour tous les membres{!me.user.totpEnabled && <span className="muted"> (activez d'abord la 2FA sur votre compte)</span>}</span></label>
      <div className="row" style={{ marginTop: 14 }}>
        <button className="btn" disabled={act.busy}>Enregistrer</button>
        {org.data?.webhookUrl && <button type="button" className="btn ghost" onClick={() => act.run(() => api('/org/webhook/test', { method: 'POST' })).then((r) => r && setOk('Webhook testé avec succès.'))}>Tester le webhook</button>}
      </div>
    </form>
  )
}

function AuditLogs() {
  const [q, setQ] = useState('')
  const logs = useLoad<any[]>(() => api(`/audit-logs?limit=200&q=${encodeURIComponent(q)}`), [q])
  return (
    <div className="card">
      <div className="row between"><h2>Journal des actions</h2><input placeholder="Filtrer (action, détail)" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <Err msg={logs.error} />
      {!logs.data ? <Skeleton kind="table" n={6} /> : logs.data.length === 0 ? <Empty icon="file">Aucune action enregistrée.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Détail</th><th>IP</th></tr></thead>
            <tbody>
              {logs.data.map((l) => (
                <tr key={l.id}>
                  <td className="muted small" style={{ whiteSpace: 'nowrap' }}>{fmt(l.createdAt)}</td>
                  <td className="small">{l.user?.name ?? <span className="muted">système</span>}</td>
                  <td><span className="badge">{l.action}</span></td>
                  <td className="small">{l.detail}</td>
                  <td className="muted small">{l.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
