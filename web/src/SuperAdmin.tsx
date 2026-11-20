// Super Administration (2.1) : organisations, formules et quotas, statistiques globales, moteurs, journaux, e-mails.
import React, { useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { api, SCAN_FR, fmt, fmtDate, ago } from './api'
import { Brand, Empty, Err, Icon, Loading, Modal, Ok, PageHead, Tabs, THEME_FR, themeIcon, useAction, useAuth, useLoad, useTheme } from './ui'
import { BarChart } from './charts'
import { FooterLight } from './Footer'

export function SuperAdmin() {
  const { me, loading } = useAuth()
  const [tab, setTab] = useState('overview')
  const [theme, toggle] = useTheme()
  const [open, setOpen] = useState(false)
  if (loading) return <Loading />
  if (!me?.user?.isSuperAdmin) return <Navigate to="/app" replace />
  const tabs = [{ id: 'overview', label: "Vue d'ensemble", icon: 'dashboard' }, { id: 'orgs', label: 'Organisations', icon: 'users' }, { id: 'users', label: 'Utilisateurs', icon: 'users' }, { id: 'scans', label: 'Moteurs et audits', icon: 'radar' }, { id: 'settings', label: 'Formules et paramètres', icon: 'settings' }, { id: 'logs', label: 'Journal', icon: 'file' }, { id: 'emails', label: 'E-mails', icon: 'bell' }]
  return (
    <div className="shell">
      <div className={'scrim' + (open ? ' open' : '')} onClick={() => setOpen(false)} />
      <aside className={'side' + (open ? ' open' : '')}>
        <Brand to="/admin" />
        <div className="navgroup">Super Administration</div>
        {tabs.map((t) => <a key={t.id} className={'nav' + (tab === t.id ? ' active' : '')} href="#" onClick={(e) => { e.preventDefault(); setTab(t.id); setOpen(false) }}><Icon name={t.icon} /><span className="lbl">{t.label}</span></a>)}
        <div className="navgroup">Retour</div>
        {me.org && <Link className="nav" to="/app"><Icon name="dashboard" /><span className="lbl">Mon espace</span></Link>}
        <div className="foot">
          <div><b>{me.user.name}</b></div>
          <div className="muted">Super Administrateur</div>
          <button className="btn ghost sm" style={{ marginTop: 10 }} onClick={toggle}>Thème : {THEME_FR[theme]}</button>
        </div>
      </aside>
      <div style={{ minWidth: 0 }}>
      <header className="topbar">
        <button className="iconbtn menu" onClick={() => setOpen(true)} aria-label="Ouvrir le menu"><Icon name="menu" /></button>
        <Brand to="/admin" />
        <div className="topbar-title">{tabs.find((t) => t.id === tab)?.label}<small>Super Administration</small></div>
        <div className="topbar-actions">
          <button className="iconbtn theme" onClick={toggle} title={`Thème : ${THEME_FR[theme]} (cliquer pour changer)`} aria-label="Changer de thème"><Icon name={themeIcon(theme)} /></button>
          <span className="userchip"><span className="avatar">{String(me.user.name ?? '?').slice(0, 2).toUpperCase()}</span><span className="who"><b>{me.user.name}</b><small>Super Administrateur</small></span></span>
        </div>
      </header>
      <main className="main">
        <div className="note warn">Tout accès aux données d'une organisation cliente doit être justifié : le motif est enregistré dans le journal avec votre identité.</div>
        {tab === 'overview' && <Overview />}
        {tab === 'orgs' && <Organizations />}
        {tab === 'users' && <Users />}
        {tab === 'scans' && <Engines />}
        {tab === 'settings' && <PlatformSettings />}
        {tab === 'logs' && <Logs />}
        {tab === 'emails' && <Emails />}
        <FooterLight />
      </main>
      </div>
    </div>
  )
}

function Overview() {
  const { data: d, error } = useLoad<any>(() => api('/admin/overview'))
  if (error) return <Err msg={error} />
  if (!d) return <Loading />
  const e = d.engines
  return (
    <>
      <PageHead title="Vue d'ensemble de la plateforme" />
      <div className="grid g5" style={{ marginBottom: 16 }}>
        <div className="stat"><b>{d.counts.orgs}</b><span>Organisations</span></div>
        <div className="stat"><b>{d.counts.users}</b><span>Utilisateurs</span></div>
        <div className="stat"><b>{d.counts.apps}</b><span>Applications</span></div>
        <div className="stat"><b>{d.counts.scansMonth}</b><span>Audits sur 30 jours <small className="muted">· {d.counts.scans} au total</small></span></div>
        <div className="stat"><b style={{ color: d.counts.running ? 'var(--accent)' : undefined }}>{d.counts.running}</b><span>Audits en cours</span></div>
        <div className="stat"><b style={{ color: d.counts.failed ? 'var(--danger)' : undefined }}>{d.counts.failed}</b><span>Audits en échec (30 j)</span></div>
        <div className="stat"><b>{d.counts.findings}</b><span>Constats créés (30 j)</span></div>
        <div className="stat"><b style={{ color: d.counts.incidents ? 'var(--danger)' : undefined }}>{d.counts.incidents}</b><span>Incidents ouverts</span></div>
      </div>
      <div className="grid g2">
        <div className="card"><h2>Audits par jour (30 j)</h2><BarChart labels={d.usage.map((u: any) => u.day.slice(5))} values={d.usage.map((u: any) => u.scans)} formatLabel={(l) => l.replace('-', '/')} /></div>
        <div className="card"><h2>Requêtes émises par les moteurs (30 j)</h2><BarChart labels={d.usage.map((u: any) => u.day.slice(5))} values={d.usage.map((u: any) => u.requests)} color="var(--chart2)" formatLabel={(l) => l.replace('-', '/')} /></div>
        <div className="card">
          <h2>Répartition</h2>
          <table><tbody>
            {Object.entries(d.byPlan).map(([k, v]: any) => <tr key={k}><td>Formule {k}</td><td><b>{v}</b></td></tr>)}
            {Object.entries(d.byStatus).map(([k, v]: any) => <tr key={k}><td>Statut {k}</td><td><b>{v}</b></td></tr>)}
            {Object.entries(d.emails).map(([k, v]: any) => <tr key={k}><td>E-mails {k}</td><td><b>{v}</b></td></tr>)}
          </tbody></table>
        </div>
        <div className="card">
          <h2>Moteurs et infrastructure</h2>
          <table><tbody>
            <tr><td>File de tâches</td><td><b>{e.queue.backend === 'redis' ? 'Redis / BullMQ' : 'Mémoire (processus unique)'}</b> — {e.queue.waiting} en attente, {e.queue.active} actif(s), {e.queue.failed} en échec</td></tr>
            <tr><td>Navigateurs Playwright</td><td><b>{e.browsers.length ? e.browsers.join(', ') : 'aucun'}</b>{!e.playwright && ' (désactivé)'}</td></tr>
            <tr><td>Base de données</td><td><b>{e.db}</b></td></tr>
            <tr><td>Courrier</td><td><b>{e.mail === 'smtp' ? 'SMTP' : 'Journal (pas de SMTP)'}</b></td></tr>
            <tr><td>Paiement</td><td><b>{e.billing === 'stripe' ? 'Stripe' : 'Démonstration'}</b></td></tr>
            <tr><td>Cibles internes</td><td><b>{e.allowPrivateTargets ? 'AUTORISÉES (laboratoire)' : 'bloquées'}</b></td></tr>
            <tr><td>Processus</td><td className="small">Node {e.node} · {e.env} · {Math.round(e.uptimeSec / 60)} min · {e.memoryMb} Mo</td></tr>
          </tbody></table>
        </div>
      </div>
    </>
  )
}

function Organizations() {
  const [q, setQ] = useState('')
  const list = useLoad<any[]>(() => api(`/admin/organizations?q=${encodeURIComponent(q)}`), [q])
  const [open, setOpen] = useState<any>(null)
  return (
    <>
      <PageHead title="Organisations"><input placeholder="Rechercher" value={q} onChange={(e) => setQ(e.target.value)} /></PageHead>
      <Err msg={list.error} />
      <div className="card">
        {!list.data ? <Loading /> : list.data.length === 0 ? <Empty>Aucune organisation.</Empty> : (
          <div className="tablewrap"><table>
            <thead><tr><th>Organisation</th><th>Formule</th><th>Statut</th><th>Membres</th><th>Applications</th><th>Audits / mois</th><th>Critiques+élevés</th><th>Créée</th><th></th></tr></thead>
            <tbody>
              {list.data.map((o) => (
                <tr key={o.id}>
                  <td><b>{o.name}</b>{o.overrides && <span className="badge" style={{ marginLeft: 6 }}>quotas perso.</span>}</td>
                  <td>{o.plan}<div className="muted small">{o.subscriptionStatus}</div></td>
                  <td><span className={`badge ${o.status === 'ACTIVE' ? 'ok' : 'bad'}`}>{o.status}</span></td>
                  <td>{o.members}</td><td>{o.apps}</td><td>{o.scansMonth}</td>
                  <td>{o.highOpen ? <span className="badge bad">{o.highOpen}</span> : 0}</td>
                  <td className="muted small">{fmtDate(o.createdAt)}</td>
                  <td><button className="btn ghost sm" onClick={() => setOpen(o)}>Gérer</button></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
      {open && <OrgModal o={open} onClose={() => { setOpen(null); list.reload() }} />}
    </>
  )
}

function OrgModal({ o, onClose }: { o: any; onClose: () => void }) {
  const act = useAction()
  const [reason, setReason] = useState('')
  const [d, setD] = useState<any>(null)
  const [f, setF] = useState<any>({ status: o.status, plan: o.plan, planOverrides: {} })
  const [ok, setOk] = useState('')
  const load = async () => act.run(async () => { const r = await api(`/admin/organizations/${o.id}?reason=${encodeURIComponent(reason)}`); setD(r); setF({ status: r.status, plan: r.plan, planOverrides: r.planOverrides }) })
  const save = async () => { if (await act.run(() => api(`/admin/organizations/${o.id}`, { method: 'PATCH', body: { ...f, reason } }))) setOk('Modifications enregistrées.') }
  return (
    <Modal title={`Organisation — ${o.name}`} onClose={onClose} wide>
      <Err msg={act.error} /><Ok msg={ok} />
      <div className="row" style={{ alignItems: 'flex-end' }}>
        <label className="f" style={{ flexGrow: 3 }}>Motif de l'accès (journalisé)<input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="ex. : ticket support #123, vérification de facturation" /></label>
        <button className="btn" disabled={reason.length < 5 || act.busy} onClick={load}>Ouvrir le dossier</button>
      </div>
      {d && (
        <>
          <h3 style={{ marginTop: 16 }}>Statut et formule</h3>
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <label className="f">Statut<select value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}><option value="ACTIVE">ACTIVE</option><option value="SUSPENDED">SUSPENDED (sessions révoquées)</option></select></label>
            <label className="f">Formule<select value={f.plan} onChange={(e) => setF({ ...f, plan: e.target.value })}>{['STARTER', 'PROFESSIONAL', 'BUSINESS'].map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
            <button className="btn" disabled={act.busy} onClick={save}>Enregistrer</button>
          </div>
          <h3 style={{ marginTop: 14 }}>Quotas personnalisés (vide = valeur de la formule)</h3>
          <div className="row">
            {['apps', 'members', 'scansPerMonth', 'concurrent', 'historyDays', 'minMonitorInterval', 'loadVus', 'loadSeconds'].map((k) => (
              <label key={k} className="f" style={{ maxWidth: 150 }}>{k}<input type="number" value={f.planOverrides[k] ?? ''} placeholder={String(d.effectivePlan[k])} onChange={(e) => setF({ ...f, planOverrides: { ...f.planOverrides, [k]: e.target.value === '' ? null : Number(e.target.value) } })} /></label>
            ))}
            <label className="chk" style={{ alignSelf: 'flex-end' }}><input type="checkbox" checked={f.planOverrides.api ?? d.effectivePlan.api} onChange={(e) => setF({ ...f, planOverrides: { ...f.planOverrides, api: e.target.checked } })} />Module API</label>
            <label className="chk" style={{ alignSelf: 'flex-end' }}><input type="checkbox" checked={f.planOverrides.activeScans ?? d.effectivePlan.activeScans} onChange={(e) => setF({ ...f, planOverrides: { ...f.planOverrides, activeScans: e.target.checked } })} />Contrôles actifs</label>
          </div>
          <h3 style={{ marginTop: 14 }}>Membres ({d.members.length})</h3>
          <table><tbody>{d.members.map((m: any) => <tr key={m.id}><td>{m.user.name}</td><td className="muted small">{m.user.email}</td><td><span className="badge">{m.role}</span></td><td className="small">{m.user.totpEnabled ? '2FA' : ''}</td><td className="muted small">{m.user.lastLoginAt ? ago(m.user.lastLoginAt) : 'jamais connecté'}</td></tr>)}</tbody></table>
          <h3 style={{ marginTop: 14 }}>Projets et applications</h3>
          {d.projects.map((p: any) => <div key={p.id} className="small" style={{ marginBottom: 6 }}><b>{p.name}</b>{p.archived && ' (archivé)'} : {p.applications.map((a: any) => `${a.name} [${a.environment}${a.authorized ? ', autorisée' : ''}${a.monitoring ? ', surveillée' : ''}]`).join(' · ') || 'aucune application'}</div>)}
          <h3 style={{ marginTop: 14 }}>Derniers audits</h3>
          <table><tbody>{d.scans.map((s: any) => <tr key={s.id}><td className="muted small">{fmt(s.createdAt)}</td><td>{s.app}</td><td><span className="badge">{SCAN_FR[s.status]}</span></td><td>{s.score ?? '—'}</td><td className="small muted">{s.error}</td></tr>)}</tbody></table>
          <h3 style={{ marginTop: 14 }}>Journal récent</h3>
          <table><tbody>{d.logs.slice(0, 20).map((l: any) => <tr key={l.id}><td className="muted small">{fmt(l.createdAt)}</td><td><span className="badge">{l.action}</span></td><td className="small">{l.detail}</td></tr>)}</tbody></table>
        </>
      )}
    </Modal>
  )
}

function Users() {
  const [q, setQ] = useState('')
  const list = useLoad<any[]>(() => api(`/admin/users?q=${encodeURIComponent(q)}`), [q])
  const act = useAction()
  const patch = async (id: string, body: any) => { if (await act.run(() => api(`/admin/users/${id}`, { method: 'PATCH', body }))) list.reload() }
  return (
    <>
      <PageHead title="Utilisateurs"><input placeholder="Rechercher (nom, e-mail)" value={q} onChange={(e) => setQ(e.target.value)} /></PageHead>
      <Err msg={list.error || act.error} />
      <div className="card">
        {!list.data ? <Loading /> : (
          <div className="tablewrap"><table>
            <thead><tr><th>Utilisateur</th><th>Organisations</th><th>Sécurité</th><th>Dernière connexion</th><th></th></tr></thead>
            <tbody>
              {list.data.map((u) => (
                <tr key={u.id}>
                  <td><b>{u.name}</b> {u.isSuperAdmin && <span className="badge run">Super Admin</span>}<div className="muted small">{u.email}</div></td>
                  <td className="small">{u.orgs.join(', ') || <span className="muted">aucune</span>}</td>
                  <td className="small">{u.totpEnabled && <span className="badge ok">2FA</span>} {!u.emailVerified && <span className="badge bad">e-mail non confirmé</span>} {u.lockedUntil && new Date(u.lockedUntil) > new Date() && <span className="badge bad">bloqué ({u.failedLogins} échecs)</span>}</td>
                  <td className="muted small">{u.lastLoginAt ? ago(u.lastLoginAt) : 'jamais'}</td>
                  <td><div className="row" style={{ justifyContent: 'flex-end' }}>
                    {u.lockedUntil && new Date(u.lockedUntil) > new Date() && <button className="btn ghost sm" onClick={() => patch(u.id, { unlock: true })}>Débloquer</button>}
                    <button className="btn ghost sm" onClick={() => window.confirm('Révoquer toutes les sessions de cet utilisateur ?') && patch(u.id, { revokeSessions: true })}>Révoquer sessions</button>
                    {u.totpEnabled && <button className="btn ghost sm" onClick={() => window.confirm('Réinitialiser la 2FA (après vérification d\'identité) ?') && patch(u.id, { reset2fa: true })}>Réinitialiser 2FA</button>}
                    <button className="btn ghost sm" onClick={() => window.confirm(`${u.isSuperAdmin ? 'Retirer' : 'Accorder'} le rôle Super Administrateur ?`) && patch(u.id, { isSuperAdmin: !u.isSuperAdmin })}>{u.isSuperAdmin ? 'Retirer Super Admin' : 'Promouvoir'}</button>
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </>
  )
}

function Engines() {
  const list = useLoad<any[]>(() => api('/admin/scans'))
  const act = useAction()
  return (
    <>
      <PageHead title="Moteurs et audits récents" sub="Audits en cours et des dernières 24 heures, toutes organisations confondues."><button className="btn ghost" onClick={() => list.reload()}>Actualiser</button></PageHead>
      <Err msg={list.error || act.error} />
      <div className="card">
        {!list.data ? <Loading /> : list.data.length === 0 ? <Empty>Aucun audit récent.</Empty> : (
          <div className="tablewrap"><table>
            <thead><tr><th>Organisation</th><th>Application</th><th>Modules</th><th>État</th><th>Requêtes</th><th>Durée</th><th></th></tr></thead>
            <tbody>
              {list.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.org}</td>
                  <td><b>{s.app}</b><div className="muted small mono">{s.url}</div></td>
                  <td className="small">{s.modules} · {s.profile}</td>
                  <td><span className={`badge ${s.status === 'DONE' ? 'ok' : s.status === 'FAILED' ? 'bad' : s.status === 'RUNNING' ? 'run' : ''}`}>{SCAN_FR[s.status]}</span>{s.status === 'RUNNING' && <div className="muted small">{s.progress} % — {s.stage}</div>}{s.error && <div className="small" style={{ color: 'var(--danger)' }}>{s.error}</div>}</td>
                  <td>{s.requestsMade}</td>
                  <td className="muted small">{s.startedAt && s.finishedAt ? `${Math.round((new Date(s.finishedAt).getTime() - new Date(s.startedAt).getTime()) / 1000)} s` : s.startedAt ? ago(s.startedAt) : '—'}</td>
                  <td>{['QUEUED', 'RUNNING'].includes(s.status) && <button className="btn danger sm" onClick={() => { const r = window.prompt("Motif de l'annulation :"); if (r) act.run(() => api(`/admin/scans/${s.id}/cancel`, { method: 'POST', body: { reason: r } })).then(() => list.reload()) }}>Annuler</button>}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </>
  )
}

function PlatformSettings() {
  const s = useLoad<any>(() => api('/admin/settings'))
  const act = useAction()
  const [over, setOver] = useState<any>(null)
  const [reg, setReg] = useState<boolean | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [ok, setOk] = useState('')
  if (!s.data) return s.error ? <Err msg={s.error} /> : <Loading />
  const o = over ?? s.data.planOverrides
  const fields = ['label', 'apps', 'members', 'scansPerMonth', 'concurrent', 'historyDays', 'minMonitorInterval', 'loadVus', 'loadSeconds', 'priceMonthly']
  const save = async () => {
    if (await act.run(() => api('/admin/settings', { method: 'PUT', body: { planOverrides: o, registrationsOpen: reg ?? s.data.registrationsOpen, maintenanceMessage: msg ?? s.data.maintenanceMessage } }))) { setOk('Paramètres enregistrés et appliqués.'); s.reload() }
  }
  return (
    <>
      <PageHead title="Formules et paramètres globaux" sub="Les quotas des formules sont configurables ici (12.1). Vide = valeur par défaut." />
      <Err msg={act.error} /><Ok msg={ok} />
      <div className="card">
        <h2>Quotas par formule</h2>
        <div className="tablewrap"><table>
          <thead><tr><th>Champ</th>{Object.keys(s.data.defaultPlans).map((k) => <th key={k}>{k}</th>)}</tr></thead>
          <tbody>
            {fields.map((f) => (
              <tr key={f}><td className="small">{f}</td>{Object.keys(s.data.defaultPlans).map((k) => <td key={k}><input style={{ width: 110 }} type={f === 'label' ? 'text' : 'number'} placeholder={String(s.data.defaultPlans[k][f])} value={o[k]?.[f] ?? ''} onChange={(e) => setOver({ ...o, [k]: { ...(o[k] ?? {}), [f]: e.target.value === '' ? undefined : f === 'label' ? e.target.value : Number(e.target.value) } })} /></td>)}</tr>
            ))}
            {['api', 'activeScans'].map((f) => (
              <tr key={f}><td className="small">{f}</td>{Object.keys(s.data.defaultPlans).map((k) => <td key={k}><input type="checkbox" checked={o[k]?.[f] ?? s.data.defaultPlans[k][f]} onChange={(e) => setOver({ ...o, [k]: { ...(o[k] ?? {}), [f]: e.target.checked } })} /></td>)}</tr>
            ))}
            <tr><td className="small">browsers</td>{Object.keys(s.data.defaultPlans).map((k) => <td key={k} className="small">{['chromium', 'firefox', 'webkit'].map((b) => { const cur: string[] = o[k]?.browsers ?? s.data.defaultPlans[k].browsers; return <label key={b} className="chk" style={{ display: 'inline-flex', marginRight: 6 }}><input type="checkbox" checked={cur.includes(b)} onChange={(e) => setOver({ ...o, [k]: { ...(o[k] ?? {}), browsers: e.target.checked ? [...cur, b] : cur.filter((x) => x !== b) } })} />{b}</label> })}</td>)}</tr>
          </tbody>
        </table></div>
      </div>
      <div className="card">
        <h2>Plateforme</h2>
        <label className="chk"><input type="checkbox" checked={reg ?? s.data.registrationsOpen} onChange={(e) => setReg(e.target.checked)} />Inscriptions ouvertes</label>
        <label className="f" style={{ marginTop: 10 }}>Message de maintenance (affiché sur la page d'accueil, vide = aucun)<input value={msg ?? s.data.maintenanceMessage} onChange={(e) => setMsg(e.target.value)} /></label>
        <p className="muted small" style={{ marginTop: 10 }}>URL publique : {s.data.config.appUrl} · Vérification d'e-mail obligatoire pour auditer : {s.data.config.requireEmailVerification ? 'oui' : 'non'} · Super Administrateurs par environnement : {s.data.config.superAdminEmails.join(', ') || 'aucun'}</p>
        <button className="btn" disabled={act.busy} onClick={save}>Enregistrer</button>
      </div>
    </>
  )
}

function Logs() {
  const [q, setQ] = useState('')
  const logs = useLoad<any[]>(() => api(`/admin/audit-logs?q=${encodeURIComponent(q)}`), [q])
  return (
    <>
      <PageHead title="Journal de la plateforme" sub="Toutes organisations, y compris les accès du Super Administrateur (admin.*)."><input placeholder="Filtrer" value={q} onChange={(e) => setQ(e.target.value)} /></PageHead>
      <Err msg={logs.error} />
      <div className="card">
        {!logs.data ? <Loading /> : (
          <div className="tablewrap"><table>
            <thead><tr><th>Date</th><th>Organisation</th><th>Action</th><th>Détail</th><th>IP</th></tr></thead>
            <tbody>{logs.data.map((l) => <tr key={l.id}><td className="muted small" style={{ whiteSpace: 'nowrap' }}>{fmt(l.createdAt)}</td><td className="small">{l.org ?? <span className="muted">—</span>}</td><td><span className={`badge ${l.action.startsWith('admin.') ? 'run' : ''}`}>{l.action}</span></td><td className="small">{l.detail}</td><td className="muted small">{l.ip}</td></tr>)}</tbody>
          </table></div>
        )}
      </div>
    </>
  )
}

function Emails() {
  const list = useLoad<any[]>(() => api('/admin/emails'))
  const [open, setOpen] = useState<any>(null)
  return (
    <>
      <PageHead title="Boîte d'envoi" sub="Trace de chaque e-mail. Sans SMTP, les messages sont journalisés ici (statut LOGGED) au lieu d'être envoyés." />
      <Err msg={list.error} />
      <div className="card">
        {!list.data ? <Loading /> : list.data.length === 0 ? <Empty>Aucun e-mail.</Empty> : (
          <table><tbody>{list.data.map((m) => <tr key={m.id}><td className="muted small">{fmt(m.createdAt)}</td><td><b>{m.subject}</b><div className="muted small">{m.to}</div></td><td><span className={`badge ${m.status === 'SENT' ? 'ok' : m.status === 'FAILED' ? 'bad' : ''}`}>{m.status}</span>{m.error && <div className="small" style={{ color: 'var(--danger)' }}>{m.error}</div>}</td><td><button className="btn ghost sm" onClick={() => setOpen(m)}>Voir</button></td></tr>)}</tbody></table>
        )}
      </div>
      {open && <Modal title={open.subject} onClose={() => setOpen(null)}><p className="muted small">À : {open.to}</p><pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>{open.text}</pre></Modal>}
    </>
  )
}
