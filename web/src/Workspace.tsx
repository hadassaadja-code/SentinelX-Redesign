import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, ENV_FR, SEVS, SEV_FR, SEV_VAR, MODULE_FR, fmt, fmtDate, ago } from './api'
import { Empty, Err, Icon, Loading, Modal, PageHead, CopyBtn, Ok, Skeleton, useAction, useAuth, useCan, useLoad } from './ui'
import { HBars, LineChart, BarChart } from './charts'

// ================= TABLEAU DE BORD (10.1) =================
export function Dashboard() {
  const { me } = useAuth()
  const { data: d, error } = useLoad(() => api('/dashboard'))
  if (error) return <Err msg={error} />
  if (!d) return <><PageHead title="Tableau de bord" /><Skeleton kind="cards" n={5} /><div style={{ height: 16 }} /><Skeleton kind="table" /></>
  const steps = [
    { label: 'Créer un projet', done: d.projects > 0, to: '/app/projects' },
    { label: 'Ajouter une application', done: d.applications > 0, to: '/app/projects' },
    { label: "Déclarer l'autorisation d'audit", done: d.apps.some((a: any) => a.authorized), to: '/app/projects' },
    { label: 'Lancer un premier audit', done: d.scans > 0, to: '/app/scans' },
    { label: 'Activer le monitoring', done: d.apps.some((a: any) => a.monitoring), to: '/app/monitoring' },
  ]
  const onboarding = steps.some((s) => !s.done)
  return (
    <>
      <PageHead title="Tableau de bord" sub={`${me.org.name} — formule ${me.plan.label}`}>
        <Link className="btn" to="/app/scans">Lancer un audit</Link>
      </PageHead>
      {onboarding && (
        <div className="card">
          <h2>Premiers pas</h2>
          <div className="checklist">
            {steps.map((s, i) => <Link key={s.label} to={s.to} className={s.done ? 'done' : ''}><span className="n">{s.done ? <Icon name="check" size={13} /> : i + 1}</span>{s.label}</Link>)}
          </div>
        </div>
      )}
      <div className="grid g5" style={{ marginBottom: 16 }}>
        <div className="stat"><span className="ic"><Icon name="folder" /></span><b>{d.projects}</b><span>Projets</span></div>
        <div className="stat"><span className="ic"><Icon name="globe" /></span><b>{d.applications}</b><span>Applications</span></div>
        <div className="stat"><span className="ic"><Icon name="radar" /></span><b>{d.scans}</b><span>Audits réalisés <small className="muted">· {d.scansThisWeek} cette semaine</small></span></div>
        <div className="stat"><span className="ic"><Icon name="bug" /></span><b>{d.openFindings}</b><span>Constats ouverts</span></div>
        <div className="stat"><b style={{ color: d.severities.CRITICAL ? 'var(--crit)' : undefined }}>{d.severities.CRITICAL}</b><span>Critiques</span></div>
        <div className="stat"><b>{d.qaRate != null ? d.qaRate + ' %' : '—'}</b><span>Taux de réussite QA</span></div>
        <div className="stat"><b>{d.securityScore ?? '—'}</b><span>Score de sécurité</span></div>
        <div className="stat"><span className="ic"><Icon name="gauge" /></span><b>{d.perfScore ?? '—'}</b><span>Score de performance</span></div>
        <div className="stat"><b style={{ color: d.openIncidents ? 'var(--danger)' : undefined }}>{d.openIncidents}</b><span>Incidents ouverts</span></div>
        <div className="stat"><span className="ic"><Icon name="clock" /></span><b>{d.mttrDays != null ? `${d.mttrDays} j` : '—'}</b><span>Délai moyen de correction <small className="muted">· {d.fixedFindings} corrigé(s) / 30 j</small></span></div>
      </div>
      <div className="grid g2">
        <div className="card">
          <h2>Constats ouverts par gravité</h2>
          <HBars items={SEVS.map((s) => ({ label: SEV_FR[s], value: d.severities[s], color: `var(--${SEV_VAR[s]})` }))} />
          <div className="row" style={{ marginTop: 10 }}>
            {Object.entries(d.modules).map(([m, n]: any) => <span key={m} className="badge">{MODULE_FR[m] ?? m} : {n}</span>)}
            <Link to="/app/findings?open=true" className="small" style={{ marginLeft: 'auto' }}>Voir toutes les vulnérabilités</Link>
          </div>
        </div>
        <div className="card">
          <h2>Évolution du score global</h2>
          {d.trend.length === 0 ? <Empty>Aucun audit terminé pour l'instant.</Empty> : (
            <LineChart labels={d.trend.map((t: any) => fmtDate(t.date))} series={[{ name: 'Score global', values: d.trend.map((t: any) => t.score) }]} max={100} />
          )}
          <div className="muted small">Les {d.trend.length} derniers audits terminés, du plus ancien au plus récent (score sur 100).</div>
        </div>
        <div className="card">
          <h2>Nouveaux constats sur 30 jours</h2>
          <BarChart labels={d.findingsPerDay.map((x: any) => x.date.slice(5))} values={d.findingsPerDay.map((x: any) => x.n)} formatLabel={(l) => l.replace('-', '/')} />
        </div>
        <div className="card">
          <h2>État des applications</h2>
          {d.apps.length === 0 ? <Empty>Aucune application enregistrée.</Empty> : (
            <div className="tablewrap"><table>
              <thead><tr><th>Application</th><th>Disponibilité</th><th>Dernier score</th><th>Critiques / élevés</th><th></th></tr></thead>
              <tbody>
                {d.apps.map((a: any) => (
                  <tr key={a.id}>
                    <td><span className={`dot ${a.lastStatus}`} /><b>{a.name}</b><div className="muted small">{ENV_FR[a.environment]}{!a.authorized && ' · non autorisée'}{a.verifiedAt && ' · propriété vérifiée'}</div></td>
                    <td className="small">{a.monitoring ? (a.uptime24h != null ? `${a.uptime24h} % / 24 h` : 'en attente') : <span className="muted">non surveillée</span>}{a.lastResponseMs != null && <div className="muted">{a.lastResponseMs} ms</div>}</td>
                    <td><b>{a.lastScore ?? '—'}</b></td>
                    <td>{a.highOpen ? <span className="badge bad">{a.highOpen}</span> : <span className="badge ok">0</span>}</td>
                    <td><Link to={`/app/scans?app=${a.id}`} className="small">Auditer</Link></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>
        <div className="card">
          <h2>Derniers incidents</h2>
          {d.incidents.length === 0 ? <Empty>Aucun incident enregistré.</Empty> : (
            <table><tbody>
              {d.incidents.map((i: any) => (
                <tr key={i.id}>
                  <td>{i.title}</td>
                  <td><span className={`badge ${i.status === 'RESOLVED' ? 'ok' : 'bad'}`}>{i.status === 'OPEN' ? 'Ouvert' : i.status === 'ACKNOWLEDGED' ? 'Pris en charge' : 'Résolu'}</span></td>
                  <td className="muted small" style={{ whiteSpace: 'nowrap' }}>{ago(i.startedAt)}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
        <div className="card">
          <h2>Consommation de la formule</h2>
          {[['Applications', d.usage.apps, d.plan.apps], ['Collaborateurs', d.usage.members, d.plan.members], ['Audits ce mois-ci', d.usage.scansThisMonth, d.plan.scansPerMonth]].map(([l, u, m]: any) => (
            <div key={l} style={{ marginBottom: 10 }}>
              <div className="row between small"><span>{l}</span><b>{u} / {m}</b></div>
              <div className="bar" style={{ marginTop: 4 }}><i style={{ width: `${Math.min(100, (u / m) * 100)}%`, background: u >= m ? 'var(--danger)' : undefined }} /></div>
            </div>
          ))}
          <Link to="/app/billing" className="small">Gérer l'abonnement</Link>
        </div>
      </div>
    </>
  )
}

// ================= PROJETS ET APPLICATIONS =================
export function Projects() {
  const can = useCan()
  const { reload: reloadMe } = useAuth()
  const { data, error, reload } = useLoad<any[]>(() => api('/projects'))
  const members = useLoad<any[]>(() => api('/members'))
  const act = useAction()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [techLeadId, setTechLeadId] = useState('')
  const refresh = () => Promise.all([reload(), reloadMe()])
  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/projects', { method: 'POST', body: { name, description, techLeadId } }), { success: 'Projet créé.' })) {
      setName('')
      setDescription('')
      refresh()
    }
  }
  return (
    <>
      <PageHead title="Projets et applications" sub="Organisez vos applications par projet et par environnement, déclarez les autorisations d'audit et le périmètre." />
      <Err msg={error || act.error} />
      {can.manage && (
        <form className="card row" onSubmit={create}>
          <label className="f">Nom du projet<input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Site vitrine" /></label>
          <label className="f" style={{ flexGrow: 2 }}>Description (facultatif)<input value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          <label className="f">Responsable technique<select value={techLeadId} onChange={(e) => setTechLeadId(e.target.value)}><option value="">—</option>{(members.data ?? []).map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label>
          <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy} style={{ alignSelf: 'flex-end' }}><Icon name="plus" />Créer le projet</button>
        </form>
      )}
      {!data ? <div className="card"><Skeleton kind="table" /></div> : data.length === 0 ? <div className="card"><Empty icon="folder">Aucun projet. Créez-en un pour enregistrer vos applications.</Empty></div> : data.map((p) => <ProjectCard key={p.id} p={p} members={members.data ?? []} refresh={refresh} />)}
    </>
  )
}

function ProjectCard({ p, members, refresh }: { p: any; members: any[]; refresh: () => any }) {
  const can = useCan()
  const act = useAction()
  const nav = useNavigate()
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<any>(null)
  const [authFor, setAuthFor] = useState<any>(null)
  const [stats, setStats] = useState<any>(null)
  const [edit, setEdit] = useState(false)
  const [pf, setPf] = useState({ name: p.name, description: p.description, techLeadId: p.techLeadId ?? '' })
  const [f, setF] = useState({ name: '', url: 'https://', type: 'WEB', environment: 'PRODUCTION', openapiUrl: '' })
  const call = async (fn: () => Promise<any>) => {
    if (await act.run(fn)) refresh()
  }
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await act.run(() => api('/applications', { method: 'POST', body: { ...f, projectId: p.id } }), { success: "Application ajoutée. Déclarez maintenant son autorisation d'audit." })) {
      setAdding(false)
      setF({ name: '', url: 'https://', type: 'WEB', environment: 'PRODUCTION', openapiUrl: '' })
      refresh()
    }
  }
  const remove = async () => {
    const confirm = p.archived ? p.name : window.prompt(`Suppression contrôlée : saisissez le nom exact du projet (« ${p.name} ») pour confirmer. Toutes ses applications et résultats seront supprimés.`)
    if (confirm !== p.name) return
    act.run(() => api(`/projects/${p.id}`, { method: 'DELETE', body: { confirm } }), { success: 'Projet supprimé.' }).then((ok) => ok && refresh())
  }
  return (
    <div className="card" style={{ opacity: p.archived ? 0.65 : 1 }}>
      <div className="row between">
        <div>
          {edit ? (
            <form className="row" onSubmit={async (e) => { e.preventDefault(); if (await act.run(() => api(`/projects/${p.id}`, { method: 'PATCH', body: pf }))) { setEdit(false); refresh() } }}>
              <input value={pf.name} onChange={(e) => setPf({ ...pf, name: e.target.value })} required />
              <input value={pf.description} onChange={(e) => setPf({ ...pf, description: e.target.value })} placeholder="Description" />
              <select value={pf.techLeadId} onChange={(e) => setPf({ ...pf, techLeadId: e.target.value })}><option value="">Responsable technique</option>{members.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}</select>
              <button className="btn sm">Enregistrer</button><button type="button" className="btn ghost sm" onClick={() => setEdit(false)}>Annuler</button>
            </form>
          ) : (
            <>
              <h2 style={{ marginBottom: 2 }}>{p.name} {p.archived && <span className="badge">Archivé</span>}</h2>
              <div className="muted small">{p.description}{p.techLead && <> · Responsable technique : <b>{p.techLead}</b></>} · {p.applications.length} application(s)</div>
            </>
          )}
        </div>
        <div className="row">
          <button className="btn ghost sm" onClick={async () => setStats(stats ? null : await api(`/projects/${p.id}/stats`))}>{stats ? 'Masquer les statistiques' : 'Statistiques'}</button>
          {can.manage && !edit && (
            <>
              {!p.archived && <button className="btn sm" onClick={() => setAdding(!adding)}><Icon name="plus" />Ajouter une application</button>}
              <button className="btn ghost sm" onClick={() => setEdit(true)}>Modifier</button>
              <button className="btn ghost sm" onClick={() => call(() => api(`/projects/${p.id}`, { method: 'PATCH', body: { archived: !p.archived } }))}>{p.archived ? 'Désarchiver' : 'Archiver'}</button>
              {can.admin && <button className="btn danger sm" onClick={remove}>Supprimer</button>}
            </>
          )}
        </div>
      </div>
      <Err msg={act.error} />
      {stats && (
        <div className="grid g5" style={{ margin: '12px 0' }}>
          <div className="stat"><b>{stats.scans}</b><span>Audits</span></div>
          <div className="stat"><b>{stats.avgScore ?? '—'}</b><span>Score moyen (10 derniers)</span></div>
          <div className="stat"><b style={{ color: stats.findings.CRITICAL ? 'var(--crit)' : undefined }}>{stats.findings.CRITICAL ?? 0}</b><span>Critiques ouverts</span></div>
          <div className="stat"><b>{(stats.findings.HIGH ?? 0) + (stats.findings.MEDIUM ?? 0)}</b><span>Élevés + moyens ouverts</span></div>
          <div className="stat"><b>{stats.incidents}</b><span>Incidents</span></div>
        </div>
      )}
      {adding && (
        <form className="row subform" onSubmit={add}>
          <label className="f">Nom<input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="f" style={{ flexGrow: 2 }}>URL principale<input required type="url" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} /></label>
          <label className="f">Type<select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}><option value="WEB">Application web</option><option value="API">API</option></select></label>
          <label className="f">Environnement<select value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>{Object.keys(ENV_FR).map((k) => <option key={k} value={k}>{ENV_FR[k]}</option>)}</select></label>
          {f.type === 'API' && <label className="f" style={{ flexGrow: 2 }}>URL de la spécification OpenAPI<input type="url" value={f.openapiUrl} onChange={(e) => setF({ ...f, openapiUrl: e.target.value })} placeholder="https://api.exemple.com/openapi.json" /></label>}
          <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy} style={{ alignSelf: 'flex-end' }}>Enregistrer</button>
        </form>
      )}
      {p.applications.length === 0 ? <Empty>Aucune application dans ce projet.</Empty> : (
        <div className="tablewrap">
          <table style={{ marginTop: 10 }}>
            <thead><tr><th>Application</th><th>Environnement</th><th>Autorisation d'audit</th><th>Surveillance</th><th></th></tr></thead>
            <tbody>
              {p.applications.map((a: any) => (
                <tr key={a.id}>
                  <td><b>{a.name}</b> <span className="badge">{a.type}</span>{a.verifiedAt && <span className="badge ok" title={`Propriété vérifiée (${a.verificationMethod}) le ${fmt(a.verifiedAt)}`}>Vérifiée</span>}<div className="muted small mono">{a.url}</div>{a.owner && <div className="muted small">Propriétaire technique : {a.owner}</div>}</td>
                  <td><span className="badge">{ENV_FR[a.environment]}</span></td>
                  <td>
                    {a.authorized ? (
                      <>
                        <span className={`badge ${a.authorizationExpires && new Date(a.authorizationExpires) < new Date() ? 'bad' : 'ok'}`}>{a.authorizationExpires && new Date(a.authorizationExpires) < new Date() ? 'Expirée' : `Autorisée le ${fmtDate(a.authorizedAt)}`}</span>
                        <div className="muted small">Périmètre : {a.authorizedScopes.split(',').map((s: string) => ({ PASSIVE: 'passif', ACTIVE: 'actif', LOAD: 'charge' } as any)[s]).join(', ')}{a.authorizationExpires && ` · jusqu'au ${fmtDate(a.authorizationExpires)}`}</div>
                      </>
                    ) : <span className="badge bad">Non déclarée</span>}
                  </td>
                  <td className="small">{a.monitoring ? `Toutes les ${a.monitorInterval} min` : <span className="muted">Inactive</span>}{a.scheduleHours > 0 && <div className="muted">Audit {a.scheduleHours === 24 ? 'quotidien' : 'hebdomadaire'}</div>}</td>
                  <td>
                    <div className="row" style={{ justifyContent: 'flex-end' }}>
                      {can.has('application.authorize') && <button className="btn sm ghost" onClick={() => setAuthFor(a)}>{a.authorized ? 'Autorisation' : "Déclarer l'autorisation"}</button>}
                      {a.authorized && can.operate && <button className="btn sm" onClick={() => nav(`/app/scans?app=${a.id}`)}>Auditer</button>}
                      {can.manage && <button className="btn ghost sm" onClick={() => setEditing(a)}>Configurer</button>}
                      {can.manage && <button className="btn danger sm" onClick={() => window.confirm(`Supprimer l'application « ${a.name} » et ses résultats ?`) && call(() => api(`/applications/${a.id}`, { method: 'DELETE' }))}>Supprimer</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {authFor && <AuthorizeModal a={authFor} onClose={() => setAuthFor(null)} refresh={refresh} />}
      {editing && <AppConfigModal a={editing} members={members} onClose={() => setEditing(null)} refresh={refresh} />}
    </div>
  )
}

/** Déclaration d'autorisation (14.4) avec vérification de propriété et périmètre. */
function AuthorizeModal({ a, onClose, refresh }: { a: any; onClose: () => void; refresh: () => any }) {
  const { me } = useAuth()
  const act = useAction()
  const ver = useLoad<any>(() => api(`/applications/${a.id}/verification`), [a.id])
  const [declared, setDeclared] = useState(false)
  const [activeDeclared, setActiveDeclared] = useState(false)
  const [scopes, setScopes] = useState<string[]>(a.authorizedScopes ? a.authorizedScopes.split(',') : ['PASSIVE'])
  const [months, setMonths] = useState(12)
  const [verifyMsg, setVerifyMsg] = useState<any>(null)
  const toggle = (s: string) => setScopes(scopes.includes(s) ? scopes.filter((x) => x !== s) : [...scopes, s])
  const verify = async () => {
    setVerifyMsg(null)
    if (await act.run(async () => setVerifyMsg(await api(`/applications/${a.id}/verify`, { method: 'POST' })))) { ver.reload(); refresh() }
  }
  const needsActive = scopes.includes('ACTIVE') || scopes.includes('LOAD')
  return (
    <Modal title={`Autorisation d'audit — ${a.name}`} onClose={onClose} wide>
      <p className="muted small">Aucun audit n'est lancé sans autorisation explicite. Les contrôles actifs et tests de charge exigent une validation spécifique, et une vérification de propriété en production.</p>
      <Err msg={act.error} />
      <h3>1. Vérification de la propriété du domaine {ver.data?.verifiedAt && <span className="badge ok">Vérifiée ({ver.data.method}) le {fmtDate(ver.data.verifiedAt)}</span>}</h3>
      {ver.data && !ver.data.verifiedAt && (
        <div className="subform" style={{ display: 'block' }}>
          <p className="small">Prouvez que vous contrôlez <b>{new URL(a.url).hostname}</b> par l'une de ces méthodes, puis cliquez sur « Vérifier » :</p>
          {ver.data.methods.map((m: any) => <div key={m.id} className="small" style={{ marginBottom: 8 }}><b>{m.label}</b><div className="mono" style={{ marginTop: 2 }}>{m.instructions}</div></div>)}
          <div className="row"><CopyBtn text={`sentinelx-verify=${ver.data.token}`} label="Copier le jeton" /><button className="btn sm" disabled={act.busy} onClick={verify}>Vérifier maintenant</button></div>
          {verifyMsg && <div className={verifyMsg.ok ? 'note ok' : 'err'} style={{ marginTop: 8 }}>{verifyMsg.ok ? `Propriété vérifiée (${verifyMsg.method}). ` : 'Vérification échouée. '}{verifyMsg.detail}</div>}
        </div>
      )}
      <h3 style={{ marginTop: 16 }}>2. Périmètre autorisé</h3>
      <label className="chk"><input type="checkbox" checked disabled /><span><b>Contrôles passifs</b> — lecture seule : en-têtes, TLS, fichiers exposés, QA, mesures de performance.</span></label>
      <label className="chk"><input type="checkbox" checked={scopes.includes('ACTIVE')} onChange={() => toggle('ACTIVE')} disabled={!me.plan.activeScans} /><span><b>Contrôles actifs non destructifs</b> — réflexion de paramètres, signatures d'erreur SQL, redirections ouvertes, CORS, rafale de requêtes API.{!me.plan.activeScans && <span className="muted"> Non inclus dans la formule {me.plan.label}.</span>}</span></label>
      <label className="chk"><input type="checkbox" checked={scopes.includes('LOAD')} onChange={() => toggle('LOAD')} /><span><b>Tests de charge</b> — jusqu'à {me.plan.loadVus} utilisateurs virtuels pendant {me.plan.loadSeconds} s, arrêt automatique en cas de dégradation.</span></label>
      <label className="f" style={{ maxWidth: 240, marginTop: 10 }}>Durée de validité<select value={months} onChange={(e) => setMonths(Number(e.target.value))}>{[1, 3, 6, 12, 24].map((m) => <option key={m} value={m}>{m} mois</option>)}</select></label>
      <h3 style={{ marginTop: 16 }}>3. Déclaration</h3>
      <label className="chk">
        <input type="checkbox" checked={declared} onChange={(e) => setDeclared(e.target.checked)} />
        <span>Je déclare être propriétaire de <b>{a.url}</b> ou détenir une autorisation écrite pour la tester. Cette déclaration est enregistrée dans le journal de l'organisation avec mon identité et la date.</span>
      </label>
      {needsActive && (
        <label className="chk">
          <input type="checkbox" checked={activeDeclared} onChange={(e) => setActiveDeclared(e.target.checked)} />
          <span>J'autorise spécifiquement les <b>contrôles actifs et/ou tests de charge</b> sur cette cible et j'ai informé les équipes concernées.</span>
        </label>
      )}
      {needsActive && !a.verifiedAt && a.environment === 'PRODUCTION' && <div className="note warn">Environnement de production : la vérification de propriété est obligatoire pour les contrôles actifs et tests de charge.</div>}
      <div className="row" style={{ marginTop: 14 }}>
        <button className={'btn' + (act.busy ? ' busy' : '')} disabled={!declared || (needsActive && !activeDeclared) || act.busy} onClick={async () => { if (await act.run(() => api(`/applications/${a.id}/authorize`, { method: 'POST', body: { declaration: true, activeDeclaration: activeDeclared, scopes, months } }), { success: 'Autorisation enregistrée et journalisée.' })) { refresh(); onClose() } }}>Confirmer l'autorisation</button>
        {a.authorized && <button className="btn danger" onClick={async () => { if (window.confirm("Révoquer l'autorisation ? Le monitoring et les audits planifiés seront désactivés.") && (await act.run(() => api(`/applications/${a.id}/revoke-authorization`, { method: 'POST' })))) { refresh(); onClose() } }}>Révoquer</button>}
      </div>
    </Modal>
  )
}

/** Fiche application (4.3) : description, propriétaire, périmètre, en-têtes, planification, budget de performance, navigateurs. */
function AppConfigModal({ a, members, onClose, refresh }: { a: any; members: any[]; onClose: () => void; refresh: () => any }) {
  const { me } = useAuth()
  const act = useAction()
  const [f, setF] = useState<any>({
    name: a.name, description: a.description, url: a.url, type: a.type, environment: a.environment, technologies: a.technologies, ownerId: a.ownerId ?? '', openapiUrl: a.openapiUrl ?? '',
    allowedPaths: a.allowedPaths, excludedPaths: a.excludedPaths, maxRequestsPerScan: a.maxRequestsPerScan, perfBudgetMs: a.perfBudgetMs, browsers: a.browsers.split(','),
    scheduleHours: a.scheduleHours, scheduleModules: a.scheduleModules.split(','), headers: '',
  })
  const [saved, setSaved] = useState('')
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })
  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    const body: any = { ...f }
    delete body.headers
    if (f.headers.trim()) {
      const h: any = {}
      for (const line of f.headers.split('\n')) {
        const i = line.indexOf(':')
        if (i > 0) h[line.slice(0, i).trim()] = line.slice(i + 1).trim()
      }
      body.scanHeaders = h
    }
    if (await act.run(() => api(`/applications/${a.id}`, { method: 'PATCH', body }), { success: 'Configuration enregistrée.' })) {
      setSaved('Configuration enregistrée.')
      refresh()
    }
  }
  const toggleIn = (k: string, v: string) => setF({ ...f, [k]: f[k].includes(v) ? f[k].filter((x: string) => x !== v) : [...f[k], v] })
  return (
    <Modal title={`Configuration — ${a.name}`} onClose={onClose} wide>
      <Err msg={act.error} /><Ok msg={saved} />
      <form onSubmit={save}>
        <div className="grid g2">
          <label className="f">Nom<input required value={f.name} onChange={set('name')} /></label>
          <label className="f">URL principale<input required type="url" value={f.url} onChange={set('url')} /></label>
          <label className="f">Description<input value={f.description} onChange={set('description')} /></label>
          <label className="f">Technologies (facultatif)<input value={f.technologies} onChange={set('technologies')} placeholder="React, Node.js, PostgreSQL" /></label>
          <label className="f">Type<select value={f.type} onChange={set('type')}><option value="WEB">Application web</option><option value="API">API</option></select></label>
          <label className="f">Environnement<select value={f.environment} onChange={set('environment')}>{Object.keys(ENV_FR).map((k) => <option key={k} value={k}>{ENV_FR[k]}</option>)}</select></label>
          <label className="f">Propriétaire technique<select value={f.ownerId} onChange={set('ownerId')}><option value="">—</option>{members.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label>
          <label className="f">Spécification OpenAPI (module API)<input type="url" value={f.openapiUrl} onChange={set('openapiUrl')} placeholder="https://…/openapi.json" /></label>
        </div>
        <h3 style={{ marginTop: 14 }}>Périmètre et limites de requêtes</h3>
        <div className="grid g2">
          <label className="f">Chemins autorisés (un par ligne, vide = tout le site)<textarea rows={3} value={f.allowedPaths} onChange={set('allowedPaths')} placeholder={'/\n/api/'} /></label>
          <label className="f">Chemins exclus (un par ligne)<textarea rows={3} value={f.excludedPaths} onChange={set('excludedPaths')} placeholder={'/admin/\n/logout'} /></label>
          <label className="f">Requêtes maximum par audit<input type="number" min={20} max={2000} value={f.maxRequestsPerScan} onChange={set('maxRequestsPerScan')} /></label>
          <label className="f">Budget de performance (temps moyen, ms ; 0 = aucun)<input type="number" min={0} max={60000} value={f.perfBudgetMs} onChange={set('perfBudgetMs')} /></label>
          <label className="f" style={{ gridColumn: '1 / -1' }}>En-têtes ajoutés aux requêtes d'audit (un par ligne « Nom: valeur », chiffrés au repos{a.hasHeaders ? ', déjà configurés : laisser vide pour conserver' : ''})<textarea rows={2} value={f.headers} onChange={set('headers')} placeholder="Authorization: Bearer jeton-de-test" /></label>
        </div>
        <h3 style={{ marginTop: 14 }}>Navigateurs et planification</h3>
        <div className="row">
          {['chromium', 'firefox', 'webkit'].map((b) => <label key={b} className="chk"><input type="checkbox" checked={f.browsers.includes(b)} disabled={!me.plan.browsers.includes(b) || !me.features.browsers.includes(b)} onChange={() => toggleIn('browsers', b)} />{b}{!me.features.browsers.includes(b) && <span className="muted small"> (non installé)</span>}</label>)}
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <label className="f" style={{ maxWidth: 220 }}>Audit récurrent<select value={f.scheduleHours} onChange={(e) => setF({ ...f, scheduleHours: Number(e.target.value) })}><option value={0}>Aucun</option><option value={24}>Quotidien</option><option value={168}>Hebdomadaire</option></select></label>
          {f.scheduleHours > 0 && Object.keys(MODULE_FR).map((m) => <label key={m} className="chk" style={{ alignSelf: 'flex-end' }}><input type="checkbox" checked={f.scheduleModules.includes(m)} disabled={m === 'API' && !me.plan.api} onChange={() => toggleIn('scheduleModules', m)} />{MODULE_FR[m]}</label>)}
        </div>
        <div className="row" style={{ marginTop: 16 }}>
          <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy}>Enregistrer</button>
          <button type="button" className="btn ghost" onClick={() => act.run(() => api(`/applications/${a.id}/baseline/reset`, { method: 'POST' })).then((ok) => ok && setSaved('Capture de référence réinitialisée : le prochain audit en créera une nouvelle.'))}>Réinitialiser la capture de référence</button>
        </div>
      </form>
    </Modal>
  )
}
