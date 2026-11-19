import React, { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, CATEGORY_FR, GROUP_FR, METRIC_GROUP_FR, MODULE_FR, SCAN_FR, SEVS, SEV_FR, SEV_VAR, STATUS_FR, fmt, fmtDate } from './api'
import { Empty, Err, Icon, Loading, Modal, PageHead, Score, Sev, Skeleton, Tabs, CopyBtn, useAction, useAuth, useCan, useLoad } from './ui'
import { HBars, LineChart, Progress } from './charts'

const ScanBadge = ({ s }: { s: string }) => (
  <span className={`badge ${s === 'DONE' ? 'ok' : s === 'FAILED' ? 'bad' : s === 'CANCELED' ? '' : 'run'}`}>
    {(s === 'RUNNING' || s === 'QUEUED') && <span className="spin" style={{ width: 10, height: 10 }} />}
    {SCAN_FR[s] ?? s}
  </span>
)
const active = (s: any) => s.status === 'QUEUED' || s.status === 'RUNNING'

// ================= CAMPAGNES =================
export function Scans() {
  const can = useCan()
  const { me, reload: reloadMe } = useAuth()
  const [params] = useSearchParams()
  const scans = useLoad<any[]>(() => api('/scans'))
  const apps = useLoad<any[]>(() => api('/applications'))
  const act = useAction()
  const [appId, setAppId] = useState(params.get('app') ?? '')
  const [mods, setMods] = useState<string[]>(['QA', 'SECURITY', 'PERFORMANCE'])
  const [profile, setProfile] = useState('STANDARD')
  const [load, setLoad] = useState({ vus: 5, seconds: 15, p95Ms: 2000, errorRate: 5, paths: '', confirmLoad: false })
  const authorized = (apps.data ?? []).filter((a) => a.authorized)
  const app = authorized.find((a) => a.id === appId)

  const running = (scans.data ?? []).some(active)
  useEffect(() => {
    if (!running) return
    const t = setInterval(() => scans.reload(), 2500)
    return () => { clearInterval(t); reloadMe() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running])

  const launch = async (e: React.FormEvent) => {
    e.preventDefault()
    const body: any = { applicationId: appId, modules: mods, profile }
    if (profile === 'LOAD') Object.assign(body, { ...load, paths: load.paths.split('\n').map((p) => p.trim()).filter(Boolean) })
    if (await act.run(() => api('/scans', { method: 'POST', body }), { success: profile === 'LOAD' ? 'Test de charge lancé.' : 'Audit lancé. Suivez sa progression ci-dessous.' })) scans.reload()
  }
  const toggle = (m: string) => setMods(mods.includes(m) ? mods.filter((x) => x !== m) : [...mods, m])

  return (
    <>
      <PageHead title="Campagnes d'audit" sub="Lancez un audit sur une application autorisée et suivez son exécution en temps réel." />
      <Err msg={scans.error || apps.error || act.error} />
      {can.operate && (
        <form className="card" onSubmit={launch}>
          <h2>Nouvel audit</h2>
          {apps.data && authorized.length === 0 ? (
            <div className="note" style={{ marginBottom: 0 }}>Aucune application autorisée. <Link to="/app/projects">Ajoutez une application et déclarez votre autorisation</Link> pour pouvoir l'auditer.</div>
          ) : (
            <>
              <div className="row" style={{ alignItems: 'flex-end' }}>
                <label className="f">Application
                  <select required value={appId} onChange={(e) => setAppId(e.target.value)}>
                    <option value="">Choisir…</option>
                    {authorized.map((a) => <option key={a.id} value={a.id}>{a.name} — {a.url}</option>)}
                  </select>
                </label>
                <label className="f" style={{ maxWidth: 260 }}>Profil
                  <select value={profile} onChange={(e) => setProfile(e.target.value)}>
                    <option value="STANDARD">Standard</option>
                    <option value="DEEP">Approfondi (plus de liens et d'opérations)</option>
                    {can.has('scan.load') && <option value="LOAD">Test de charge</option>}
                  </select>
                </label>
                {profile !== 'LOAD' && (
                  <div className="row" style={{ flex: '1 1 300px' }}>
                    {Object.keys(MODULE_FR).map((m) => (
                      <label key={m} className="chk" title={m === 'API' && !me.plan.api ? `Non inclus dans la formule ${me.plan.label}` : ''}><input type="checkbox" checked={mods.includes(m)} disabled={m === 'API' && !me.plan.api} onChange={() => toggle(m)} />{MODULE_FR[m]}</label>
                    ))}
                  </div>
                )}
                <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy || !appId || (profile !== 'LOAD' && mods.length === 0) || (profile === 'LOAD' && !load.confirmLoad)}><Icon name="play" />{profile === 'LOAD' ? 'Lancer le test de charge' : "Lancer l'audit"}</button>
              </div>
              {app && app.authorizedScopes && !app.authorizedScopes.includes('ACTIVE') && profile !== 'LOAD' && <p className="muted small" style={{ margin: '8px 0 0' }}>Contrôles passifs uniquement sur cette cible (autorisation « actif » non déclarée{!me.plan.activeScans ? ` ou non incluse dans la formule ${me.plan.label}` : ''}).</p>}
              {profile === 'LOAD' && (
                <div className="subform" style={{ display: 'block' }}>
                  {app && !app.authorizedScopes.includes('LOAD') && <div className="err">Cette application n'a pas d'autorisation « test de charge ». Déclarez-la dans la fiche d'autorisation.</div>}
                  <div className="row">
                    <label className="f">Utilisateurs virtuels (max {me.plan.loadVus})<input type="number" min={1} max={me.plan.loadVus} value={load.vus} onChange={(e) => setLoad({ ...load, vus: Number(e.target.value) })} /></label>
                    <label className="f">Durée en secondes (max {me.plan.loadSeconds})<input type="number" min={5} max={me.plan.loadSeconds} value={load.seconds} onChange={(e) => setLoad({ ...load, seconds: Number(e.target.value) })} /></label>
                    <label className="f">Seuil P95 (ms)<input type="number" min={100} value={load.p95Ms} onChange={(e) => setLoad({ ...load, p95Ms: Number(e.target.value) })} /></label>
                    <label className="f">Seuil taux d'erreur (%)<input type="number" min={0} max={100} value={load.errorRate} onChange={(e) => setLoad({ ...load, errorRate: Number(e.target.value) })} /></label>
                    <label className="f" style={{ flexGrow: 2 }}>Chemins (un par ligne, défaut : /)<textarea rows={2} value={load.paths} onChange={(e) => setLoad({ ...load, paths: e.target.value })} placeholder={'/\n/produits'} /></label>
                  </div>
                  <label className="chk" style={{ marginTop: 8 }}><input type="checkbox" checked={load.confirmLoad} onChange={(e) => setLoad({ ...load, confirmLoad: e.target.checked })} /><span>Je confirme le lancement d'un test de charge sur cette cible, dans les limites de ma formule. Le test s'arrête automatiquement si la cible renvoie trop d'erreurs.</span></label>
                </div>
              )}
            </>
          )}
        </form>
      )}
      <div className="card">
        {!scans.data ? <Skeleton kind="table" n={5} /> : scans.data.length === 0 ? <Empty icon="radar">Aucun audit pour l'instant.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Application</th><th>Modules</th><th>État</th><th>Score</th><th>Constats</th><th>Date</th><th></th></tr></thead>
              <tbody>
                {scans.data.map((s) => (
                  <tr key={s.id}>
                    <td><b>{s.application.name}</b>{s.profile !== 'STANDARD' && <span className="badge" style={{ marginLeft: 6 }}>{s.profile === 'LOAD' ? 'Charge' : 'Approfondi'}</span>}{s.triggeredBy === 'SCHEDULE' && <span className="badge" style={{ marginLeft: 6 }}>Planifié</span>}<div className="muted small mono">{s.application.url}</div></td>
                    <td>{s.modules.split(',').map((m: string) => <span key={m} className="badge" style={{ marginRight: 4 }}>{MODULE_FR[m]}</span>)}</td>
                    <td style={{ minWidth: 150 }}><ScanBadge s={s.status} />{active(s) && <div style={{ marginTop: 6 }}><Progress value={s.progress} /><div className="muted small">{s.stage}</div></div>}</td>
                    <td><b>{s.score ?? '—'}</b></td>
                    <td>{(s.summary?.security?.total ?? 0) + (s.summary?.api?.total ?? 0) || (s.status === 'DONE' ? 0 : '—')}</td>
                    <td className="muted small">{fmt(s.createdAt)}</td>
                    <td><div className="row"><Link to={`/app/scans/${s.id}`}>Détail</Link>{active(s) && can.has('scan.cancel') && <button className="btn ghost sm" onClick={() => act.run(() => api(`/scans/${s.id}/cancel`, { method: 'POST' }), { success: 'Annulation demandée.' }).then(() => scans.reload())}>Annuler</button>}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// ================= CONSTAT =================
export function FindingCard({ f, children, members, onChange }: { f: any; children?: React.ReactNode; members?: any[]; onChange?: () => void }) {
  const can = useCan()
  const [open, setOpen] = useState(false)
  const [comments, setComments] = useState<any[] | null>(null)
  const [text, setText] = useState('')
  const act = useAction()
  const loadComments = async () => setComments(await api(`/findings/${f.id}/comments`))
  return (
    <div className={`finding ${f.severity}`}>
      <div className="row between">
        <div className="row"><Sev s={f.severity} /><b>{f.title}</b>{f.occurrences > 1 && <span className="badge" title={`Vu pour la première fois le ${fmt(f.firstSeenAt)}`}>×{f.occurrences}</span>}{f.category && <span className="badge">{CATEGORY_FR[f.category] ?? f.category}</span>}</div>
        <div className="row"><span className="badge">{STATUS_FR[f.status]}</span>{f.assignee && <span className="badge run">{f.assignee}</span>}<button className="btn ghost sm" onClick={() => setOpen(!open)}>{open ? 'Réduire' : 'Détail'}</button></div>
      </div>
      {open && (
        <>
          <dl>
            <dt>Description</dt><dd>{f.description}</dd>
            <dt>Ressource</dt><dd className="mono">{f.resource}</dd>
            <dt>Preuve</dt><dd className="mono">{f.evidence}</dd>
            <dt>Recommandation</dt><dd>{f.recommendation}</dd>
            {(f.cwe || f.owasp) && <><dt>Références</dt><dd>{[f.cwe, f.owasp].filter(Boolean).join(' · ')}</dd></>}
            {f.note && <><dt>Note</dt><dd>{f.note}</dd></>}
            <dt>Historique</dt><dd className="small muted">Première détection le {fmt(f.firstSeenAt)} · {f.occurrences} occurrence(s)</dd>
          </dl>
          {members && can.has('finding.update') && (
            <div className="row" style={{ marginTop: 10 }}>
              <select value={f.status} onChange={(e) => act.run(() => api(`/findings/${f.id}`, { method: 'PATCH', body: { status: e.target.value, note: e.target.value === 'FALSE_POSITIVE' ? window.prompt('Justification du faux positif :') ?? '' : undefined } }), { success: 'Statut mis à jour.' }).then((ok) => ok && onChange?.())} aria-label="Statut">
                {Object.keys(STATUS_FR).map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}
              </select>
              {can.has('finding.assign') && (
                <select value={f.assigneeId ?? ''} onChange={(e) => act.run(() => api(`/findings/${f.id}`, { method: 'PATCH', body: { assigneeId: e.target.value } }), { success: 'Affectation enregistrée.' }).then((ok) => ok && onChange?.())} aria-label="Assigner">
                  <option value="">Non assigné</option>
                  {members.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
                </select>
              )}
              <button className="btn ghost sm" onClick={() => { const n = window.prompt('Note :', f.note ?? ''); if (n != null) act.run(() => api(`/findings/${f.id}`, { method: 'PATCH', body: { note: n } })).then((ok) => ok && onChange?.()) }}>Note</button>
              <button className="btn ghost sm" onClick={() => (comments ? setComments(null) : loadComments())}>{comments ? 'Masquer les commentaires' : `Commentaires${f.comments ? ` (${f.comments})` : ''}`}</button>
            </div>
          )}
          <Err msg={act.error} />
          {comments && (
            <div className="comments">
              {comments.length === 0 && <div className="muted small">Aucun commentaire.</div>}
              {comments.map((c) => <div key={c.id} className="comment"><b>{c.userName}</b> <span className="muted small">{fmt(c.createdAt)}</span><div>{c.text}</div></div>)}
              {can.has('finding.comment') && (
                <form className="row" onSubmit={async (e) => { e.preventDefault(); if (await act.run(() => api(`/findings/${f.id}/comments`, { method: 'POST', body: { text } }))) { setText(''); loadComments() } }}>
                  <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Ajouter un commentaire" style={{ flex: 1 }} required />
                  <button className="btn sm">Publier</button>
                </form>
              )}
            </div>
          )}
        </>
      )}
      {children}
    </div>
  )
}

// ================= DÉTAIL D'UN AUDIT =================
export function ScanDetail() {
  const { id } = useParams()
  const can = useCan()
  const { data: s, error, reload } = useLoad<any>(() => api(`/scans/${id}`), [id])
  const members = useLoad<any[]>(() => api('/members'))
  const [tab, setTab] = useState('summary')
  const [share, setShare] = useState<any>(null)
  const act = useAction()
  const running = s && active(s)
  useEffect(() => {
    if (!running) return
    const t = setInterval(reload, 2000)
    return () => clearInterval(t)
  }, [running, reload])
  if (error) return <Err msg={error} />
  if (!s) return <><PageHead title="Audit" crumbs={[{ label: "Campagnes d'audit", to: '/app/scans' }, { label: 'Détail' }]} /><Skeleton kind="cards" n={4} /><div style={{ height: 16 }} /><Skeleton /></>
  const sum = s.summary ?? {}
  const dl = (f: string) => `/api/scans/${s.id}/report?format=${f}`
  const groups: string[] = [...new Set<string>(s.testResults.map((t: any) => t.group))]
  const mgroups: string[] = [...new Set<string>(s.metrics.map((m: any) => m.group))]
  const shots: Record<string, string> = sum.qa?.screenshots ?? {}
  const tabs = [
    { id: 'summary', label: 'Synthèse' },
    ...(s.findings.length ? [{ id: 'findings', label: `Constats (${s.findings.length})` }] : []),
    ...(s.testResults.length ? [{ id: 'tests', label: `Tests (${s.testResults.length})` }] : []),
    ...(s.metrics.length ? [{ id: 'perf', label: 'Performance' }] : []),
    ...(Object.keys(shots).length ? [{ id: 'shots', label: 'Captures' }] : []),
    ...(s.comparison ? [{ id: 'compare', label: 'Comparaison' }] : []),
  ]
  return (
    <>
      <PageHead crumbs={[{ label: "Campagnes d'audit", to: '/app/scans' }, { label: s.application.name }]} title={`${s.profile === 'LOAD' ? 'Test de charge' : 'Audit'} — ${s.application.name}`} sub={<>{s.application.url} · lancé le {fmt(s.createdAt)}{s.createdBy && <> par {s.createdBy}</>} · {s.requestsMade} requête(s) émise(s){sum.active ? ' · contrôles actifs' : ''}</>}>
        <ScanBadge s={s.status} />
        {running && can.has('scan.cancel') && <button className="btn danger" onClick={() => act.run(() => api(`/scans/${s.id}/cancel`, { method: 'POST' }), { success: 'Annulation demandée.' }).then(reload)}>Annuler</button>}
        {s.status === 'DONE' && (
          <>
            <a className="btn" href={dl('pdf')}>Rapport PDF</a>
            <a className="btn ghost" href={dl('json')}>JSON</a>
            <a className="btn ghost" href={dl('csv')}>CSV</a>
            <a className="btn ghost" href={dl('sarif')} title="Format SARIF (GitHub Code Scanning, IDE)">SARIF</a>
            {can.has('report.share') && <button className="btn ghost" onClick={() => act.run(async () => setShare(await api('/reports/share', { method: 'POST', body: { scanId: s.id, days: 7 } })))}>Partager</button>}
          </>
        )}
      </PageHead>
      <Err msg={act.error} />
      {share && <Modal title="Lien de partage (7 jours)" onClose={() => setShare(null)}><p className="small">Ce lien donne accès au rapport PDF sans compte. Il expire le {fmt(share.expiresAt)} et peut être révoqué depuis la page Rapports.</p><div className="row"><input readOnly value={share.url} style={{ flex: 1 }} /><CopyBtn text={share.url} /></div></Modal>}
      {running && <div className="card"><div className="row between"><span><span className="spin" />{s.stage || 'Démarrage…'}</span><b>{s.progress} %</b></div><Progress value={s.progress} /><div className="muted small">Cette page se met à jour automatiquement.</div></div>}
      {s.status === 'FAILED' && <Err msg={`L'audit a échoué : ${s.error ?? 'erreur inconnue'}`} />}
      {s.status === 'CANCELED' && <div className="note">Audit annulé{s.findings.length || s.testResults.length ? ' : les résultats partiels sont affichés.' : '.'}</div>}
      {(s.status === 'DONE' || s.status === 'CANCELED') && <Tabs tabs={tabs} value={tab} onChange={setTab} />}

      {tab === 'summary' && s.status !== 'QUEUED' && (
        <>
          <div className="card row" style={{ gap: 22 }}>
            <Score value={s.score} />
            <div style={{ flex: 1, minWidth: 240 }}>
              <h2>Synthèse</h2>
              {sum.qa && <div>QA : {sum.qa.error ? <span className="muted">module en échec ({sum.qa.error})</span> : <><b>{sum.qa.passed}/{sum.qa.total}</b> tests réussis ({sum.qa.rate} %){sum.qa.skipped ? `, ${sum.qa.skipped} ignoré(s)` : ''}{sum.qa.browserRan ? ' · navigateur réel' : ' · contrôles statiques seulement'}{sum.qa.axe && <> · accessibilité : {sum.qa.axe.violations} violation(s) dont {sum.qa.axe.serious} sérieuse(s)</>}</>}</div>}
              {sum.security && <div>Sécurité : {sum.security.error ? <span className="muted">module en échec ({sum.security.error})</span> : <>score <b>{sum.security.score}/100</b>, <b>{sum.security.total}</b> constat(s) — {SEVS.filter((x) => sum.security.counts[x]).map((x) => `${sum.security.counts[x]} ${SEV_FR[x].toLowerCase()}`).join(', ') || 'aucun'}{sum.security.activeSkipped && <span className="muted"> · contrôles actifs non autorisés</span>}</>}</div>}
              {sum.api && <div>API : {sum.api.error ? <span className="muted">module en échec ({sum.api.error})</span> : <>score <b>{sum.api.score}/100</b>, {sum.api.total} constat(s), {sum.api.passed}/{sum.api.tests} test(s) dynamique(s){sum.api.info?.operations != null && <>, {sum.api.info.operations} opération(s) documentée(s) ({sum.api.info.secured} protégée(s))</>}</>}</div>}
              {sum.performance && <div>Performance : {sum.performance.error ? <span className="muted">module en échec ({sum.performance.error})</span> : <>score <b>{sum.performance.score}/100</b>, temps moyen {sum.performance.avg} ms, P95 {sum.performance.p95} ms{sum.performance.vitals?.lcp ? `, LCP ${Math.round(sum.performance.vitals.lcp)} ms` : ''}{sum.performance.vitals?.cls != null ? `, CLS ${sum.performance.vitals.cls}` : ''}</>}</div>}
              {sum.load && <div>Charge : {sum.load.vus} utilisateurs virtuels pendant {sum.load.seconds} s{sum.load.aborted && <span className="muted"> · {sum.load.aborted}</span>}</div>}
              {sum.regressions > 0 && <div className="err" style={{ marginTop: 8 }}>{sum.regressions} régression(s) : des constats corrigés sont réapparus.</div>}
              {sum.security?.info?.tls && <div className="muted small" style={{ marginTop: 6 }}>Certificat TLS : {sum.security.info.tls.subject} — émis par {sum.security.info.tls.issuer} — {sum.security.info.tls.protocol} / {sum.security.info.tls.cipher} — expire dans {sum.security.info.tls.daysLeft} jour(s)</div>}
              {sum.security?.info?.dns && <div className="muted small">DNS : SPF {sum.security.info.dns.spf ? 'présent' : 'absent'} · DMARC {sum.security.info.dns.dmarc ? 'présent' : 'absent'} · CAA {sum.security.info.dns.caa ? 'présent' : 'absent'}</div>}
            </div>
            {s.findings.length > 0 && <div style={{ minWidth: 260, flex: 1 }}><HBars items={SEVS.map((x) => ({ label: SEV_FR[x], value: s.findings.filter((f: any) => f.severity === x).length, color: `var(--${SEV_VAR[x]})` }))} /></div>}
          </div>
          {s.findings.filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length > 0 && (
            <div className="card">
              <h2>À traiter en priorité</h2>
              {s.findings.filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH').map((f: any) => <FindingCard key={f.id} f={f} members={members.data ?? []} onChange={reload} />)}
            </div>
          )}
        </>
      )}
      {tab === 'findings' && (
        <>
          {['SECURITY', 'API', 'QA', 'PERFORMANCE'].map((m) => {
            const list = s.findings.filter((f: any) => f.module === m)
            if (!list.length) return null
            return <div key={m}><h2 style={{ marginTop: 18 }}>{MODULE_FR[m]} — {list.length} constat(s)</h2>{list.map((f: any) => <FindingCard key={f.id} f={f} members={members.data ?? []} onChange={reload} />)}</div>
          })}
        </>
      )}
      {tab === 'tests' && groups.map((g) => {
        const list = s.testResults.filter((t: any) => t.group === g)
        return (
          <div className="card" key={g}>
            <h2>{GROUP_FR[g] ?? g} <span className="muted small">— {list.filter((t: any) => t.status === 'PASS').length}/{list.filter((t: any) => t.status !== 'SKIP').length} réussis</span></h2>
            <table><tbody>
              {list.map((t: any) => (
                <tr key={t.id}>
                  <td style={{ width: 90 }}><span className={`badge ${t.status === 'PASS' ? 'ok' : t.status === 'FAIL' ? 'bad' : ''}`}>{t.status === 'PASS' ? 'Réussi' : t.status === 'FAIL' ? 'Échec' : 'Ignoré'}</span></td>
                  <td><b>{t.name}</b>{t.browser && <span className="badge" style={{ marginLeft: 6 }}>{t.browser}</span>}{t.detail && <div className="muted small mono">{t.detail}</div>}</td>
                  <td className="muted small" style={{ textAlign: 'right' }}>{t.durationMs ? `${t.durationMs} ms` : ''}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
        )
      })}
      {tab === 'perf' && (
        <>
          {mgroups.map((g) => (
            <div key={g}>
              <h2 style={{ marginTop: 18 }}>{METRIC_GROUP_FR[g] ?? g}</h2>
              <div className="grid g5">
                {s.metrics.filter((m: any) => m.group === g).map((m: any) => <div className="stat" key={m.id}><b>{m.value} <span>{m.unit}</span></b><span>{m.name}</span></div>)}
              </div>
            </div>
          ))}
          {sum.performance?.samples?.length > 1 && <div className="card" style={{ marginTop: 16 }}><h2>Temps de réponse des requêtes successives</h2><LineChart labels={sum.performance.samples.map((_: any, i: number) => `#${i + 1}`)} series={[{ name: 'Temps de réponse', values: sum.performance.samples }]} unit=" ms" /></div>}
          {sum.loadSeries?.length > 1 && (
            <div className="grid g2" style={{ marginTop: 16 }}>
              <div className="card"><h2>Latence par seconde</h2><LineChart labels={sum.loadSeries.map((x: any) => `${x.t} s`)} series={[{ name: 'P50', values: sum.loadSeries.map((x: any) => x.p50) }, { name: 'P95', values: sum.loadSeries.map((x: any) => x.p95), color: 'var(--chart2)' }]} unit=" ms" /></div>
              <div className="card"><h2>Débit et erreurs par seconde</h2><LineChart labels={sum.loadSeries.map((x: any) => `${x.t} s`)} series={[{ name: 'Requêtes', values: sum.loadSeries.map((x: any) => x.rps) }, { name: 'Erreurs', values: sum.loadSeries.map((x: any) => x.errors), color: 'var(--danger)' }]} /></div>
            </div>
          )}
          <p className="muted small" style={{ marginTop: 8 }}>{s.profile === 'LOAD' ? 'Test de charge encadré par les limites de votre formule.' : `Mesure sur ${sum.performance?.samples?.length ?? 10} requêtes successives. Il ne s'agit pas d'un test de charge.`}</p>
        </>
      )}
      {tab === 'shots' && (
        <div className="grid g2">
          {Object.entries(shots).map(([k, file]) => (
            <div className="card" key={k}>
              <h2>{k.replace('-mobile', ' (mobile)')}{sum.qa?.visualDiff?.[k] && <span className="badge" style={{ marginLeft: 8 }}>{sum.qa.visualDiff[k].percent} % de différence</span>}</h2>
              <img src={`/api/scans/${s.id}/screenshot/${file}`} alt={`Capture ${k}`} className="shot" />
              {sum.qa?.visualDiff?.[k] && <img src={`/api/scans/${s.id}/screenshot/${file.replace('.png', '-diff.png')}`} alt="Différences" className="shot" style={{ marginTop: 8 }} />}
            </div>
          ))}
        </div>
      )}
      {tab === 'compare' && s.comparison && (
        <div className="card">
          <h2>Comparaison avec l'audit précédent ({fmt(s.comparison.previousDate)})</h2>
          <div className="grid g5">
            <div className="stat"><b>{s.comparison.previousScore ?? '—'} → {s.score ?? '—'}</b><span>Score global</span></div>
            <div className="stat"><b style={{ color: 'var(--ok)' }}>{s.comparison.fixed.length}</b><span>Corrigée(s)</span></div>
            <div className="stat"><b style={{ color: s.comparison.added.length ? 'var(--high)' : undefined }}>{s.comparison.added.length}</b><span>Nouvelle(s)</span></div>
            <div className="stat"><b>{s.comparison.persistent}</b><span>Persistante(s)</span></div>
            {s.comparison.previous.avgMs != null && sum.performance?.avg != null && <div className="stat"><b>{s.comparison.previous.avgMs} → {sum.performance.avg} ms</b><span>Temps moyen</span></div>}
          </div>
          {s.comparison.fixed.length > 0 && <p className="small" style={{ marginTop: 10 }}>Corrigées : {s.comparison.fixed.join(' · ')}</p>}
          {s.comparison.added.length > 0 && <p className="small">Nouvelles : {s.comparison.added.join(' · ')}</p>}
          <Link to={`/app/reports?compare=${s.comparison.previousId},${s.id}`} className="small">Comparaison détaillée</Link>
        </div>
      )}
    </>
  )
}

// ================= VULNÉRABILITÉS =================
export function Findings() {
  const [params, setParams] = useSearchParams()
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [module, setModule] = useState('')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(params.get('open') === 'true')
  const [mine, setMine] = useState(false)
  const { data, error, reload } = useLoad<any[]>(() => api(`/findings?severity=${severity}&status=${status}&module=${module}&q=${encodeURIComponent(q)}&open=${open}${mine ? '&assignee=me' : ''}`), [severity, status, module, q, open, mine])
  const stats = useLoad<any>(() => api('/findings/stats'))
  const members = useLoad<any[]>(() => api('/members'))
  const refresh = () => { reload(); stats.reload() }
  return (
    <>
      <PageHead title="Vulnérabilités" sub="Suivi des constats : Détectée → Confirmée → Assignée → En cours → Corrigée → Retestée → Clôturée. Un même constat est regroupé entre les audits.">
        <input placeholder="Rechercher (titre, ressource, CWE)" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filtrer par gravité"><option value="">Toutes les gravités</option>{SEVS.map((s) => <option key={s} value={s}>{SEV_FR[s]}</option>)}</select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); if (e.target.value) { setOpen(false); setParams({}) } }} aria-label="Filtrer par statut"><option value="">Tous les statuts</option>{Object.keys(STATUS_FR).map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}</select>
        <select value={module} onChange={(e) => setModule(e.target.value)} aria-label="Module"><option value="">Tous les modules</option>{Object.keys(MODULE_FR).map((m) => <option key={m} value={m}>{MODULE_FR[m]}</option>)}</select>
        <label className="chk"><input type="checkbox" checked={open} onChange={(e) => setOpen(e.target.checked)} />Ouverts seulement</label>
        <label className="chk"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />Assignés à moi</label>
      </PageHead>
      {stats.data && (
        <div className="grid g5" style={{ marginBottom: 16 }}>
          {SEVS.map((s) => <div className="stat" key={s}><b style={{ color: `var(--${SEV_VAR[s]})` }}>{stats.data.bySeverity[s] ?? 0}</b><span>{SEV_FR[s]} ouvert(s)</span></div>)}
        </div>
      )}
      <Err msg={error} />
      {!data ? <div className="card"><Skeleton kind="table" n={6} /></div> : data.length === 0 ? <div className="card"><Empty icon="check">Aucune vulnérabilité ne correspond à ces critères.</Empty></div> : data.map((f) => (
        <FindingCard key={f.id} f={f} members={members.data ?? []} onChange={refresh}>
          <div className="row" style={{ marginTop: 8 }}>
            <span className="muted small">{f.application} · détecté le {fmtDate(f.createdAt)} · <Link to={`/app/scans/${f.scanId}`}>voir l'audit</Link></span>
          </div>
        </FindingCard>
      ))}
    </>
  )
}

// ================= RAPPORTS =================
export function Reports() {
  const can = useCan()
  const [params] = useSearchParams()
  const { data, error, reload } = useLoad<any>(() => api('/reports'))
  const act = useAction()
  const [share, setShare] = useState<any>(null)
  const [from, setFrom] = useState(new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10))
  const [to, setTo] = useState(new Date().toISOString().slice(0, 10))
  const [cmp, setCmp] = useState<string[]>(params.get('compare')?.split(',') ?? [])
  const [cmpData, setCmpData] = useState<any>(null)
  const scans: any[] = data?.scans ?? []
  const toggleCmp = (id: string) => setCmp(cmp.includes(id) ? cmp.filter((x) => x !== id) : [...cmp, id].slice(-2))
  useEffect(() => {
    if (cmp.length === 2) api(`/reports/compare?a=${cmp[0]}&b=${cmp[1]}`).then(setCmpData).catch(() => setCmpData(null))
    else setCmpData(null)
  }, [cmp])
  return (
    <>
      <PageHead title="Rapports" sub="Un rapport par campagne terminée (PDF, JSON, CSV, SARIF), une synthèse d'organisation par période, et des liens de partage à durée limitée.">
        <label className="f" style={{ flex: 'none' }}>Du<input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
        <label className="f" style={{ flex: 'none' }}>Au<input type="date" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        <a className="btn" href={`/api/reports/summary?from=${from}&to=${to}`}>Synthèse PDF de la période</a>
      </PageHead>
      <Err msg={error || act.error} />
      {share && <Modal title={`Lien de partage (expire le ${fmt(share.expiresAt)})`} onClose={() => { setShare(null); reload() }}><div className="row"><input readOnly value={share.url} style={{ flex: 1 }} /><CopyBtn text={share.url} /></div></Modal>}
      {cmpData && (
        <div className="card">
          <div className="row between"><h2>Comparaison : {cmpData.a.app} ({fmtDate(cmpData.a.date)}) → {cmpData.b.app} ({fmtDate(cmpData.b.date)})</h2><button className="btn ghost sm" onClick={() => setCmp([])}>Fermer</button></div>
          <div className="grid g5">
            <div className="stat"><b>{cmpData.a.score ?? '—'} → {cmpData.b.score ?? '—'}</b><span>Score global</span></div>
            <div className="stat"><b style={{ color: 'var(--ok)' }}>{cmpData.fixed.length}</b><span>Corrigées</span></div>
            <div className="stat"><b style={{ color: cmpData.added.length ? 'var(--high)' : undefined }}>{cmpData.added.length}</b><span>Nouvelles</span></div>
            <div className="stat"><b>{cmpData.persistent.length}</b><span>Persistantes</span></div>
            <div className="stat"><b>{cmpData.tests.a}/{cmpData.tests.totalA} → {cmpData.tests.b}/{cmpData.tests.totalB}</b><span>Tests réussis</span></div>
          </div>
          <table style={{ marginTop: 12 }}><thead><tr><th>Métrique</th><th>Avant</th><th>Après</th></tr></thead><tbody>
            {cmpData.perf.filter((p: any) => p.a != null || p.b != null).map((p: any) => <tr key={p.name}><td>{p.name}</td><td>{p.a ?? '—'}</td><td>{p.b ?? '—'}</td></tr>)}
          </tbody></table>
          {(['fixed', 'added', 'persistent'] as const).map((k) => cmpData[k].length > 0 && <p key={k} className="small" style={{ marginTop: 8 }}><b>{{ fixed: 'Corrigées', added: 'Nouvelles', persistent: 'Persistantes' }[k]}</b> : {cmpData[k].map((f: any) => `[${SEV_FR[f.severity]}] ${f.title}`).join(' · ')}</p>)}
        </div>
      )}
      <div className="card">
        <div className="row between"><h2>Rapports par campagne</h2>{cmp.length === 1 && <span className="muted small">Sélectionnez un second audit pour comparer.</span>}</div>
        {!data ? <Skeleton kind="table" n={5} /> : scans.length === 0 ? <Empty icon="file">Aucun rapport disponible. Lancez un audit pour en générer un.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th></th><th>Application</th><th>Date</th><th>Modules</th><th>Score</th><th>Télécharger</th><th></th></tr></thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td><input type="checkbox" checked={cmp.includes(s.id)} onChange={() => toggleCmp(s.id)} aria-label="Comparer" /></td>
                    <td><Link to={`/app/scans/${s.id}`}><b>{s.application.name}</b></Link><div className="muted small">{s.profile === 'LOAD' ? 'Test de charge' : s.profile === 'DEEP' ? 'Approfondi' : 'Standard'}</div></td>
                    <td className="muted small">{fmt(s.createdAt)}</td>
                    <td>{s.modules.split(',').map((m: string) => MODULE_FR[m]).join(', ')}</td>
                    <td><b>{s.score ?? '—'}</b></td>
                    <td><div className="row">{['pdf', 'json', 'csv', 'sarif'].map((f) => <a key={f} className="btn ghost sm" href={`/api/scans/${s.id}/report?format=${f}`}>{f.toUpperCase()}</a>)}</div></td>
                    <td>{can.has('report.share') && <button className="btn ghost sm" onClick={() => act.run(async () => setShare(await api('/reports/share', { method: 'POST', body: { scanId: s.id, days: 7 } })))}>Partager</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {data?.shares?.length > 0 && (
        <div className="card">
          <h2>Liens de partage actifs</h2>
          <table><tbody>
            {data.shares.map((r: any) => (
              <tr key={r.id}>
                <td><b>{r.title}</b><div className="muted small mono">{r.url}</div></td>
                <td className="muted small">expire le {fmt(r.expiresAt)}</td>
                <td style={{ textAlign: 'right' }}><div className="row" style={{ justifyContent: 'flex-end' }}><CopyBtn text={r.url} />{can.has('report.share') && <button className="btn danger sm" onClick={() => act.run(() => api(`/reports/${r.id}/share`, { method: 'DELETE' }), { success: 'Lien de partage révoqué.' }).then(reload)}>Révoquer</button>}</div></td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
    </>
  )
}
