import React, { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, INCIDENT_FR, fmt, ago, pct } from './api'
import { Empty, Err, Loading, Modal, Ok, PageHead, Skeleton, useAction, useAuth, useCan, useLoad } from './ui'
import { LineChart, Sparkline } from './charts'

export function Monitoring() {
  const can = useCan()
  const { me } = useAuth()
  const [params] = useSearchParams()
  const apps = useLoad<any[]>(() => api('/monitoring'))
  const incidents = useLoad<any[]>(() => api('/incidents'))
  const act = useAction()
  const [config, setConfig] = useState<any>(null)
  const [detail, setDetail] = useState<string | null>(params.get('app'))
  const refresh = () => { apps.reload(); incidents.reload() }
  const call = async (fn: () => Promise<any>) => { if (await act.run(fn)) refresh() }
  const openIncidents = (incidents.data ?? []).filter((i) => i.status !== 'RESOLVED')
  return (
    <>
      <PageHead title="Monitoring" sub={`Disponibilité, code HTTP, temps de réponse, mot-clé attendu et certificat TLS. Fréquence minimale de votre formule : ${me.plan.minMonitorInterval} min.`} />
      <Err msg={apps.error || incidents.error || act.error} />
      {apps.data && (
        <div className="grid g5" style={{ marginBottom: 16 }}>
          <div className="stat"><b>{apps.data.filter((a) => a.monitoring).length}</b><span>Applications surveillées</span></div>
          <div className="stat"><b style={{ color: apps.data.some((a) => a.lastStatus === 'DOWN') ? 'var(--danger)' : 'var(--ok)' }}>{apps.data.filter((a) => a.lastStatus === 'DOWN').length}</b><span>Indisponibles</span></div>
          <div className="stat"><b style={{ color: openIncidents.length ? 'var(--danger)' : undefined }}>{openIncidents.length}</b><span>Incidents ouverts</span></div>
          <div className="stat"><b>{(() => { const u = apps.data.filter((a) => a.uptime30d != null); return u.length ? `${Math.round((u.reduce((x, a) => x + a.uptime30d, 0) / u.length) * 10) / 10} %` : '—' })()}</b><span>Disponibilité moyenne 30 j</span></div>
          <div className="stat"><b style={{ color: apps.data.some((a) => a.sslDaysLeft != null && a.sslDaysLeft <= a.sslDaysWarn) ? 'var(--high)' : undefined }}>{apps.data.filter((a) => a.sslDaysLeft != null && a.sslDaysLeft <= a.sslDaysWarn).length}</b><span>Certificats à renouveler</span></div>
        </div>
      )}
      <div className="card">
        {!apps.data ? <Skeleton kind="table" n={4} /> : apps.data.length === 0 ? <Empty icon="activity">Aucune application à surveiller.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Application</th><th>État</th><th>24 h</th><th>Disponibilité</th><th>Réponse</th><th>TLS</th><th>Surveillance</th><th></th></tr></thead>
              <tbody>
                {apps.data.map((a) => (
                  <tr key={a.id}>
                    <td><b>{a.name}</b><div className="muted small">{a.project.name}{a.inMaintenance && <span className="badge" style={{ marginLeft: 6 }}>Maintenance</span>}</div></td>
                    <td><span className={`dot ${a.lastStatus}`} />{a.lastStatus === 'UP' ? 'Disponible' : a.lastStatus === 'DOWN' ? 'Indisponible' : 'Non vérifiée'}<div className="muted small">{a.lastHttpCode ? `HTTP ${a.lastHttpCode} · ` : ''}{a.lastCheckedAt ? ago(a.lastCheckedAt) : ''}</div></td>
                    <td><Sparkline points={a.sparkline} /></td>
                    <td className="small">{pct(a.uptime24h)} <span className="muted">/ 24 h</span><div className="muted">{pct(a.uptime7d)} / 7 j · {pct(a.uptime30d)} / 30 j</div></td>
                    <td>{a.lastResponseMs != null ? `${a.lastResponseMs} ms` : '—'}{a.avgMs24h != null && <div className="muted small">moy. {a.avgMs24h} ms</div>}</td>
                    <td className="small">{a.sslDaysLeft == null ? <span className="muted">—</span> : <span className={`badge ${a.sslDaysLeft <= a.sslDaysWarn ? 'bad' : 'ok'}`}>{a.sslDaysLeft} j</span>}</td>
                    <td>
                      {!a.authorized ? <span className="badge bad">Autorisation requise</span> : can.has('monitoring.manage') ? (
                        <div className="row">
                          <label className="chk"><input type="checkbox" checked={a.monitoring} onChange={(e) => call(() => api(`/applications/${a.id}`, { method: 'PATCH', body: { monitoring: e.target.checked } }))} />Active</label>
                          <select value={a.monitorInterval} onChange={(e) => call(() => api(`/applications/${a.id}`, { method: 'PATCH', body: { monitorInterval: Number(e.target.value) } }))} aria-label="Fréquence">
                            {[5, 15, 30, 60].map((n) => <option key={n} value={n} disabled={n < me.plan.minMonitorInterval}>{n === 60 ? '1 heure' : `${n} min`}</option>)}
                          </select>
                        </div>
                      ) : <span className="badge">{a.monitoring ? `Toutes les ${a.monitorInterval} min` : 'Inactive'}</span>}
                    </td>
                    <td><div className="row" style={{ justifyContent: 'flex-end' }}>
                      <button className="btn ghost sm" onClick={() => setDetail(a.id)}>Historique</button>
                      {a.authorized && can.has('monitoring.manage') && <button className="btn ghost sm" onClick={() => setConfig(a)}>Règles</button>}
                      {a.authorized && can.has('monitoring.check') && <button className="btn ghost sm" disabled={act.busy} onClick={() => act.run(() => api(`/applications/${a.id}/check`, { method: 'POST' }), { success: 'Vérification effectuée.' }).then((ok) => ok && refresh())}>Vérifier</button>}
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {detail && <HistoryModal id={detail} name={apps.data?.find((a) => a.id === detail)?.name ?? ''} onClose={() => setDetail(null)} />}
      {config && <RulesModal a={config} onClose={() => setConfig(null)} refresh={refresh} />}
      <div className="card">
        <h2>Incidents</h2>
        {!incidents.data ? <Loading /> : incidents.data.length === 0 ? <Empty>Aucun incident enregistré.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Incident</th><th>État</th><th>Occurrences</th><th>Début</th><th>Résolution</th><th>Notes</th><th></th></tr></thead>
              <tbody>
                {incidents.data.map((i) => (
                  <tr key={i.id}>
                    <td><b>{i.application.name}</b><div className="small">{i.title}</div></td>
                    <td><span className={`badge ${i.status === 'OPEN' ? 'bad' : i.status === 'ACKNOWLEDGED' ? 'run' : 'ok'}`}>{INCIDENT_FR[i.status]}</span></td>
                    <td>{i.occurrences}</td>
                    <td className="muted small">{fmt(i.startedAt)}</td>
                    <td className="muted small">{i.resolvedAt ? `${fmt(i.resolvedAt)} (${Math.max(1, Math.round((new Date(i.resolvedAt).getTime() - new Date(i.startedAt).getTime()) / 60000))} min)` : '—'}</td>
                    <td className="small" style={{ maxWidth: 220 }}>{i.notes}</td>
                    <td>{can.has('incident.update') && (
                      <div className="row" style={{ justifyContent: 'flex-end' }}>
                        {i.status === 'OPEN' && <button className="btn sm" onClick={() => act.run(() => api(`/incidents/${i.id}`, { method: 'PATCH', body: { status: 'ACKNOWLEDGED' } }), { success: 'Incident pris en charge.' }).then((ok) => ok && refresh())}>Prendre en charge</button>}
                        {i.status !== 'RESOLVED' && <button className="btn ghost sm" onClick={() => act.run(() => api(`/incidents/${i.id}`, { method: 'PATCH', body: { status: 'RESOLVED' } }), { success: 'Incident résolu.' }).then((ok) => ok && refresh())}>Résoudre</button>}
                        <button className="btn ghost sm" onClick={() => { const n = window.prompt('Notes :', i.notes ?? ''); if (n != null) call(() => api(`/incidents/${i.id}`, { method: 'PATCH', body: { notes: n } })) }}>Notes</button>
                      </div>
                    )}</td>
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

function HistoryModal({ id, name, onClose }: { id: string; name: string; onClose: () => void }) {
  const [hours, setHours] = useState(24)
  const checks = useLoad<any[]>(() => api(`/monitoring/${id}/checks?hours=${hours}`), [id, hours])
  const hist = useLoad<any>(() => api(`/applications/${id}/history`), [id])
  const c = checks.data ?? []
  const total = c.length, up = c.filter((x) => x.up).length
  return (
    <Modal title={`Historique — ${name}`} onClose={onClose} wide>
      <div className="row" style={{ marginBottom: 10 }}>
        {[24, 168, 720].map((h) => <button key={h} className={'btn sm ' + (hours === h ? '' : 'ghost')} onClick={() => setHours(h)}>{h === 24 ? '24 h' : h === 168 ? '7 jours' : '30 jours'}</button>)}
        <span className="muted small" style={{ marginLeft: 'auto' }}>{total} vérification(s){total ? ` · ${Math.round((up / total) * 1000) / 10} % de disponibilité` : ''}</span>
      </div>
      {!checks.data ? <Loading /> : total === 0 ? <Empty>Aucune vérification sur la période.</Empty> : (
        <LineChart labels={c.map((x) => new Date(x.at).toLocaleString('fr-FR', hours > 24 ? { dateStyle: 'short', timeStyle: 'short' } : { timeStyle: 'short' }))} series={[{ name: 'Temps de réponse', values: c.map((x) => (x.up ? x.responseMs : null)) }]} unit=" ms" />
      )}
      {hist.data?.scans?.length > 1 && (
        <>
          <h3 style={{ marginTop: 16 }}>Scores des audits</h3>
          <LineChart labels={hist.data.scans.map((s: any) => new Date(s.date).toLocaleDateString('fr-FR'))} series={[{ name: 'Global', values: hist.data.scans.map((s: any) => s.score) }, { name: 'Sécurité', values: hist.data.scans.map((s: any) => s.security), color: 'var(--chart2)' }, { name: 'Performance', values: hist.data.scans.map((s: any) => s.performance), color: 'var(--chart3)' }]} max={100} />
          <h3 style={{ marginTop: 16 }}>Temps de réponse moyen mesuré par les audits</h3>
          <LineChart labels={hist.data.scans.map((s: any) => new Date(s.date).toLocaleDateString('fr-FR'))} series={[{ name: 'Temps moyen', values: hist.data.scans.map((s: any) => s.avgMs) }, { name: 'P95', values: hist.data.scans.map((s: any) => s.p95), color: 'var(--chart2)' }]} unit=" ms" />
        </>
      )}
    </Modal>
  )
}

function RulesModal({ a, onClose, refresh }: { a: any; onClose: () => void; refresh: () => void }) {
  const act = useAction()
  const [f, setF] = useState({ monitorExpectStatus: a.monitorExpectStatus, monitorKeyword: a.monitorKeyword, monitorMaxMs: a.monitorMaxMs, monitorFailThreshold: a.monitorFailThreshold, sslDaysWarn: a.sslDaysWarn })
  const [maint, setMaint] = useState(0)
  const [ok, setOk] = useState('')
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value })
  return (
    <Modal title={`Règles de surveillance — ${a.name}`} onClose={onClose}>
      <Err msg={act.error} /><Ok msg={ok} />
      <form onSubmit={async (e) => { e.preventDefault(); if (await act.run(() => api(`/applications/${a.id}`, { method: 'PATCH', body: f }), { success: 'Règles de surveillance enregistrées.' })) { setOk('Règles enregistrées.'); refresh() } }}>
        <div className="grid g2">
          <label className="f">Code HTTP attendu (0 = tout code &lt; 500)<input type="number" min={0} max={599} value={f.monitorExpectStatus} onChange={set('monitorExpectStatus')} /></label>
          <label className="f">Texte attendu dans la réponse<input value={f.monitorKeyword} onChange={set('monitorKeyword')} placeholder="ex. : Bienvenue" /></label>
          <label className="f">Temps de réponse maximal (ms, 0 = aucun)<input type="number" min={0} value={f.monitorMaxMs} onChange={set('monitorMaxMs')} /></label>
          <label className="f">Échecs consécutifs avant incident<input type="number" min={1} max={10} value={f.monitorFailThreshold} onChange={set('monitorFailThreshold')} /></label>
          <label className="f">Alerte certificat TLS (jours avant expiration)<input type="number" min={1} max={90} value={f.sslDaysWarn} onChange={set('sslDaysWarn')} /></label>
        </div>
        <button className={'btn' + (act.busy ? ' busy' : '')} disabled={act.busy} style={{ marginTop: 12 }}>Enregistrer</button>
      </form>
      <h3 style={{ marginTop: 18 }}>Fenêtre de maintenance</h3>
      <p className="muted small">Pendant la maintenance, les vérifications continuent mais aucun incident ni alerte n'est créé.</p>
      <div className="row">
        <select value={maint} onChange={(e) => setMaint(Number(e.target.value))}><option value={0}>Aucune / terminer</option>{[1, 2, 4, 8, 24, 72].map((h) => <option key={h} value={h}>{h} h</option>)}</select>
        <button className="btn ghost" onClick={async () => { if (await act.run(() => api(`/applications/${a.id}/maintenance`, { method: 'POST', body: { hours: maint } }))) { setOk(maint ? `Maintenance déclarée pour ${maint} h.` : 'Maintenance terminée.'); refresh() } }}>Appliquer</button>
      </div>
    </Modal>
  )
}
