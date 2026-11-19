import React, { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { api } from './api'
import { Brand, DevLinks, Err, useAction, useAuth } from './ui'
import { Footer } from './Footer'

const ICONS: Record<string, React.ReactNode> = {
  qa: (<><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><path d="m9 11 3 3L22 4" /></>),
  security: (<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />),
  perf: (<><path d="M12 14l4-4" /><path d="M3.34 19a10 10 0 1 1 17.32 0" /></>),
  monitor: (<path d="M22 12h-4l-3 9L9 3l-3 9H2" />),
  report: (<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /><path d="M16 13H8" /><path d="M16 17H8" /><path d="M10 9H8" /></>),
  org: (<><rect x="4" y="2" width="16" height="20" rx="2" /><path d="M9 22v-4h6v4" /><path d="M8 6h.01M12 6h.01M16 6h.01M8 10h.01M12 10h.01M16 10h.01M8 14h.01M12 14h.01M16 14h.01" /></>),
}
const Tile = ({ k, color }: { k: string; color: string }) => (
  <div className="tile" style={{ ['--c' as any]: color }}>
    <svg viewBox="0 0 24 24" aria-hidden="true">{ICONS[k]}</svg>
  </div>
)

const MODULES = [
  { k: 'qa', color: '#2f6bff', title: 'Quality Assurance', text: "Accessibilité des pages, liens cassés, ressources manquantes, structure HTML et formulaires." },
  { k: 'security', color: '#7a5cff', title: 'Cybersécurité', text: "En-têtes de sécurité, HTTPS et certificat TLS, cookies, fichiers sensibles exposés. Contrôles non destructifs." },
  { k: 'perf', color: '#f2711c', title: 'Performance', text: "Temps de réponse moyen, P95, P99, débit et taux d'erreur, avec un historique par application." },
  { k: 'monitor', color: '#1f9d63', title: 'Monitoring', text: "Surveillance de disponibilité à fréquence réglable, incidents regroupés et alertes." },
  { k: 'report', color: '#d946a8', title: 'Rapports', text: "Rapports PDF, JSON et CSV par campagne, avec comparaison entre deux audits." },
  { k: 'org', color: '#0ea5b7', title: 'Multi-organisation', text: "Chaque entreprise dispose d'un espace isolé, de rôles et de quotas selon sa formule." },
]

export function Landing() {
  const { me } = useAuth()
  return (
    <div className="pub" id="securite">
      <nav className="pubnav">
        <Brand />
        <div className="row">
          {me ? (
            <Link className="btn" to="/app">Ouvrir mon espace</Link>
          ) : (
            <>
              <Link className="btn ghost" to="/login">Connexion</Link>
              <Link className="btn" to="/register">Créer un compte</Link>
            </>
          )}
        </div>
      </nav>

      <section className="hero">
        <div>
          <h1>Qualité, sécurité et performance de vos applications, <em>au même endroit</em>.</h1>
          <p className="lead">SentinelX audite vos sites et API, centralise les résultats et suit les corrections. Chaque constat est accompagné de sa preuve et d'une recommandation.</p>
          <div className="row">
            <Link className="btn lg" to={me ? '/app' : '/register'}>Démarrer un audit</Link>
            <a className="btn ghost lg" href="#modules">Voir les modules</a>
          </div>
        </div>

        <div className="preview" aria-label="Exemple de rapport d'audit">
          <div className="preview-top">
            <b>Rapport d'audit</b>
            <span className="badge run">Exemple</span>
          </div>
          <div className="preview-grid">
            <div className="score" style={{ ['--v' as any]: 86 }}>86</div>
            <div>
              {[
                ['Critique', 1, '#e5484d', 12],
                ['Élevée', 3, '#f2711c', 36],
                ['Moyenne', 5, '#d99a06', 60],
                ['Faible', 8, '#3b82f6', 100],
              ].map(([label, n, c, w]) => (
                <div className="sevrow" key={label as string}>
                  <span>{label}</span>
                  <div className="bar"><i style={{ width: `${w}%`, ['--c' as any]: c }} /></div>
                  <b>{n}</b>
                </div>
              ))}
            </div>
          </div>
          <div className="preview-list">
            <div>En-têtes de sécurité manquants <span className="badge sev HIGH">Élevée</span></div>
            <div>Certificat TLS valide <span className="badge ok">Conforme</span></div>
            <div>2 liens cassés détectés <span className="badge sev MEDIUM">Moyenne</span></div>
          </div>
          <div className="float-card">
            <div className="ico">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{ICONS.monitor}</svg>
            </div>
            <div><b>Application disponible</b><div className="muted small">Réponse moyenne : 182 ms</div></div>
          </div>
        </div>
      </section>

      <section id="modules">
        <h2 className="section-title">Tout ce qu'il faut pour suivre vos applications</h2>
        <p className="section-sub">Six modules, un seul tableau de bord, des résultats clairs avec la preuve et la correction à appliquer.</p>
        <div className="grid g3">
          {MODULES.map((m) => (
            <div className="card modcard" key={m.k}>
              <Tile k={m.k} color={m.color} />
              <h2>{m.title}</h2>
              <p className="muted">{m.text}</p>
            </div>
          ))}
        </div>
      </section>

      <Footer />
    </div>
  )
}

export function Login() {
  const { me, reload } = useAuth()
  const nav = useNavigate()
  const { error, busy, run } = useAction()
  const [f, setF] = useState({ email: '', password: '' })
  const [ticket, setTicket] = useState('')
  const [code, setCode] = useState('')
  if (me && !me.mfaRequired) return <Navigate to="/app" replace />
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let r: any
    if (await run(async () => { r = await api('/auth/login', { method: 'POST', body: f }) })) {
      if (r?.mfaRequired) return setTicket(r.ticket)
      await reload()
      nav('/app')
    }
  }
  const submitMfa = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await run(() => api('/auth/login/mfa', { method: 'POST', body: { ticket, code } }))) {
      await reload()
      nav('/app')
    }
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        {ticket ? (
          <>
            <h1>Vérification en deux étapes</h1>
            <p className="muted">Saisissez le code à 6 chiffres de votre application d'authentification, ou un code de récupération.</p>
            <Err msg={error} />
            <form onSubmit={submitMfa}>
              <label className="f">Code<input autoFocus required inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} /></label>
              <button className="btn" disabled={busy}>Valider</button>
              <button type="button" className="btn ghost" onClick={() => { setTicket(''); setCode('') }}>Retour</button>
            </form>
          </>
        ) : (
          <>
            <h1>Connexion</h1>
            <p className="muted">Accédez à l'espace de votre organisation.</p>
            <Err msg={error} />
            <form onSubmit={submit}>
              <label className="f">Adresse e-mail<input type="email" required autoComplete="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
              <label className="f">Mot de passe<input type="password" required autoComplete="current-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
              <button className="btn" disabled={busy}>Se connecter</button>
            </form>
            <p className="muted small" style={{ marginTop: 14, marginBottom: 0 }}><Link to="/forgot-password">Mot de passe oublié ?</Link></p>
          </>
        )}
      </div>
      <p className="muted">Pas encore de compte ? <Link to="/register">Créer une organisation</Link></p>
    </div>
  )
}

export function Register() {
  const { me, reload } = useAuth()
  const nav = useNavigate()
  const { error, busy, run } = useAction()
  const [f, setF] = useState({ name: '', orgName: '', email: '', password: '' })
  const [links, setLinks] = useState<any>(null)
  if (me && !links) return <Navigate to="/app" replace />
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let r: any
    if (await run(async () => { r = await api('/auth/register', { method: 'POST', body: f }) })) {
      await reload()
      if (r?.devLinks) setLinks(r.devLinks)
      else nav('/app/projects')
    }
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        {links ? (
          <>
            <h1>Compte créé</h1>
            <p className="muted">Un e-mail de confirmation vous a été adressé.</p>
            <DevLinks links={links} />
            <Link className="btn" to="/app/projects">Ouvrir mon espace</Link>
          </>
        ) : (
          <>
            <h1>Créer votre espace</h1>
            <p className="muted">Vous serez administrateur de l'organisation créée.</p>
            <Err msg={error} />
            <form onSubmit={submit}>
              <label className="f">Votre nom<input required value={f.name} onChange={set('name')} autoComplete="name" /></label>
              <label className="f">Nom de l'organisation<input required value={f.orgName} onChange={set('orgName')} autoComplete="organization" /></label>
              <label className="f">Adresse e-mail<input type="email" required value={f.email} onChange={set('email')} autoComplete="email" /></label>
              <label className="f">Mot de passe (10 caractères minimum, deux types de caractères)<input type="password" required minLength={10} value={f.password} onChange={set('password')} autoComplete="new-password" /></label>
              <button className="btn" disabled={busy}>Créer le compte</button>
            </form>
          </>
        )}
      </div>
      <p className="muted">Déjà inscrit ? <Link to="/login">Se connecter</Link></p>
    </div>
  )
}
