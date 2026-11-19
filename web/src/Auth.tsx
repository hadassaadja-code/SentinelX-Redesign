// Pages d'authentification complémentaires : mot de passe oublié, réinitialisation, confirmation d'e-mail, invitation, sans organisation.
import React, { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, ROLE_FR } from './api'
import { Brand, DevLinks, Err, Loading, Ok, useAction, useAuth } from './ui'

export function ForgotPassword() {
  const { error, busy, run } = useAction()
  const [email, setEmail] = useState('')
  const [done, setDone] = useState<any>(null)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let r: any
    if (await run(async () => { r = await api('/auth/forgot', { method: 'POST', body: { email } }) })) setDone(r)
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Mot de passe oublié</h1>
        {done ? (
          <>
            <Ok msg="Si un compte existe avec cette adresse, un lien de réinitialisation vient d'être envoyé. Il est valable une heure." />
            <DevLinks links={done.devLinks} />
          </>
        ) : (
          <>
            <p className="muted">Indiquez votre adresse e-mail : vous recevrez un lien pour choisir un nouveau mot de passe.</p>
            <Err msg={error} />
            <form onSubmit={submit}>
              <label className="f">Adresse e-mail<input type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
              <button className="btn" disabled={busy}>Envoyer le lien</button>
            </form>
          </>
        )}
      </div>
      <p className="muted"><Link to="/login">Retour à la connexion</Link></p>
    </div>
  )
}

export function ResetPassword() {
  const [params] = useSearchParams()
  const nav = useNavigate()
  const { error, busy, run } = useAction()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (password !== confirm) return alert('Les deux mots de passe ne correspondent pas')
    if (await run(() => api('/auth/reset', { method: 'POST', body: { token: params.get('token'), password } }))) setDone(true)
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Nouveau mot de passe</h1>
        {done ? (
          <>
            <Ok msg="Mot de passe modifié. Toutes vos sessions ont été fermées : reconnectez-vous." />
            <button className="btn" onClick={() => nav('/login')}>Se connecter</button>
          </>
        ) : (
          <>
            <Err msg={error} />
            <form onSubmit={submit}>
              <label className="f">Nouveau mot de passe<input type="password" required minLength={10} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
              <label className="f">Confirmation<input type="password" required minLength={10} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
              <button className="btn" disabled={busy}>Enregistrer</button>
            </form>
          </>
        )}
      </div>
    </div>
  )
}

export function VerifyEmail() {
  const [params] = useSearchParams()
  const { reload } = useAuth()
  const [state, setState] = useState<'loading' | 'ok' | 'error'>('loading')
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api('/auth/verify-email', { method: 'POST', body: { token: params.get('token') } })
      .then(async () => { setState('ok'); await reload() })
      .catch((e) => { setState('error'); setMsg(e.message) })
  }, [params, reload])
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Confirmation de l'adresse e-mail</h1>
        {state === 'loading' && <Loading />}
        {state === 'ok' && <><Ok msg="Votre adresse e-mail est confirmée." /><Link className="btn" to="/app">Ouvrir mon espace</Link></>}
        {state === 'error' && <><Err msg={msg} /><Link className="btn ghost" to="/app/settings">Renvoyer un lien depuis mes paramètres</Link></>}
      </div>
    </div>
  )
}

export function Invite() {
  const [params] = useSearchParams()
  const nav = useNavigate()
  const { me, reload } = useAuth()
  const { error, busy, run } = useAction()
  const [info, setInfo] = useState<any>(null)
  const [err, setErr] = useState('')
  const [f, setF] = useState({ name: '', password: '' })
  const token = params.get('token')
  useEffect(() => {
    api(`/auth/invite?token=${encodeURIComponent(token ?? '')}`).then(setInfo).catch((e) => setErr(e.message))
  }, [token])
  const accept = async (e: React.FormEvent) => {
    e.preventDefault()
    if (await run(() => api('/auth/invite/accept', { method: 'POST', body: { token, ...f } }))) {
      await reload()
      nav('/app')
    }
  }
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Invitation</h1>
        {err && <Err msg={err} />}
        {!info && !err && <Loading />}
        {info && (
          <>
            <p className="muted"><b>{info.inviter}</b> vous invite à rejoindre <b>{info.orgName}</b> en tant que {ROLE_FR[info.role] ?? info.role}, avec l'adresse {info.email}.</p>
            {me && me.user?.email !== info.email && <div className="note warn">Vous êtes connecté avec une autre adresse ({me.user?.email}). Déconnectez-vous pour accepter cette invitation.</div>}
            <Err msg={error} />
            <form onSubmit={accept}>
              {!info.existingAccount && (
                <>
                  <label className="f">Votre nom<input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoComplete="name" /></label>
                  <label className="f">Mot de passe (10 caractères minimum)<input type="password" required minLength={10} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></label>
                </>
              )}
              {info.existingAccount && <p className="muted small">Un compte existe déjà pour cette adresse : il sera rattaché à l'organisation.</p>}
              <button className="btn" disabled={busy || (me && me.user?.email !== info.email)}>Accepter l'invitation</button>
            </form>
          </>
        )}
      </div>
    </div>
  )
}

export function NoOrganization() {
  const { me, reload } = useAuth()
  const nav = useNavigate()
  return (
    <div className="auth">
      <Brand />
      <div className="card">
        <h1>Aucune organisation</h1>
        <p className="muted">Votre compte n'est rattaché à aucune organisation. Demandez une invitation à un administrateur ou créez votre propre espace.</p>
        {me?.user?.isSuperAdmin && <Link className="btn" to="/admin">Super Administration</Link>}
        <button className="btn ghost" style={{ marginLeft: 8 }} onClick={async () => { await api('/auth/logout', { method: 'POST' }).catch(() => {}); await reload(); nav('/login') }}>Déconnexion</button>
      </div>
    </div>
  )
}
