import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, ROLE_FR, SEV_FR } from './api'
import { FooterLight } from './Footer'

// ---------- Icônes (traits, 24x24) ----------
const PATHS: Record<string, string> = {
  dashboard: 'M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z',
  folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
  radar: 'M12 2a10 10 0 1 0 10 10M12 6a6 6 0 1 0 6 6M12 10a2 2 0 1 0 2 2M12 12l7-7',
  bug: 'M8 2l1.5 2M16 2l-1.5 2M12 20a6 6 0 0 0 6-6v-3a6 6 0 0 0-12 0v3a6 6 0 0 0 6 6zM3 13h3M18 13h3M4 20l3-2M20 20l-3-2M4 6l3 2M20 6l-3 2M12 20V8',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8',
  bell: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8',
  card: 'M2 5h20v14H2zM2 10h20M6 15h4',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  menu: 'M4 6h16M4 12h16M4 18h16',
  x: 'M18 6 6 18M6 6l12 12',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  check: 'M20 6 9 17l-5-5',
  alert: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
  chevron: 'm9 18 6-6-6-6',
  plus: 'M12 5v14M5 12h14',
  play: 'M5 3l14 9-14 9V3z',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z',
  gauge: 'M12 14l4-4M3.34 19a10 10 0 1 1 17.32 0',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z',
  flag: 'M4 22V4a1 1 0 0 1 1-1h11l-1 4 1 4H5',
  phone: 'M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.6a2 2 0 0 1-.5 2.1L8.1 9.7a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.8.3 1.7.5 2.6.7a2 2 0 0 1 1.7 2z',
  pin: 'M21 10c0 7-9 13-9 13S3 17 3 10a9 9 0 0 1 18 0zM12 13a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  mail: 'M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM22 6l-10 7L2 6',
}
export const Icon = ({ name, size, className }: { name: string; size?: number; className?: string }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} className={className} aria-hidden="true" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d={PATHS[name] ?? ''} /></svg>
)

// ---------- Notifications éphémères (toasts) ----------
type Toast = { id: number; kind: 'ok' | 'error' | 'info'; text: string }
const ToastCtx = createContext<{ push: (kind: Toast['kind'], text: string) => void }>({ push: () => {} })
export const useToast = () => {
  const { push } = useContext(ToastCtx)
  return { success: (t: string) => push('ok', t), error: (t: string) => push('error', t), info: (t: string) => push('info', t) }
}
let toastSeq = 0
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const push = useCallback((kind: Toast['kind'], text: string) => {
    const id = ++toastSeq
    setList((l) => [...l.slice(-4), { id, kind, text }])
    setTimeout(() => setList((l) => l.filter((t) => t.id !== id)), kind === 'error' ? 6000 : 3500)
  }, [])
  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div className="toasts" aria-live="polite">
        {list.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`} role={t.kind === 'error' ? 'alert' : 'status'}>
            <Icon name={t.kind === 'ok' ? 'check' : t.kind === 'error' ? 'alert' : 'info'} />
            <span>{t.text}</span>
            <button onClick={() => setList((l) => l.filter((x) => x.id !== t.id))} aria-label="Fermer">×</button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

// ---------- Authentification ----------
const AuthCtx = createContext<{ me: any; loading: boolean; reload: () => Promise<void> }>(null as any)
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const reload = useCallback(async () => {
    try {
      setMe(await api('/auth/me'))
    } catch (e: any) {
      setMe(e?.code === 'MFA_REQUIRED' ? { mfaRequired: true } : null)
    } finally {
      setLoading(false)
    }
  }, [])
  const toast = useToast()
  const toastRef = useRef(toast)
  toastRef.current = toast
  useEffect(() => {
    reload()
  }, [reload])
  // Session perdue (expirée, révoquée ou supprimée côté serveur) : on oublie l'utilisateur, la coquille redirige vers la connexion.
  useEffect(() => {
    const onLost = () => setMe((cur: any) => {
      if (cur) toastRef.current.error('Votre session a expiré. Veuillez vous reconnecter.')
      return null
    })
    window.addEventListener('sx:session-lost', onLost)
    return () => window.removeEventListener('sx:session-lost', onLost)
  }, [])
  return <AuthCtx.Provider value={{ me, loading, reload }}>{children}</AuthCtx.Provider>
}
export const useAuth = () => useContext(AuthCtx)
/** Permissions : alignées sur la matrice serveur (me.permissions). */
export function useCan() {
  const { me } = useAuth()
  const perms: string[] = me?.permissions ?? []
  const has = (p: string) => perms.includes(p)
  const r = me?.role
  return { has, admin: r === 'ADMIN', manage: has('project.manage'), operate: has('scan.run'), superAdmin: !!me?.user?.isSuperAdmin }
}

// ---------- Chargement de données ----------
export function useLoad<T = any>(fn: () => Promise<T>, deps: any[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(() => fn().then((d) => { setData(d); setError('') }).catch((e) => setError(e.message)), deps)
  useEffect(() => {
    reload()
  }, [reload])
  return { data, error, reload, setData }
}

/** Exécute une action : état occupé, erreur inline + notification, message de réussite optionnel. */
export function useAction() {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const run = async (fn: () => Promise<any>, opts: { success?: string; silent?: boolean } = {}) => {
    setBusy(true)
    setError('')
    try {
      await fn()
      if (opts.success) toast.success(opts.success)
      return true
    } catch (e: any) {
      setError(e.message)
      if (!opts.silent) toast.error(e.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  return { error, busy, run, setError }
}

// ---------- Thème ----------
export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('sx-theme') ?? 'light'
    } catch {
      return 'light'
    }
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('sx-theme', theme)
    } catch {}
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))]
}

// ---------- Petits composants ----------
export const Err = ({ msg }: { msg?: string }) => (msg ? <div className="err" role="alert"><Icon name="alert" /><span>{msg}</span></div> : null)
export const Ok = ({ msg }: { msg?: string }) => (msg ? <div className="note ok" role="status"><Icon name="check" /><span>{msg}</span></div> : null)
export const Sev = ({ s }: { s: string }) => <span className={`badge sev ${s}`}>{SEV_FR[s] ?? s}</span>
export const Empty = ({ children, icon = 'inbox' }: { children: React.ReactNode; icon?: string }) => <div className="empty"><Icon name={icon} /><div>{children}</div></div>
export const Loading = ({ label = 'Chargement…' }: { label?: string }) => <div className="empty" role="status"><span className="spin" />{label}</div>
/** Squelette de chargement : lignes, cartes ou tableau. */
export function Skeleton({ kind = 'lines', n = 4 }: { kind?: 'lines' | 'cards' | 'table'; n?: number }) {
  if (kind === 'cards') return <div className="skel cards" aria-busy="true">{Array.from({ length: n }, (_, i) => <i key={i} />)}</div>
  if (kind === 'table') return <div className="skel" aria-busy="true"><i className="t" />{Array.from({ length: n }, (_, i) => <i key={i} className={i % 2 ? 'w80' : ''} />)}</div>
  return <div className="skel" aria-busy="true"><i className="t" /><i /><i className="w80" /><i className="w60" /></div>
}
export function Score({ value, size }: { value: number | null | undefined; size?: number }) {
  const style: any = size ? { width: size, height: size, fontSize: size / 3.2 } : {}
  if (value == null) return <div className="score" style={{ ...style, borderColor: 'var(--line)' }}>—</div>
  return <div className={`score ${value >= 75 ? '' : value >= 50 ? 'mid' : 'low'}`} style={{ ...style, ['--v' as any]: value }}>{value}</div>
}
export function PageHead({ title, sub, children, crumbs }: { title: string; sub?: React.ReactNode; children?: React.ReactNode; crumbs?: Array<{ label: string; to?: string }> }) {
  return (
    <div className="head">
      <div>
        {crumbs && (
          <nav className="crumbs" aria-label="Fil d'Ariane">
            {crumbs.map((c, i) => <React.Fragment key={i}>{i > 0 && <Icon name="chevron" />}{c.to ? <Link to={c.to}>{c.label}</Link> : <span>{c.label}</span>}</React.Fragment>)}
          </nav>
        )}
        <h1>{title}</h1>
        {sub && <div className="muted">{sub}</div>}
      </div>
      {children && <div className="row">{children}</div>}
    </div>
  )
}
export const Brand = ({ to = '/' }: { to?: string }) => (
  <Link to={to} className="brand" aria-label="SentinelX"><i><Icon name="shield" /></i><span>SentinelX</span></Link>
)
export function Tabs({ tabs, value, onChange }: { tabs: Array<{ id: string; label: React.ReactNode }>; value: string; onChange: (id: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => <button key={t.id} role="tab" aria-selected={value === t.id} className={'tab' + (value === t.id ? ' active' : '')} onClick={() => onChange(t.id)}>{t.label}</button>)}
    </div>
  )
}
export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    document.body.style.overflow = 'hidden'
    return () => { window.removeEventListener('keydown', h); document.body.style.overflow = '' }
  }, [onClose])
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={'modal' + (wide ? ' wide' : '')} role="dialog" aria-modal="true" aria-label={title}>
        <div className="row between" style={{ marginBottom: 12 }}><h2 style={{ margin: 0 }}>{title}</h2><button className="iconbtn" onClick={onClose} aria-label="Fermer"><Icon name="x" /></button></div>
        {children}
      </div>
    </div>
  )
}
export function CopyBtn({ text, label = 'Copier' }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false)
  return <button type="button" className="btn ghost sm" onClick={async () => { try { await navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1500) } catch {} }}>{ok ? <><Icon name="check" />Copié</> : label}</button>
}
/** Liens de démonstration renvoyés par le serveur quand aucun SMTP n'est configuré. */
export function DevLinks({ links }: { links?: Record<string, string> }) {
  if (!links) return null
  return (
    <div className="note">
      <b>Mode démonstration (pas de serveur SMTP)</b> : l'e-mail n'a pas été envoyé. Lien à utiliser :
      {Object.values(links).map((l) => <div key={l} className="row" style={{ marginTop: 6 }}><a href={l} className="mono small" style={{ wordBreak: 'break-all' }}>{l}</a><CopyBtn text={l} /></div>)}
    </div>
  )
}

// ---------- Coquille de l'espace de travail ----------
const NAV = [
  { group: null, items: [{ to: '/app', label: 'Tableau de bord', icon: 'dashboard', end: true }] },
  { group: 'Périmètre', items: [{ to: '/app/projects', label: 'Projets et applications', icon: 'folder' }] },
  { group: 'Audits', items: [{ to: '/app/scans', label: "Campagnes d'audit", icon: 'radar' }, { to: '/app/findings', label: 'Vulnérabilités', icon: 'bug' }, { to: '/app/monitoring', label: 'Monitoring', icon: 'activity' }, { to: '/app/reports', label: 'Rapports', icon: 'file' }] },
  { group: 'Organisation', items: [{ to: '/app/notifications', label: 'Notifications', icon: 'bell', badge: true }, { to: '/app/members', label: 'Membres et rôles', icon: 'users' }, { to: '/app/billing', label: 'Abonnement', icon: 'card' }, { to: '/app/settings', label: 'Paramètres', icon: 'settings' }] },
]
export function Shell() {
  const { me, loading, reload } = useAuth()
  const [theme, toggle] = useTheme()
  const nav = useNavigate()
  const loc = useLocation()
  const [open, setOpen] = useState(false)
  const [verifyLinks, setVerifyLinks] = useState<any>(null)
  const toast = useToast()
  const mainRef = useRef<HTMLElement>(null)
  useEffect(() => { setOpen(false); window.scrollTo({ top: 0 }) }, [loc.pathname])
  if (loading) return <div className="main" style={{ margin: '0 auto' }}><Skeleton kind="cards" n={5} /><div style={{ height: 18 }} /><Skeleton /></div>
  if (!me) return <Navigate to="/login" replace />
  if (me.mfaRequired) return <Navigate to="/app/settings?mfa=required" replace />
  if (!me.org) return <Navigate to="/no-organization" replace />
  const item = (it: any) => (
    <NavLink key={it.to} to={it.to} end={it.end} className={({ isActive }) => 'nav' + (isActive ? ' active' : '')} title={it.label}>
      <Icon name={it.icon} />
      <span className="lbl">{it.label}</span>
      {it.badge && me.unread > 0 && <span className="pill">{me.unread}</span>}
    </NavLink>
  )
  const logout = async () => {
    await api('/auth/logout', { method: 'POST' }).catch(() => {})
    await reload()
    nav('/login')
  }
  const switchOrg = async (orgId: string) => {
    await api('/auth/switch-org', { method: 'POST', body: { orgId } })
    await reload()
    nav('/app')
  }
  const initials = String(me.user.name ?? '?').split(/\s+/).map((s: string) => s[0]).join('').slice(0, 2).toUpperCase()
  return (
    <div className="shell">
      <div className={'scrim' + (open ? ' open' : '')} onClick={() => setOpen(false)} />
      <aside className={'side' + (open ? ' open' : '')} aria-label="Navigation principale">
        <div className="row between" style={{ gap: 0 }}>
          <Brand to="/app" />
          <button className="iconbtn" style={{ display: open ? 'inline-grid' : 'none', marginBottom: 12 }} onClick={() => setOpen(false)} aria-label="Fermer le menu"><Icon name="x" /></button>
        </div>
        {me.memberships?.length > 1 && (
          <select className="orgswitch" value={me.org.id} onChange={(e) => switchOrg(e.target.value)} aria-label="Organisation">
            {me.memberships.map((m: any) => <option key={m.orgId} value={m.orgId}>{m.name}</option>)}
          </select>
        )}
        {NAV.map((g, i) => (
          <React.Fragment key={i}>
            {g.group && <div className="navgroup">{g.group}</div>}
            {g.items.map(item)}
          </React.Fragment>
        ))}
        {me.user.isSuperAdmin && (
          <>
            <div className="navgroup">Plateforme</div>
            {item({ to: '/admin', label: 'Super Administration', icon: 'shield' })}
          </>
        )}
        <div className="foot">
          <div className="row who" style={{ flexWrap: 'nowrap' }}>
            <span className="avatar">{initials}</span>
            <div style={{ minWidth: 0 }}><b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{me.user.name}</b><div className="muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{me.org.name} · {ROLE_FR[me.role]}</div></div>
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <button className="iconbtn" onClick={toggle} title={theme === 'dark' ? 'Thème clair' : 'Thème sombre'} aria-label="Changer de thème"><Icon name={theme === 'dark' ? 'sun' : 'moon'} /></button>
            <button className="iconbtn" onClick={logout} title="Déconnexion" aria-label="Déconnexion"><Icon name="logout" /></button>
          </div>
        </div>
      </aside>
      <div style={{ minWidth: 0 }}>
        <header className="topbar">
          <button className="iconbtn" onClick={() => setOpen(true)} aria-label="Ouvrir le menu"><Icon name="menu" /></button>
          <Brand to="/app" />
          <Link to="/app/notifications" className="iconbtn right" aria-label="Notifications"><Icon name="bell" />{me.unread > 0 && <span className="pill">{me.unread}</span>}</Link>
        </header>
        <main className="main" ref={mainRef}>
          {!me.user.emailVerified && (
            <div className="note warn">
              <div className="row between">
                <span>Votre adresse e-mail n'est pas encore confirmée.</span>
                <button className="btn sm" onClick={async () => { const r = await api('/auth/verify-email/send', { method: 'POST' }); setVerifyLinks(r.devLinks ?? null); if (!r.devLinks) toast.success('E-mail de confirmation envoyé.') }}>Renvoyer le lien</button>
              </div>
              {verifyLinks && <div style={{ marginTop: 8 }}><DevLinks links={verifyLinks} /></div>}
            </div>
          )}
          {me.org.status === 'SUSPENDED' && <Err msg="Cette organisation est suspendue." />}
          <Outlet />
          <FooterLight />
        </main>
      </div>
    </div>
  )
}
