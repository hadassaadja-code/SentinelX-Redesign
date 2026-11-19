// Pieds de page : version complète (page d'accueil) et version allégée (toutes les autres pages).
// Les coordonnées et liens sont regroupés ici pour être modifiés facilement.
import React from 'react'
import { Link } from 'react-router-dom'
import { Icon } from './ui'

export const CONTACT = {
  phones: ['+229 01 00 00 00 00'],
  city: 'Cotonou, Bénin',
  email: 'contact@sentinelx.bj',
}
const YEAR = new Date().getFullYear()

const LINKS = [
  { label: 'À propos de SentinelX', to: '/#modules' },
  { label: 'Modules', to: '/#modules' },
  { label: 'Formules et tarifs', to: '/register' },
  { label: 'Sécurité de la plateforme', to: '/#securite' },
]
const USEFUL = [
  { label: 'Créer un compte', to: '/register' },
  { label: 'Se connecter', to: '/login' },
  { label: 'Mot de passe oublié', to: '/forgot-password' },
  { label: 'Quality Assurance', to: '/#modules' },
  { label: 'Cybersécurité', to: '/#modules' },
  { label: 'Sécurité des API', to: '/#modules' },
  { label: 'Performance', to: '/#modules' },
  { label: 'Monitoring', to: '/#modules' },
]

/** Pied de page complet, page d'accueil. */
export function Footer() {
  return (
    <footer className="footer" role="contentinfo">
      <div className="footer-in">
        <div className="footer-tag"><span>Plateforme SaaS · QA · Cybersécurité · Performance</span></div>
        <div className="footer-cols">
          <div className="footer-brand">
            <div className="brand" style={{ padding: 0, marginBottom: 14 }}><i><Icon name="shield" /></i><span>SentinelX</span></div>
            <p>SentinelX centralise l'audit de vos sites et API : tests fonctionnels, analyse de sécurité, mesures de performance et surveillance de disponibilité, avec des rapports exploitables et le suivi des corrections.</p>
            <p className="footer-note">Les audits ne sont lancés que sur des cibles dont vous êtes propriétaire ou pour lesquelles vous détenez une autorisation explicite.</p>
          </div>
          <div>
            <h3>Liens</h3>
            <ul>{LINKS.map((l) => <li key={l.label}><Link to={l.to}>{l.label}</Link></li>)}</ul>
          </div>
          <div>
            <h3>Liens utiles</h3>
            <ul>{USEFUL.map((l) => <li key={l.label}><Link to={l.to}>{l.label}</Link></li>)}</ul>
          </div>
          <div>
            <h3>Contactez-nous</h3>
            <ul className="footer-contact">
              {CONTACT.phones.map((p) => <li key={p}><Icon name="phone" /><a href={`tel:${p.replace(/\s/g, '')}`}>{p}</a></li>)}
              <li><Icon name="pin" /><span>{CONTACT.city}</span></li>
              <li><Icon name="mail" /><a href={`mailto:${CONTACT.email}`}>{CONTACT.email}</a></li>
            </ul>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© {YEAR} SentinelX. Tous droits réservés.</span>
          <span>QA · Cybersécurité · API · Performance · Monitoring</span>
        </div>
      </div>
    </footer>
  )
}

/** Pied de page allégé, sur une ligne, pour l'espace de travail et les pages de connexion. */
export function FooterLight() {
  return (
    <footer className="footer-light" role="contentinfo">
      <span>© {YEAR} SentinelX</span>
      <nav aria-label="Liens de pied de page">
        <Link to="/">Accueil</Link>
        <Link to="/#modules">Modules</Link>
        <a href={`mailto:${CONTACT.email}`}>Contact</a>
      </nav>
      <span className="faint">QA · Cybersécurité · Performance</span>
    </footer>
  )
}
