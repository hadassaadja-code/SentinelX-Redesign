// Moteur de cybersécurité (section 6). Contrôles passifs par défaut ; contrôles actifs non destructifs
// (réflexion, redirection ouverte, signatures d'erreur SQL, CORS, méthodes) uniquement si l'autorisation
// "ACTIVE" a été déclarée sur la cible (section 14.4). Aucune charge utile destructrice n'est envoyée.
import dns from 'node:dns'
import net from 'node:net'
import tls from 'node:tls'
import { cut, errMsg, guardedLookup, inScope, safeRequest, type Fetched } from './http.js'
import { Collector, type ScanContext, type Severity } from './types.js'

const MARK = 'sxprobe7731'

function tlsProbe(host: string, port: number, opts: { minVersion?: any; maxVersion?: any } = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, lookup: guardedLookup as any, timeout: 8000, ...opts }, () => {
      const c: any = s.getPeerCertificate(true)
      const cipher = s.getCipher()
      const out = {
        authorized: s.authorized, error: s.authorizationError ? String(s.authorizationError) : null, protocol: s.getProtocol(), cipher: cipher?.name,
        validTo: c?.valid_to, validFrom: c?.valid_from, subject: c?.subject?.CN, issuer: c?.issuer?.O ?? c?.issuer?.CN, altNames: c?.subjectaltname, bits: c?.bits, curve: c?.asn1Curve ?? c?.nistCurve ?? null,
        selfSigned: c && c.issuer && c.subject && JSON.stringify(c.issuer) === JSON.stringify(c.subject),
      }
      s.end()
      resolve(out)
    })
    s.on('error', reject)
    s.on('timeout', () => s.destroy(new Error('Délai TLS dépassé')))
  })
}

const SENSITIVE_FILES: Array<{ path: string; test: (r: Fetched) => boolean; sev: Severity; title: string; desc: string; cwe: string }> = [
  { path: '/.git/HEAD', test: (r) => /^ref:\s|^[0-9a-f]{40}/.test(r.body.trim()), sev: 'HIGH', title: 'Dépôt Git exposé publiquement', desc: 'Le dossier .git est accessible : le code source et son historique peuvent être reconstitués.', cwe: 'CWE-538' },
  { path: '/.git/config', test: (r) => /\[core\]/.test(r.body), sev: 'HIGH', title: 'Configuration Git exposée', desc: 'Le fichier .git/config est téléchargeable (dépôts distants, identifiants éventuels).', cwe: 'CWE-538' },
  { path: '/.env', test: (r) => /^[A-Z][A-Z0-9_]*\s*=/m.test(r.body) && !isHtml(r), sev: 'CRITICAL', title: 'Fichier .env exposé publiquement', desc: 'Le fichier de configuration est téléchargeable : il contient généralement des secrets.', cwe: 'CWE-538' },
  { path: '/.svn/entries', test: (r) => /^\d+\s*$/m.test(r.body.slice(0, 20)) || /dir\n/.test(r.body), sev: 'HIGH', title: 'Métadonnées Subversion exposées', desc: 'Le dossier .svn est accessible.', cwe: 'CWE-538' },
  { path: '/.DS_Store', test: (r) => r.body.startsWith('\0\0\0\u0001Bud1'), sev: 'LOW', title: 'Fichier .DS_Store exposé', desc: 'Révèle la liste des fichiers du dossier.', cwe: 'CWE-538' },
  { path: '/phpinfo.php', test: (r) => /phpinfo\(\)|PHP Version/i.test(r.body), sev: 'HIGH', title: 'Page phpinfo accessible', desc: 'Expose la configuration complète du serveur PHP.', cwe: 'CWE-200' },
  { path: '/server-status', test: (r) => /Apache Server Status/i.test(r.body), sev: 'MEDIUM', title: 'Page Apache server-status accessible', desc: 'Expose les requêtes en cours et les adresses des clients.', cwe: 'CWE-200' },
  { path: '/actuator/env', test: (r) => /propertySources|systemProperties/.test(r.body), sev: 'CRITICAL', title: 'Spring Actuator /env exposé', desc: 'Expose les variables d\'environnement et secrets de l\'application.', cwe: 'CWE-200' },
  { path: '/actuator', test: (r) => /_links|"health"/.test(r.body) && !isHtml(r), sev: 'MEDIUM', title: 'Spring Actuator exposé', desc: 'Les points de terminaison de supervision sont accessibles sans authentification.', cwe: 'CWE-200' },
  { path: '/wp-config.php.bak', test: (r) => /DB_PASSWORD/.test(r.body), sev: 'CRITICAL', title: 'Sauvegarde wp-config exposée', desc: 'Les identifiants de base de données sont téléchargeables.', cwe: 'CWE-538' },
  { path: '/config.json', test: (r) => /(password|secret|api[_-]?key|token)/i.test(r.body) && r.body.trim().startsWith('{'), sev: 'HIGH', title: 'Fichier config.json contenant des secrets', desc: 'Un fichier de configuration JSON avec des clés sensibles est accessible.', cwe: 'CWE-538' },
  { path: '/backup.zip', test: (r) => r.body.startsWith('PK'), sev: 'HIGH', title: 'Archive de sauvegarde exposée', desc: 'Une archive est téléchargeable à la racine du site.', cwe: 'CWE-538' },
  { path: '/.htaccess', test: (r) => /RewriteRule|AuthType|Order\s/i.test(r.body), sev: 'LOW', title: 'Fichier .htaccess lisible', desc: 'La configuration du serveur web est exposée.', cwe: 'CWE-538' },
  { path: '/composer.json', test: (r) => /"require"/.test(r.body) && !isHtml(r), sev: 'LOW', title: 'composer.json exposé', desc: 'Révèle les dépendances et versions utilisées.', cwe: 'CWE-200' },
  { path: '/package.json', test: (r) => /"dependencies"|"name"/.test(r.body) && r.body.trim().startsWith('{'), sev: 'LOW', title: 'package.json exposé', desc: 'Révèle les dépendances et versions utilisées.', cwe: 'CWE-200' },
  { path: '/elmah.axd', test: (r) => /Error Log/i.test(r.body), sev: 'HIGH', title: 'Journal d\'erreurs ELMAH exposé', desc: 'Les erreurs détaillées (et parfois les sessions) sont consultables.', cwe: 'CWE-200' },
]
const isHtml = (r: Fetched) => (r.headers.get('content-type') ?? '').includes('html')

const SQL_ERRORS = [/You have an error in your SQL syntax/i, /Warning: mysql_/i, /unterminated quoted string/i, /PG::SyntaxError/i, /ORA-\d{5}/, /Microsoft OLE DB Provider for SQL Server/i, /SQLSTATE\[/i, /SQLite3::|sqlite3\.OperationalError/i, /Unclosed quotation mark/i, /syntax error at or near/i, /MySqlException|MySQLSyntaxErrorException/i, /PDOException/i]
const STACK_TRACES = [/Traceback \(most recent call last\)/, /at [\w.$]+\([\w]+\.java:\d+\)/, /Stack trace:\s*#0/, /\bat\s+.+\.(js|ts):\d+:\d+\)?\s*$/m, /Exception in thread/, /System\.\w+Exception/, /Whoops! There was an error/i, /Laravel.*Exception|Illuminate\\/, /Django Version:|DEBUG = True/]

// Bibliothèques JavaScript : versions minimales considérées comme corrigées pour les vulnérabilités publiques majeures
const JS_LIBS: Array<{ name: string; re: RegExp; safe: string; cve: string }> = [
  { name: 'jQuery', re: /jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, safe: '3.5.0', cve: 'CVE-2020-11022/11023 (XSS)' },
  { name: 'jQuery UI', re: /jquery-ui[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, safe: '1.13.2', cve: 'CVE-2022-31160 (XSS)' },
  { name: 'Bootstrap', re: /bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min|\.bundle(?:\.min)?)?\.js/i, safe: '4.3.1', cve: 'CVE-2019-8331 (XSS)' },
  { name: 'AngularJS', re: /angular(?:\.min)?\.js|angular[-.](\d+\.\d+\.\d+)/i, safe: '1.8.4', cve: 'fin de vie, XSS multiples' },
  { name: 'Lodash', re: /lodash[-.]?(\d+\.\d+\.\d+)/i, safe: '4.17.21', cve: 'CVE-2021-23337 (injection de prototype)' },
  { name: 'Moment.js', re: /moment[-.]?(\d+\.\d+\.\d+)/i, safe: '2.29.4', cve: 'CVE-2022-31129 (ReDoS)' },
  { name: 'Vue', re: /vue[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i, safe: '2.6.0', cve: 'XSS ancien' },
]
const cmpVer = (a: string, b: string) => {
  const x = a.split('.').map(Number), y = b.split('.').map(Number)
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0)
  return 0
}

/** Analyse de la Content-Security-Policy. */
export function analyzeCsp(csp: string): string[] {
  const issues: string[] = []
  const d: Record<string, string[]> = {}
  for (const part of csp.split(';')) {
    const [k, ...v] = part.trim().split(/\s+/)
    if (k) d[k.toLowerCase()] = v
  }
  const script = d['script-src'] ?? d['default-src'] ?? []
  if (!d['default-src'] && !d['script-src']) issues.push('ni default-src ni script-src : les scripts ne sont pas restreints')
  if (script.includes("'unsafe-inline'") && !script.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"))) issues.push("script-src autorise 'unsafe-inline' sans nonce ni hash")
  if (script.includes("'unsafe-eval'")) issues.push("script-src autorise 'unsafe-eval'")
  if (script.includes('*') || script.some((s) => /^https?:$/.test(s))) issues.push('script-src autorise toute origine (* ou https:)')
  if (script.some((s) => /^https?:\/\/\*\./.test(s))) issues.push('script-src autorise des sous-domaines génériques')
  if (!d['object-src'] && !(d['default-src'] ?? []).includes("'none'")) issues.push("object-src absent (recommandé : 'none')")
  if (!d['base-uri']) issues.push("base-uri absent (recommandé : 'self')")
  if (!d['frame-ancestors']) issues.push('frame-ancestors absent (clickjacking)')
  if (d['report-only']) issues.push('politique en mode report-only uniquement')
  return issues
}

export async function runSecurity(ctx: ScanContext, col: Collector): Promise<void> {
  const app = ctx.app
  const add = (severity: Severity, title: string, description: string, resource: string, evidence: string, recommendation: string, category: string, cwe = '', owasp = '') =>
    col.add({ severity, title, description, resource, evidence: cut(evidence, 600), recommendation, category, cwe, owasp })
  const get = (url: string, o: any = {}) => safeRequest(url, { scope: ctx.scope, ...o })

  await ctx.progress(5, 'Sécurité : connexion à la cible')
  const page = await get(app.url)
  const h = page.headers
  const u = new URL(page.url)
  const https = u.protocol === 'https:'
  const html = page.body
  const base = `${u.protocol}//${u.host}`
  col.info.finalUrl = page.url
  col.info.status = page.status
  col.info.server = h.get('server') ?? ''
  const missing = (name: string) => `En-tête « ${name} » absent de la réponse HTTP ${page.status} de ${page.url}`

  // ===== Transport et TLS (6.2) =====
  await ctx.progress(10, 'Sécurité : transport et TLS')
  if (!https) {
    add('HIGH', 'Application servie sans HTTPS', 'Les échanges ne sont pas chiffrés : identifiants et données peuvent être interceptés.', page.url, `URL finale après redirections : ${page.url}`, 'Activer HTTPS avec un certificat valide et rediriger tout le trafic HTTP vers HTTPS.', 'TRANSPORT', 'CWE-319', 'A02:2021')
  } else {
    if (!u.port) {
      try {
        const plain = await get(`http://${u.hostname}/`, { readBody: false, sameOriginOnly: false })
        if (new URL(plain.url).protocol === 'http:') add('MEDIUM', 'HTTP non redirigé vers HTTPS', 'La version HTTP du site répond sans rediriger vers HTTPS.', `http://${u.hostname}/`, `GET http://${u.hostname}/ → HTTP ${plain.status} sans redirection vers https`, 'Rediriger systématiquement (301) le trafic HTTP vers HTTPS.', 'TRANSPORT', 'CWE-319', 'A02:2021')
      } catch {}
    }
    const port = Number(u.port) || 443
    try {
      const t = await tlsProbe(u.hostname, port)
      const days = t.validTo ? Math.floor((new Date(t.validTo).getTime() - Date.now()) / 86400_000) : null
      col.info.tls = { ...t, daysLeft: days }
      if (!t.authorized) add('HIGH', 'Certificat TLS non valide', 'Le certificat présenté ne peut pas être validé (chaîne, nom de domaine ou expiration).', u.host, `Erreur de validation : ${t.error} — sujet : ${t.subject}, émetteur : ${t.issuer}${t.selfSigned ? ' (auto-signé)' : ''}`, 'Installer un certificat valide couvrant ce nom de domaine avec la chaîne complète.', 'TLS', 'CWE-295', 'A02:2021')
      else if (days !== null && days < 30) add(days < 7 ? 'HIGH' : 'MEDIUM', 'Certificat TLS bientôt expiré', `Le certificat expire dans ${days} jour(s).`, u.host, `valid_to : ${t.validTo}`, 'Renouveler le certificat et automatiser le renouvellement.', 'TLS', 'CWE-295', 'A02:2021')
      if (t.bits && !t.curve && t.bits < 2048) add('MEDIUM', 'Clé RSA du certificat trop courte', `La clé publique RSA fait ${t.bits} bits.`, u.host, `bits : ${t.bits}`, 'Utiliser une clé RSA de 2048 bits minimum ou une clé ECDSA P-256.', 'TLS', 'CWE-326', 'A02:2021')
      if (t.protocol === 'TLSv1' || t.protocol === 'TLSv1.1') add('MEDIUM', 'Protocole TLS obsolète négocié', 'Le serveur négocie une version de TLS dépréciée.', u.host, `Protocole négocié : ${t.protocol}`, "Désactiver TLS 1.0 et 1.1, n'autoriser que TLS 1.2 et 1.3.", 'TLS', 'CWE-326', 'A02:2021')
      if (t.cipher && /RC4|DES|NULL|EXPORT|MD5/i.test(t.cipher)) add('HIGH', 'Suite de chiffrement faible', 'La suite négociée est considérée comme cassée ou obsolète.', u.host, `Cipher : ${t.cipher}`, 'Restreindre les suites aux algorithmes modernes (AES-GCM, ChaCha20).', 'TLS', 'CWE-327', 'A02:2021')
      // Le serveur accepte-t-il encore TLS 1.0/1.1 ? (tentative volontairement limitée aux anciennes versions)
      try {
        const old = await tlsProbe(u.hostname, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1' })
        if (old.protocol) add('MEDIUM', 'TLS 1.0 / 1.1 encore accepté', 'Le serveur accepte des versions de TLS dépréciées, vulnérables à des attaques connues (BEAST, POODLE sur TLS).', u.host, `Connexion établie en ${old.protocol}`, 'Désactiver TLS 1.0 et 1.1 côté serveur.', 'TLS', 'CWE-326', 'A02:2021')
      } catch {}
    } catch (e) {
      col.info.tlsError = errMsg(e)
    }
    const hsts = h.get('strict-transport-security')
    if (!hsts) add('MEDIUM', 'En-tête HSTS manquant', "Sans HSTS, un navigateur peut être forcé à utiliser HTTP lors d'une attaque de type downgrade.", page.url, missing('Strict-Transport-Security'), 'Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains', 'HEADERS', 'CWE-319', 'A05:2021')
    else {
      const age = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0)
      if (age < 15552000) add('LOW', 'HSTS avec durée trop courte', 'La durée max-age est inférieure à 180 jours.', page.url, `Strict-Transport-Security: ${hsts}`, 'Porter max-age à 31536000 (1 an) au minimum.', 'HEADERS', 'CWE-319', 'A05:2021')
      if (!/includeSubDomains/i.test(hsts)) add('INFO', 'HSTS sans includeSubDomains', 'Les sous-domaines ne bénéficient pas de la protection HSTS.', page.url, `Strict-Transport-Security: ${hsts}`, 'Ajouter includeSubDomains si tous les sous-domaines sont en HTTPS.', 'HEADERS', '', 'A05:2021')
    }
    const mixed = html.match(/<(script|img|iframe|link|video|audio|source)\b[^>]*(?:src|href)\s*=\s*["']http:\/\/[^"']+["'][^>]*>/i)
    if (mixed) add('MEDIUM', 'Contenu mixte (ressource HTTP sur page HTTPS)', 'Une ressource est chargée en clair depuis une page chiffrée.', page.url, mixed[0], 'Charger toutes les ressources en HTTPS.', 'TRANSPORT', 'CWE-319', 'A02:2021')
  }

  // ===== En-têtes de sécurité =====
  await ctx.progress(18, 'Sécurité : en-têtes HTTP')
  const csp = h.get('content-security-policy')
  if (!csp) add('MEDIUM', 'Content-Security-Policy manquante', "Sans CSP, l'impact d'une injection de script (XSS) n'est pas limité par le navigateur.", page.url, missing('Content-Security-Policy'), "Définir une politique CSP restrictive (default-src 'self' au minimum).", 'HEADERS', 'CWE-1021', 'A05:2021')
  else {
    const issues = analyzeCsp(csp)
    if (issues.length) add('LOW', 'Content-Security-Policy permissive', 'La politique CSP présente contient des directives qui affaiblissent la protection.', page.url, `${issues.join(' ; ')}\nCSP : ${cut(csp, 300)}`, "Retirer 'unsafe-inline'/'unsafe-eval', utiliser des nonces, définir object-src 'none', base-uri et frame-ancestors.", 'HEADERS', 'CWE-1021', 'A05:2021')
  }
  if (!h.get('x-frame-options') && !(csp && /frame-ancestors/i.test(csp))) add('MEDIUM', 'Protection anti-clickjacking absente', 'La page peut être intégrée dans une iframe par un site tiers.', page.url, `${missing('X-Frame-Options')} ; pas de directive frame-ancestors dans la CSP`, "Ajouter X-Frame-Options: DENY ou la directive CSP frame-ancestors 'none'.", 'HEADERS', 'CWE-1021', 'A05:2021')
  if (!h.get('x-content-type-options')) add('LOW', 'X-Content-Type-Options manquant', 'Le navigateur peut interpréter un fichier avec un type différent de celui annoncé.', page.url, missing('X-Content-Type-Options'), 'Ajouter : X-Content-Type-Options: nosniff', 'HEADERS', 'CWE-16', 'A05:2021')
  if (!h.get('referrer-policy')) add('LOW', 'Referrer-Policy manquante', 'Les URL internes peuvent être transmises à des sites tiers.', page.url, missing('Referrer-Policy'), 'Ajouter : Referrer-Policy: strict-origin-when-cross-origin', 'HEADERS', 'CWE-200', 'A05:2021')
  if (!h.get('permissions-policy')) add('INFO', 'Permissions-Policy manquante', 'Les fonctionnalités sensibles du navigateur (caméra, micro, géolocalisation) ne sont pas restreintes.', page.url, missing('Permissions-Policy'), 'Déclarer une Permissions-Policy limitant les fonctionnalités inutilisées.', 'HEADERS', '', 'A05:2021')
  if (!(h.get('cross-origin-opener-policy'))) add('INFO', 'Cross-Origin-Opener-Policy absente', 'Isolation des fenêtres ouvertes non garantie.', page.url, missing('Cross-Origin-Opener-Policy'), 'Ajouter : Cross-Origin-Opener-Policy: same-origin', 'HEADERS', '', 'A05:2021')
  const cc = h.get('cache-control') ?? ''
  const cookiesHdr: string[] = (h as any).getSetCookie?.() ?? []
  if (cookiesHdr.length && !/no-store|private/i.test(cc)) add('LOW', 'Réponse avec cookie mise en cache', 'Une réponse qui pose un cookie ne déclare pas Cache-Control: no-store/private : un cache intermédiaire pourrait la conserver.', page.url, `Cache-Control: ${cc || '(absent)'} — ${cookiesHdr.length} Set-Cookie`, 'Ajouter Cache-Control: no-store (ou private) sur les réponses personnalisées.', 'HEADERS', 'CWE-525', 'A05:2021')

  // ===== Divulgation d'informations =====
  const server = h.get('server')
  if (server && /\d/.test(server)) add('LOW', 'Version du serveur exposée', 'La version du serveur facilite la recherche de vulnérabilités connues.', page.url, `Server: ${server}`, "Masquer la version dans l'en-tête Server.", 'DISCLOSURE', 'CWE-200', 'A05:2021')
  for (const name of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
    const v = h.get(name)
    if (v) add('LOW', `Technologie exposée (${name})`, 'La technologie utilisée est divulguée inutilement.', page.url, `${name}: ${v}`, `Supprimer l'en-tête ${name}.`, 'DISCLOSURE', 'CWE-200', 'A05:2021')
  }
  const comments = [...html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]).filter((c) => /(todo|fixme|password|mot de passe|secret|api[_-]?key|debug|hack)/i.test(c))
  if (comments.length) add('INFO', 'Commentaires HTML sensibles', 'Des commentaires contiennent des mots-clés révélateurs (TODO, password, debug…).', page.url, comments.slice(0, 3).map((c) => cut(c.trim(), 120)).join(' | '), 'Retirer les commentaires de développement du code livré en production.', 'DISCLOSURE', 'CWE-615', 'A05:2021')
  const emails = new Set([...html.matchAll(/[\w.+-]+@[\w-]+\.[\w.-]+/g)].map((m) => m[0]).filter((e) => !/\.(png|jpg|svg|js|css)$/i.test(e)))
  if (emails.size > 3) add('INFO', 'Adresses e-mail exposées en clair', `${emails.size} adresses e-mail figurent dans la page (collecte par des robots).`, page.url, [...emails].slice(0, 5).join(', '), 'Obfusquer ou protéger les adresses si elles ne doivent pas être collectées.', 'DISCLOSURE', 'CWE-200', '')

  // ===== Cookies =====
  for (const c of cookiesHdr.slice(0, 10)) {
    const name = c.split('=')[0].trim()
    const sensitive = /sess|sid|token|auth|jwt|remember/i.test(name)
    const lacks: string[] = []
    if (https && !/;\s*secure/i.test(c)) lacks.push('Secure')
    if (!/;\s*httponly/i.test(c)) lacks.push('HttpOnly')
    if (!/;\s*samesite/i.test(c)) lacks.push('SameSite')
    if (lacks.length) add(sensitive ? 'MEDIUM' : 'LOW', `Cookie « ${name} » sans attribut ${lacks.join(', ')}`, 'Les attributs de sécurité du cookie sont incomplets.', page.url, `Set-Cookie: ${c.replace(/=([^;]{6})[^;]*/, '=$1…')}`, 'Définir les attributs Secure, HttpOnly et SameSite sur les cookies.', 'COOKIES', 'CWE-614', 'A05:2021')
    if (sensitive && https && !/^__(Host|Secure)-/.test(name)) add('INFO', `Cookie de session « ${name} » sans préfixe __Host-`, 'Les préfixes de cookie renforcent la liaison au domaine et au chemin.', page.url, `Nom : ${name}`, 'Renommer le cookie avec le préfixe __Host- (Secure, Path=/, sans Domain).', 'COOKIES', 'CWE-614', '')
  }

  // ===== Formulaires et contenu =====
  await ctx.progress(26, 'Sécurité : analyse du contenu')
  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) ?? []
  for (const form of forms.slice(0, 10)) {
    const tag = form.match(/<form\b[^>]*>/i)?.[0] ?? ''
    const action = /action\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]
    if (/type\s*=\s*["']?password/i.test(form)) {
      if (!https) add('HIGH', 'Mot de passe transmis sans chiffrement', 'Un formulaire contenant un champ mot de passe est servi en HTTP.', page.url, cut(tag, 200), 'Servir et soumettre ce formulaire exclusivement en HTTPS.', 'AUTH', 'CWE-319', 'A02:2021')
      if (action && /^http:\/\//i.test(action)) add('HIGH', 'Formulaire de connexion soumis en HTTP', "L'action du formulaire pointe vers une URL non chiffrée.", page.url, cut(tag, 200), 'Soumettre le formulaire vers une URL HTTPS.', 'AUTH', 'CWE-319', 'A02:2021')
      if (/<input[^>]*type\s*=\s*["']?password[^>]*autocomplete\s*=\s*["']?on/i.test(form)) add('INFO', 'Autocomplétion activée sur un champ mot de passe', 'Le navigateur peut mémoriser le mot de passe sur un poste partagé.', page.url, cut(tag, 160), 'Laisser le navigateur gérer (sans autocomplete=on) ou utiliser autocomplete="current-password".', 'AUTH', 'CWE-522', '')
    }
    if (/method\s*=\s*["']?post/i.test(tag) && !/name\s*=\s*["']?[^"'>\s]*(csrf|token|nonce|authenticity|_token|xsrf)/i.test(form)) {
      add('INFO', 'Jeton anti-CSRF non visible dans un formulaire POST', "Aucun champ de type jeton n'a été repéré. Constat non confirmé : la protection peut reposer sur un autre mécanisme (cookie SameSite, en-tête).", page.url, cut(tag, 200), 'Vérifier manuellement la protection CSRF de ce formulaire.', 'CSRF', 'CWE-352', 'A01:2021')
    }
  }
  // Scripts externes sans intégrité (SRI)
  const extScripts = [...html.matchAll(/<script\b[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>/gi)].filter((m) => /^https?:\/\//i.test(m[1]) && !m[1].startsWith(base) && !/\sintegrity\s*=/i.test(m[0]))
  if (extScripts.length) add('LOW', 'Scripts tiers sans Subresource Integrity', `${extScripts.length} script(s) chargé(s) depuis un domaine tiers sans attribut integrity : une compromission du CDN compromettrait la page.`, page.url, extScripts.slice(0, 4).map((m) => m[1]).join('\n'), 'Ajouter integrity="sha384-…" et crossorigin="anonymous" sur les scripts tiers, ou les héberger localement.', 'SUPPLYCHAIN', 'CWE-829', 'A08:2021')
  // Bibliothèques JavaScript obsolètes (6.3, détection par nom de fichier)
  for (const m of html.matchAll(/(?:src)\s*=\s*["']([^"']+\.js)[^"']*["']/gi)) {
    for (const lib of JS_LIBS) {
      const v = lib.re.exec(m[1])?.[1]
      if (v && /^\d+\.\d+/.test(v) && cmpVer(v, lib.safe) < 0) add('MEDIUM', `${lib.name} ${v} obsolète`, `Cette version de ${lib.name} est antérieure à ${lib.safe} et concernée par des vulnérabilités publiées (${lib.cve}).`, m[1], `Script : ${cut(m[1], 160)}`, `Mettre à jour ${lib.name} vers la version ${lib.safe} ou plus récente.`, 'DEPENDENCIES', 'CWE-1104', 'A06:2021')
    }
  }
  // Cibles _blank sans noopener (tabnabbing)
  const blank = [...html.matchAll(/<a\b[^>]*target\s*=\s*["']?_blank[^>]*>/gi)].filter((m) => !/rel\s*=\s*["'][^"']*(noopener|noreferrer)/i.test(m[0]))
  if (blank.length) add('INFO', 'Liens target=_blank sans rel=noopener', `${blank.length} lien(s) ouvrent un nouvel onglet sans rel="noopener" : la page cible pourrait manipuler l'onglet d'origine (anciens navigateurs).`, page.url, cut(blank[0][0], 160), 'Ajouter rel="noopener noreferrer" sur les liens externes.', 'CONTENT', 'CWE-1022', '')

  // ===== Fichiers et chemins sensibles (lecture seule) =====
  await ctx.progress(34, 'Sécurité : fichiers exposés')
  for (const sf of SENSITIVE_FILES) {
    if (await ctx.cancelled()) return
    try {
      const r = await get(`${base}${sf.path}`, { maxBytes: 20000 })
      if (r.status === 200 && sf.test(r)) {
        const keys = sf.path === '/.env' ? ` — clés présentes (valeurs masquées) : ${[...r.body.matchAll(/^([A-Z][A-Z0-9_]*)\s*=/gm)].map((m) => m[1]).slice(0, 8).join(', ')}` : ''
        add(sf.sev, sf.title, sf.desc, `${base}${sf.path}`, `HTTP 200${keys || ` — début : ${cut(r.body.replace(/\s+/g, ' ').trim(), 100)}`}`, "Retirer le fichier de la racine web et bloquer son accès au niveau du serveur ; renouveler les secrets éventuellement exposés.", 'EXPOSURE', sf.cwe, 'A05:2021')
      }
    } catch {}
  }
  // Listage de répertoires
  for (const dir of ['/images/', '/uploads/', '/assets/', '/static/', '/backup/']) {
    try {
      const r = await get(`${base}${dir}`, { maxBytes: 20000 })
      if (r.status === 200 && /<title>Index of|Directory listing for|<h1>Index of/i.test(r.body)) add('MEDIUM', `Listage de répertoire activé (${dir})`, 'Le serveur affiche le contenu du dossier : fichiers non référencés accessibles.', `${base}${dir}`, `HTTP 200 — page « Index of » détectée`, 'Désactiver l\'indexation des répertoires (Options -Indexes, autoindex off).', 'EXPOSURE', 'CWE-548', 'A05:2021')
    } catch {}
  }
  // robots.txt : chemins révélateurs
  try {
    const r = await get(`${base}/robots.txt`, { maxBytes: 20000 })
    if (r.status === 200 && !isHtml(r)) {
      const dis = [...r.body.matchAll(/^Disallow:\s*(\S+)/gim)].map((m) => m[1]).filter((p) => /(admin|backup|private|secret|config|db|sql|old|tmp|test|staging|internal)/i.test(p))
      if (dis.length) add('INFO', 'robots.txt révèle des chemins sensibles', 'Le fichier robots.txt liste des chemins qui attirent l\'attention (administration, sauvegardes…).', `${base}/robots.txt`, dis.slice(0, 8).join(', '), 'Ne pas s\'appuyer sur robots.txt pour masquer des ressources ; protéger ces chemins par authentification.', 'DISCLOSURE', 'CWE-200', '')
    }
  } catch {}
  try {
    const r = await get(`${base}/.well-known/security.txt`, { maxBytes: 5000 })
    col.info.securityTxt = r.status === 200 && /Contact:/i.test(r.body)
    if (!col.info.securityTxt) add('INFO', 'Fichier security.txt absent', 'Aucun point de contact sécurité publié (RFC 9116).', `${base}/.well-known/security.txt`, `HTTP ${r.status}`, 'Publier /.well-known/security.txt avec un contact pour les signalements de vulnérabilités.', 'GOVERNANCE', '', '')
  } catch {}

  // ===== Erreurs trop détaillées =====
  await ctx.progress(42, 'Sécurité : gestion des erreurs')
  try {
    const r = await get(`${base}/sx-${MARK}-inexistant`, { maxBytes: 100000 })
    const trace = STACK_TRACES.find((re) => re.test(r.body))
    if (trace) add('MEDIUM', 'Page d\'erreur avec trace technique', 'Une ressource inexistante renvoie une trace de pile ou des détails internes.', `${base}/sx-${MARK}-inexistant`, `HTTP ${r.status} — extrait : ${cut(r.body.match(trace)?.[0] ?? '', 160)}`, 'Afficher une page d\'erreur générique en production et journaliser les détails côté serveur.', 'DISCLOSURE', 'CWE-209', 'A05:2021')
    if (r.status === 200 && !isHtml(r) === false && /404|not found|introuvable/i.test(r.body) === false) col.info.soft404 = true
  } catch {}

  // ===== DNS : SPF, DMARC, CAA =====
  await ctx.progress(48, 'Sécurité : configuration DNS')
  if (!net.isIP(u.hostname)) {
    const apex = u.hostname.split('.').slice(-2).join('.')
    const txt = async (name: string) => (await dns.promises.resolveTxt(name).catch(() => [])).map((r) => r.join(''))
    const spf = (await txt(apex)).find((t) => /^v=spf1/i.test(t))
    if (!spf) add('LOW', 'Enregistrement SPF absent', `Le domaine ${apex} ne publie pas de politique SPF : usurpation d'expéditeur facilitée.`, apex, 'Aucun TXT "v=spf1" trouvé', 'Publier un enregistrement SPF (ex. "v=spf1 include:… -all").', 'DNS', 'CWE-290', '')
    else if (/\+all/.test(spf)) add('MEDIUM', 'SPF permissif (+all)', 'La politique SPF autorise tout expéditeur.', apex, spf, 'Terminer la politique par -all ou ~all.', 'DNS', 'CWE-290', '')
    const dmarc = (await txt(`_dmarc.${apex}`)).find((t) => /^v=DMARC1/i.test(t))
    if (!dmarc) add('LOW', 'Enregistrement DMARC absent', `Le domaine ${apex} ne publie pas de politique DMARC.`, `_dmarc.${apex}`, 'Aucun TXT "v=DMARC1" trouvé', 'Publier un enregistrement DMARC (p=quarantine ou p=reject).', 'DNS', 'CWE-290', '')
    else if (/p=none/i.test(dmarc)) add('INFO', 'DMARC en mode surveillance (p=none)', 'La politique DMARC n\'impose aucune action sur les messages usurpés.', `_dmarc.${apex}`, dmarc, 'Passer progressivement à p=quarantine puis p=reject.', 'DNS', 'CWE-290', '')
    const caa = await dns.promises.resolveCaa(apex).catch(() => [])
    if (!caa.length) add('INFO', 'Enregistrement CAA absent', 'Aucune restriction sur les autorités de certification habilitées à émettre pour ce domaine.', apex, 'Aucun enregistrement CAA', 'Publier un enregistrement CAA listant vos autorités de certification.', 'DNS', '', '')
    col.info.dns = { spf: !!spf, dmarc: !!dmarc, caa: caa.length > 0 }
  }

  // ===== Contrôles actifs non destructifs (autorisation ACTIVE requise) =====
  if (!ctx.active) {
    col.info.activeSkipped = true
    return
  }
  await ctx.progress(55, 'Sécurité : CORS et méthodes HTTP')
  // CORS : réflexion d'origine arbitraire
  try {
    const r = await get(page.url, { readBody: false, headers: { origin: 'https://sentinelx-check.invalid' } })
    const acao = r.headers.get('access-control-allow-origin'), acac = r.headers.get('access-control-allow-credentials')
    if (acao === 'https://sentinelx-check.invalid') add(acac === 'true' ? 'HIGH' : 'MEDIUM', 'CORS : origine arbitraire reflétée', `Le serveur renvoie l'origine envoyée dans Access-Control-Allow-Origin${acac === 'true' ? ' avec les identifiants autorisés' : ''} : un site tiers peut lire les réponses.`, page.url, `Origin: https://sentinelx-check.invalid → Access-Control-Allow-Origin: ${acao}${acac ? `, Access-Control-Allow-Credentials: ${acac}` : ''}`, 'Valider l\'origine contre une liste blanche stricte ; ne jamais combiner origine reflétée et credentials.', 'CORS', 'CWE-942', 'A05:2021')
    else if (acao === '*' && acac === 'true') add('MEDIUM', 'CORS : * avec credentials', 'Configuration CORS incohérente et dangereuse.', page.url, `Access-Control-Allow-Origin: * ; Access-Control-Allow-Credentials: true`, 'Restreindre les origines autorisées.', 'CORS', 'CWE-942', 'A05:2021')
    else if (acao === '*') add('INFO', 'CORS ouvert à toutes les origines', 'Toute origine peut lire les réponses publiques de cette ressource. À vérifier si des données sensibles sont exposées.', page.url, 'Access-Control-Allow-Origin: *', "Restreindre les origines autorisées si la ressource n'est pas publique.", 'CORS', 'CWE-942', 'A05:2021')
  } catch {}
  // Méthodes HTTP : OPTIONS et TRACE
  try {
    const r = await get(page.url, { method: 'OPTIONS', readBody: false })
    const allow = r.headers.get('allow') ?? r.headers.get('access-control-allow-methods') ?? ''
    col.info.allowedMethods = allow
    if (/\b(PUT|DELETE|PATCH)\b/i.test(allow) && !app.openapiUrl && app.type === 'WEB') add('INFO', 'Méthodes HTTP étendues annoncées', `Le serveur annonce les méthodes ${allow} sur la page principale.`, page.url, `Allow: ${allow}`, 'Vérifier que ces méthodes sont bien protégées par authentification.', 'CONFIG', 'CWE-749', 'A05:2021')
  } catch {}
  try {
    const r = await get(page.url, { method: 'TRACE', maxBytes: 5000 })
    if (r.status === 200 && /^TRACE \//m.test(r.body)) add('LOW', 'Méthode TRACE activée', 'TRACE renvoie la requête reçue et peut servir à voler des cookies (Cross-Site Tracing) dans certains contextes.', page.url, `TRACE → HTTP 200, corps commence par ${cut(r.body.split('\n')[0], 60)}`, 'Désactiver la méthode TRACE sur le serveur web.', 'CONFIG', 'CWE-16', 'A05:2021')
  } catch {}

  // Paramètres candidats : issus des liens internes de la page
  const params = new Map<string, string>() // url sans valeur → nom du paramètre
  for (const m of html.matchAll(/(?:href)\s*=\s*["']([^"'#\s]+\?[^"'#\s]+)["']/gi)) {
    try {
      const l = new URL(m[1], page.url)
      if (!inScope(ctx.scope, l)) continue
      for (const [k] of l.searchParams) if (params.size < 12) params.set(`${l.origin}${l.pathname}|${k}`, l.href)
    } catch {}
  }
  await ctx.progress(62, 'Sécurité : réflexion et injection (non destructif)')
  let n = 0
  for (const [key, href] of params) {
    if (await ctx.cancelled()) return
    if (n++ >= 8) break
    const name = key.split('|')[1]
    // Réflexion non échappée (XSS réfléchi potentiel) : marqueur inoffensif
    try {
      const probe = new URL(href)
      probe.searchParams.set(name, `${MARK}<"'`)
      const r = await get(probe.href, { maxBytes: 300000 })
      if (r.body.includes(`${MARK}<"'`)) add('HIGH', `Paramètre « ${name} » reflété sans échappement`, 'La valeur du paramètre est renvoyée telle quelle dans la page, caractères spéciaux compris : injection de script (XSS) probable.', probe.href, `GET ${name}=${MARK}<"' → le marqueur apparaît non échappé dans la réponse HTTP ${r.status}`, 'Échapper systématiquement les données à l\'affichage (HTML, attributs, JS) et déployer une CSP.', 'INJECTION', 'CWE-79', 'A03:2021')
      else if (r.body.includes(MARK)) add('INFO', `Paramètre « ${name} » reflété (échappé)`, 'La valeur est renvoyée dans la page mais les caractères spéciaux sont encodés. Constat informatif.', probe.href, `Le marqueur apparaît échappé`, 'Conserver l\'échappement ; vérifier les autres contextes (JS, attributs).', 'INJECTION', 'CWE-79', 'A03:2021')
      // Signature d'erreur SQL avec une apostrophe (aucune modification de données)
      const sq = new URL(href)
      sq.searchParams.set(name, `${sq.searchParams.get(name) ?? ''}'`)
      const r2 = await get(sq.href, { maxBytes: 300000 })
      const sig = SQL_ERRORS.find((re) => re.test(r2.body))
      if (sig) add('HIGH', `Erreur SQL déclenchée par le paramètre « ${name} »`, 'Une apostrophe dans le paramètre provoque une erreur de base de données visible : injection SQL probable. Preuve non destructive.', sq.href, `GET ${name}=…' → HTTP ${r2.status}, message : ${cut(r2.body.match(sig)?.[0] ?? '', 120)}`, 'Utiliser des requêtes préparées (paramétrées) et masquer les erreurs techniques.', 'INJECTION', 'CWE-89', 'A03:2021')
    } catch {}
  }
  // Redirection ouverte : paramètres classiques sur la page principale
  await ctx.progress(70, 'Sécurité : redirections ouvertes')
  for (const p of ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'dest', 'continue']) {
    if (await ctx.cancelled()) return
    try {
      const probe = new URL(page.url)
      probe.searchParams.set(p, 'https://sentinelx-check.invalid/')
      const r = await get(probe.href, { readBody: false, noFollow: true })
      const loc = r.headers.get('location') ?? ''
      if ([301, 302, 303, 307, 308].includes(r.status) && loc.startsWith('https://sentinelx-check.invalid')) {
        add('MEDIUM', `Redirection ouverte via « ${p} »`, 'Le site redirige vers une URL externe arbitraire fournie en paramètre : hameçonnage facilité.', probe.href, `GET ?${p}=https://sentinelx-check.invalid/ → HTTP ${r.status} Location: ${loc}`, "N'accepter que des chemins relatifs ou une liste blanche de destinations.", 'REDIRECT', 'CWE-601', 'A01:2021')
        break
      }
    } catch {}
  }
}
