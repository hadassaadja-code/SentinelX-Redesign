// Génération des rapports (section 10) : PDF détaillé par campagne, synthèse d'organisation, CSV, JSON et SARIF.
import PDFDocument from 'pdfkit'

const SEV_FR: Record<string, string> = { CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Information' }
const SEV_COLOR: Record<string, string> = { CRITICAL: '#b91c1c', HIGH: '#c2410c', MEDIUM: '#a16207', LOW: '#1d4ed8', INFO: '#475569' }
const STATUS_FR: Record<string, string> = { DETECTED: 'Détectée', CONFIRMED: 'Confirmée', ASSIGNED: 'Assignée', IN_PROGRESS: 'En cours', FIXED: 'Corrigée', RETESTED: 'Retestée', CLOSED: 'Clôturée', FALSE_POSITIVE: 'Faux positif' }
const MODULE_FR: Record<string, string> = { QA: 'QA', SECURITY: 'Sécurité', API: 'API', PERFORMANCE: 'Performance' }
const GROUP_FR: Record<string, string> = { STATIC: 'Contrôles statiques', BROWSER: 'Navigateur', ACCESSIBILITY: 'Accessibilité', FORMS: 'Formulaires', VISUAL: 'Comparaison visuelle', API: 'API', PERF: 'Performance', LOAD: 'Test de charge' }
const fmtDate = (d: any) => (d ? new Date(d).toLocaleString('fr-FR') : '-')
// La police intégrée ne couvre que le jeu Latin-1 : on remplace le reste
const safe = (s: any) => String(s ?? '').replace(/[→]/g, '->').replace(/[…]/g, '...').replace(/[≥]/g, '>=').replace(/[—]/g, '-').replace(/[«»]/g, '"').replace(/[^\x09\x0A\x0D\x20-\x7E -ÿ]/g, '?')

const INK = '#0f2339', ACCENT = '#5b4bdb', TEXT = '#1f2937', MUTED = '#64748b', LINE = '#e2e5f2'

export function buildCsv(scan: any): string {
  const esc = (v: any) => {
    let s = String(v ?? '')
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s // neutralise les formules dans les tableurs
    return `"${s.replace(/"/g, '""')}"`
  }
  const rows = [['type', 'module', 'gravite_ou_statut', 'titre', 'ressource', 'preuve_ou_detail', 'recommandation', 'cwe', 'owasp', 'statut_suivi']]
  for (const f of scan.findings) rows.push(['constat', f.module, f.severity, f.title, f.resource, f.evidence, f.recommendation, f.cwe, f.owasp, f.status])
  for (const t of scan.testResults) rows.push(['test', t.group, t.status, t.name, scan.application.url, t.detail, '', '', '', t.browser])
  for (const m of scan.metrics) rows.push(['metrique', m.group, '', m.name, scan.application.url, `${m.value} ${m.unit}`, '', '', '', ''])
  return '﻿' + rows.map((r) => r.map(esc).join(';')).join('\r\n')
}

/** SARIF 2.1.0 : format d'échange des constats (import dans GitHub Code Scanning, IDE, outils de suivi). */
export function buildSarif(scan: any): any {
  const level: Record<string, string> = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' }
  const rules = new Map<string, any>()
  const results = scan.findings.map((f: any) => {
    const id = `SX-${f.category || f.module}-${f.title.replace(/[^a-z0-9]+/gi, '-').slice(0, 40)}`.toUpperCase()
    if (!rules.has(id)) rules.set(id, { id, name: f.title, shortDescription: { text: f.title }, fullDescription: { text: f.description }, help: { text: f.recommendation }, properties: { tags: [f.category, f.cwe, f.owasp].filter(Boolean), 'security-severity': ({ CRITICAL: '9.5', HIGH: '7.5', MEDIUM: '5.0', LOW: '2.5', INFO: '0.0' } as any)[f.severity] } })
    return { ruleId: id, level: level[f.severity], message: { text: `${f.description}\n\nPreuve : ${f.evidence}\n\nRecommandation : ${f.recommendation}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.resource } } }], properties: { severity: f.severity, status: f.status, cwe: f.cwe, owasp: f.owasp, fingerprint: f.fingerprint } }
  })
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'SentinelX', version: '1.0', informationUri: 'https://sentinelx.local', rules: [...rules.values()] } }, results, invocations: [{ executionSuccessful: scan.status === 'DONE', startTimeUtc: scan.startedAt, endTimeUtc: scan.finishedAt }] }] }
}

// ---------- Primitives de dessin PDF ----------
function pdfDoc(title: string) {
  const doc = new PDFDocument({ size: 'A4', margin: 50, info: { Title: safe(title), Author: 'SentinelX' }, bufferPages: true })
  const chunks: Buffer[] = []
  doc.on('data', (c: Buffer) => chunks.push(c))
  const W = doc.page.width - 100
  const h2 = (t: string) => {
    if (doc.y > 690) doc.addPage()
    doc.moveDown(1).fillColor(INK).font('Helvetica-Bold').fontSize(14).text(safe(t))
    doc.moveTo(50, doc.y + 2).lineTo(50 + W, doc.y + 2).strokeColor(ACCENT).lineWidth(1.5).stroke()
    doc.moveDown(0.6).fillColor(TEXT).font('Helvetica').fontSize(10)
  }
  const kv = (k: string, v: any) => doc.font('Helvetica-Bold').fillColor(TEXT).text(safe(k) + ' : ', { continued: true }).font('Helvetica').text(safe(v))
  const para = (t: string, color = TEXT, size = 10) => doc.fillColor(color).font('Helvetica').fontSize(size).text(safe(t)).fontSize(10).fillColor(TEXT)
  /** Barres horizontales : [{label, value, color}] */
  const bars = (items: Array<{ label: string; value: number; color: string }>, max?: number) => {
    const m = Math.max(1, max ?? Math.max(...items.map((i) => i.value)))
    for (const it of items) {
      if (doc.y > 740) doc.addPage()
      const y = doc.y
      doc.font('Helvetica').fontSize(9).fillColor(MUTED).text(safe(it.label), 50, y + 1, { width: 90 })
      doc.roundedRect(145, y, W - 140, 11, 3).fillColor('#eff1fa').fill()
      if (it.value > 0) doc.roundedRect(145, y, Math.max(6, ((W - 140) * it.value) / m), 11, 3).fillColor(it.color).fill()
      doc.fillColor(TEXT).font('Helvetica-Bold').fontSize(9).text(String(it.value), 50 + W - 30, y + 1, { width: 30, align: 'right' })
      doc.y = y + 16
    }
    doc.x = 50
    doc.moveDown(0.5)
  }
  /** Courbe simple : valeurs numériques successives */
  const line = (values: Array<number | null>, opts: { height?: number; label?: string; unit?: string; color?: string } = {}) => {
    const H = opts.height ?? 90
    if (doc.y > 760 - H) doc.addPage()
    const x0 = 50, y0 = doc.y + 6, w = W, h = H
    const vals = values.filter((v): v is number => v != null)
    const max = Math.max(1, ...vals), min = 0
    doc.rect(x0, y0, w, h).strokeColor(LINE).lineWidth(0.5).stroke()
    for (let i = 1; i < 4; i++) doc.moveTo(x0, y0 + (h * i) / 4).lineTo(x0 + w, y0 + (h * i) / 4).strokeColor('#f1f3fa').stroke()
    doc.fontSize(7).fillColor(MUTED).text(safe(`${Math.round(max)}${opts.unit ?? ''}`), x0 + 3, y0 + 2).text(safe(`${min}${opts.unit ?? ''}`), x0 + 3, y0 + h - 10)
    if (values.length > 1) {
      let started = false
      values.forEach((v, i) => {
        if (v == null) return
        const px = x0 + (i / (values.length - 1)) * w, py = y0 + h - ((v - min) / (max - min || 1)) * (h - 14) - 6
        if (!started) { doc.moveTo(px, py); started = true } else doc.lineTo(px, py)
      })
      doc.strokeColor(opts.color ?? ACCENT).lineWidth(1.5).stroke()
    }
    doc.y = y0 + h + 4
    doc.x = 50
    if (opts.label) para(opts.label, MUTED, 8)
  }
  const scoreBadge = (score: number | null, label: string, x: number, y: number) => {
    const c = score == null ? MUTED : score >= 75 ? '#15803d' : score >= 50 ? '#a16207' : '#b91c1c'
    doc.roundedRect(x, y, 110, 54, 8).fillColor('#f6f7fc').fill()
    doc.fillColor(c).font('Helvetica-Bold').fontSize(22).text(score == null ? '-' : String(score), x, y + 8, { width: 110, align: 'center' })
    doc.fillColor(MUTED).font('Helvetica').fontSize(8.5).text(safe(label), x, y + 36, { width: 110, align: 'center' })
  }
  const finish = (): Promise<Buffer> => new Promise((resolve, reject) => {
    const range = doc.bufferedPageRange()
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i)
      doc.fontSize(8).fillColor(MUTED).text(safe(`SentinelX - ${title} - page ${i + 1} / ${range.count}`), 50, doc.page.height - 36, { width: W, align: 'center', lineBreak: false })
    }
    doc.on('end', () => resolve(Buffer.concat(chunks)))
    doc.on('error', reject)
    doc.end()
  })
  return { doc, W, h2, kv, para, bars, line, scoreBadge, finish }
}

function findingBlock(p: ReturnType<typeof pdfDoc>, f: any, i: number) {
  const { doc, kv } = p
  if (doc.y > 640) doc.addPage()
  doc.moveDown(0.5).font('Helvetica-Bold').fontSize(11).fillColor(SEV_COLOR[f.severity] ?? TEXT).text(safe(`${i + 1}. [${SEV_FR[f.severity] ?? f.severity}] ${f.title}`))
  doc.fillColor(TEXT).fontSize(9.5).font('Helvetica')
  doc.text(safe(f.description))
  kv('Ressource', f.resource)
  kv('Preuve', f.evidence)
  kv('Recommandation', f.recommendation)
  const refs = [f.cwe, f.owasp].filter(Boolean).join(' - ')
  if (refs) kv('Références', refs)
  kv('Statut', `${STATUS_FR[f.status] ?? f.status}${f.occurrences > 1 ? ` (vu ${f.occurrences} fois depuis le ${fmtDate(f.firstSeenAt)})` : ''}`)
  if (f.note) kv('Note', f.note)
}

export async function buildPdf(scan: any, orgName: string): Promise<Buffer> {
  const p = pdfDoc(`Rapport d'audit ${scan.application.name}`)
  const { doc, W, h2, kv, para, bars, line, scoreBadge } = p
  const s = scan.summary ?? {}

  // --- Page de garde ---
  doc.rect(0, 0, doc.page.width, 150).fillColor(INK).fill()
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(28).text('SENTINELX', 50, 48)
  doc.fillColor('#9b8cff').font('Helvetica').fontSize(13).text(safe(scan.profile === 'LOAD' ? 'Rapport de test de charge' : "Rapport d'audit"), 50, 86)
  doc.fillColor('#c7cbe6').fontSize(10).text(safe(`${scan.application.name} - ${fmtDate(scan.startedAt)}`), 50, 108)
  doc.y = 175
  doc.fillColor(TEXT).font('Helvetica').fontSize(10)
  const duration = scan.startedAt && scan.finishedAt ? `${Math.round((new Date(scan.finishedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)} s` : '-'
  kv('Organisation', orgName)
  kv('Application', `${scan.application.name} (${scan.application.environment}, ${scan.application.type})`)
  kv('Cible', scan.application.url)
  kv('Date', fmtDate(scan.startedAt))
  kv('Durée', duration)
  kv('Modules exécutés', scan.modules.split(',').map((m: string) => MODULE_FR[m] ?? m).join(', '))
  kv('Profil', `${scan.profile}${s.active ? ' (contrôles actifs autorisés)' : ' (contrôles passifs)'}`)
  kv('Requêtes émises', scan.requestsMade ?? '-')
  kv('Référence', scan.id)

  // Scores
  doc.moveDown(1)
  const y = doc.y
  const badges: Array<[number | null, string]> = [[scan.score, 'Score global']]
  if (s.qa && !s.qa.error) badges.push([s.qa.rate, 'QA (taux de réussite)'])
  if (s.security && !s.security.error) badges.push([s.security.score, 'Sécurité'])
  if (s.api && !s.api.error) badges.push([s.api.score, 'API'])
  if (s.performance && !s.performance.error) badges.push([s.performance.score, 'Performance'])
  badges.slice(0, 4).forEach(([v, l], i) => scoreBadge(v, l, 50 + i * 122, y))
  doc.y = y + 64
  doc.x = 50

  // --- Synthèse ---
  h2('Synthèse')
  if (s.qa) para(s.qa.error ? `QA : échec du module (${s.qa.error})` : `QA : ${s.qa.passed} test(s) réussi(s) sur ${s.qa.total} (${s.qa.rate} %)${s.qa.skipped ? `, ${s.qa.skipped} ignoré(s)` : ''}${s.qa.browserRan ? ' - tests en navigateur réel inclus' : ''}.`)
  if (s.security) {
    const c = s.security.counts ?? {}
    para(s.security.error ? `Sécurité : échec du module (${s.security.error})` : `Sécurité : ${s.security.total} constat(s) - Critique ${c.CRITICAL ?? 0}, Élevée ${c.HIGH ?? 0}, Moyenne ${c.MEDIUM ?? 0}, Faible ${c.LOW ?? 0}, Information ${c.INFO ?? 0}.`)
  }
  if (s.api) para(s.api.error ? `API : échec du module (${s.api.error})` : `API : ${s.api.total} constat(s), ${s.api.passed}/${s.api.tests} test(s) dynamique(s) réussi(s)${s.api.info?.operations != null ? `, ${s.api.info.operations} opération(s) documentée(s)` : ''}.`)
  if (s.performance) para(s.performance.error ? `Performance : échec du module (${s.performance.error})` : `Performance : score ${s.performance.score}/100 - temps moyen ${s.performance.avg} ms, P95 ${s.performance.p95} ms${s.performance.vitals?.lcp ? `, LCP ${Math.round(s.performance.vitals.lcp)} ms` : ''}.`)
  if (s.load) para(`Test de charge : ${s.load.vus} utilisateurs virtuels pendant ${s.load.seconds} s${s.load.aborted ? ` - ${s.load.aborted}` : ''}.`)
  if (scan.comparison) {
    const c = scan.comparison
    doc.moveDown(0.4)
    para(`Comparaison avec l'audit du ${fmtDate(c.previousDate)} : ${c.fixed.length} corrigée(s), ${c.added.length} nouvelle(s), ${c.persistent} persistante(s).`)
  }
  const counts = s.security?.counts ?? s.api?.counts
  if (scan.findings.length) {
    doc.moveDown(0.6)
    const by: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    scan.findings.forEach((f: any) => by[f.severity]++)
    bars(Object.keys(by).map((k) => ({ label: SEV_FR[k], value: by[k], color: SEV_COLOR[k] })))
  }
  void counts

  // --- Constats ---
  const secF = scan.findings.filter((f: any) => f.module === 'SECURITY')
  const apiF = scan.findings.filter((f: any) => f.module === 'API')
  const otherF = scan.findings.filter((f: any) => f.module !== 'SECURITY' && f.module !== 'API')
  if (scan.modules.includes('SECURITY')) {
    h2(`Vulnérabilités et constats de sécurité (${secF.length})`)
    if (!secF.length) para('Aucun constat relevé par les contrôles exécutés.')
    secF.forEach((f: any, i: number) => findingBlock(p, f, i))
    doc.fontSize(10)
  }
  if (scan.modules.includes('API')) {
    h2(`Sécurité de l'API (${apiF.length} constat(s))`)
    if (s.api?.info) {
      kv('Spécification', s.api.info.specUrl ?? '-')
      kv('Opérations', `${s.api.info.operations ?? 0} (dont ${s.api.info.secured ?? 0} protégées)`)
      kv("Schémas d'authentification", (s.api.info.schemes ?? []).join(', ') || 'aucun')
    }
    if (!apiF.length) para('Aucun constat relevé.')
    apiF.forEach((f: any, i: number) => findingBlock(p, f, i))
    doc.fontSize(10)
  }
  if (otherF.length) {
    h2(`Autres constats (${otherF.length})`)
    otherF.forEach((f: any, i: number) => findingBlock(p, f, i))
    doc.fontSize(10)
  }

  // --- Tests ---
  const groups = [...new Set(scan.testResults.map((t: any) => t.group))] as string[]
  if (scan.testResults.length) {
    h2(`Résultats des tests (${scan.testResults.length})`)
    for (const g of groups) {
      const list = scan.testResults.filter((t: any) => t.group === g)
      doc.moveDown(0.3).font('Helvetica-Bold').fontSize(10.5).fillColor(INK).text(safe(`${GROUP_FR[g] ?? g} - ${list.filter((t: any) => t.status === 'PASS').length}/${list.filter((t: any) => t.status !== 'SKIP').length} réussis`))
      doc.fontSize(10)
      for (const t of list) {
        if (doc.y > 720) doc.addPage()
        const color = t.status === 'PASS' ? '#15803d' : t.status === 'FAIL' ? '#b91c1c' : MUTED
        doc.font('Helvetica-Bold').fillColor(color).text(t.status === 'PASS' ? 'RÉUSSI  ' : t.status === 'FAIL' ? 'ÉCHEC  ' : 'IGNORÉ  ', { continued: true })
        doc.fillColor(TEXT).text(safe(`${t.name}${t.browser ? ` [${t.browser}]` : ''}`))
        if (t.detail) doc.font('Helvetica').fontSize(9).fillColor(MUTED).text(safe(t.detail), { indent: 12 }).fontSize(10).fillColor(TEXT)
      }
    }
  }

  // --- Performance ---
  if (scan.metrics.length) {
    h2('Métriques de performance')
    const mgroups = [...new Set(scan.metrics.map((m: any) => m.group))] as string[]
    for (const g of mgroups) {
      doc.moveDown(0.3).font('Helvetica-Bold').fontSize(10.5).fillColor(INK).text(safe({ SERVER: 'Serveur', VITALS: 'Core Web Vitals', LOAD: 'Test de charge', RESOURCES: 'Ressources' }[g] ?? g)).fontSize(10)
      for (const m of scan.metrics.filter((x: any) => x.group === g)) kv(m.name, `${m.value} ${m.unit}`)
    }
    if (s.performance?.samples?.length > 1) line(s.performance.samples, { label: `Temps de réponse des ${s.performance.samples.length} requêtes successives (ms)`, unit: ' ms' })
    if (s.loadSeries?.length > 1) {
      line(s.loadSeries.map((x: any) => x.p95), { label: 'P95 par seconde pendant le test de charge (ms)', unit: ' ms' })
      line(s.loadSeries.map((x: any) => x.rps), { label: 'Requêtes par seconde', color: '#15803d' })
    }
  }

  // --- Conclusion ---
  h2('Conclusion')
  const urgent = scan.findings.filter((f: any) => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.status !== 'FALSE_POSITIVE').length
  para(urgent > 0 ? `${urgent} constat(s) de gravité élevée ou critique nécessitent une correction prioritaire. Un nouvel audit est recommandé après correction.` : scan.findings.length ? "Aucun constat de gravité élevée ou critique n'a été relevé par les contrôles exécutés. Les constats de gravité inférieure restent à traiter." : 'Aucun constat relevé. Consultez le détail des tests exécutés ci-dessus.')
  doc.moveDown(0.6)
  para(`Périmètre : contrôles automatisés ${s.active ? 'passifs et actifs non destructifs' : 'passifs et non destructifs'}, exécutés sur une cible déclarée autorisée${scan.application.verifiedAt ? ' et dont la propriété a été vérifiée' : ''}. Ce rapport ne remplace pas un test d'intrusion complet ; l'absence de constat ne garantit pas l'absence de vulnérabilité.`, MUTED, 8.5)
  return p.finish()
}

/** Rapport de synthèse d'organisation sur une période : état de chaque application, tendances, constats ouverts. */
export async function buildSummaryPdf(data: { orgName: string; from: Date; to: Date; apps: any[]; scans: any[]; findings: any[]; incidents: any[]; uptime: Record<string, number | null> }): Promise<Buffer> {
  const p = pdfDoc('Rapport de synthèse')
  const { doc, h2, kv, para, bars, line, scoreBadge } = p
  doc.rect(0, 0, doc.page.width, 150).fillColor(INK).fill()
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(28).text('SENTINELX', 50, 48)
  doc.fillColor('#9b8cff').font('Helvetica').fontSize(13).text('Rapport de synthèse', 50, 86)
  doc.fillColor('#c7cbe6').fontSize(10).text(safe(`${data.orgName} - du ${data.from.toLocaleDateString('fr-FR')} au ${data.to.toLocaleDateString('fr-FR')}`), 50, 108)
  doc.y = 175
  doc.x = 50
  doc.fillColor(TEXT).font('Helvetica').fontSize(10)
  const done = data.scans.filter((s) => s.status === 'DONE')
  const avg = (a: number[]) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null)
  const open = data.findings.filter((f) => !['FIXED', 'RETESTED', 'CLOSED', 'FALSE_POSITIVE'].includes(f.status))
  const y = doc.y
  scoreBadge(avg(done.map((s) => s.score).filter((x) => x != null)), 'Score moyen', 50, y)
  scoreBadge(done.length, 'Audits terminés', 172, y)
  scoreBadge(open.length, 'Constats ouverts', 294, y)
  scoreBadge(open.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length, 'Critiques / élevés', 416, y)
  doc.y = y + 64
  doc.x = 50
  h2('Constats ouverts par gravité')
  const by: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  open.forEach((f) => by[f.severity]++)
  bars(Object.keys(by).map((k) => ({ label: SEV_FR[k], value: by[k], color: SEV_COLOR[k] })))
  h2('Applications')
  for (const a of data.apps) {
    if (doc.y > 700) doc.addPage()
    const last = done.filter((s) => s.applicationId === a.id).sort((x, y2) => new Date(y2.createdAt).getTime() - new Date(x.createdAt).getTime())[0]
    const openA = open.filter((f) => f.applicationId === a.id)
    doc.font('Helvetica-Bold').fontSize(10.5).fillColor(INK).text(safe(`${a.name} (${a.environment})`)).fontSize(10).fillColor(TEXT)
    kv('URL', a.url)
    kv('Dernier audit', last ? `${fmtDate(last.createdAt)} - score ${last.score ?? '-'}/100` : 'aucun sur la période')
    kv('Constats ouverts', `${openA.length} (${openA.filter((f) => f.severity === 'CRITICAL').length} critique(s), ${openA.filter((f) => f.severity === 'HIGH').length} élevé(s))`)
    kv('Disponibilité', data.uptime[a.id] != null ? `${data.uptime[a.id]} %` : 'non surveillée')
    kv('Incidents', String(data.incidents.filter((i) => i.applicationId === a.id).length))
    doc.moveDown(0.5)
  }
  if (done.length > 1) {
    h2('Évolution des scores')
    line(done.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()).map((s) => s.score), { label: `Score global des ${done.length} audits terminés, du plus ancien au plus récent` })
  }
  h2('Constats critiques et élevés ouverts')
  const top = open.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 25)
  if (!top.length) para('Aucun constat critique ou élevé ouvert.')
  top.forEach((f, i) => findingBlock(p, f, i))
  doc.fontSize(10)
  h2('Incidents de disponibilité')
  if (!data.incidents.length) para('Aucun incident sur la période.')
  for (const i of data.incidents.slice(0, 30)) {
    if (doc.y > 740) doc.addPage()
    para(`${fmtDate(i.startedAt)} - ${i.title} - ${i.status === 'RESOLVED' ? `résolu le ${fmtDate(i.resolvedAt)}` : i.status === 'ACKNOWLEDGED' ? 'pris en charge' : 'ouvert'} (${i.occurrences} occurrence(s))`)
  }
  return p.finish()
}
