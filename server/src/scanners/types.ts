// Types partagés entre les moteurs d'analyse.
import type { ScanScope } from './http.js'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export type F = {
  severity: Severity; title: string; description: string; resource: string; evidence: string; recommendation: string
  category: string; cwe?: string; owasp?: string
}
export type Test = { group: string; browser?: string; name: string; status: 'PASS' | 'FAIL' | 'SKIP'; detail: string; durationMs: number }
export type Metric = { group: string; name: string; value: number; unit: string }

/** Contexte d'exécution d'une campagne : périmètre, options, progression et annulation. */
export type ScanContext = {
  scanId: string
  orgId: string
  app: any
  scope: ScanScope
  profile: 'STANDARD' | 'DEEP' | 'LOAD'
  active: boolean // contrôles actifs autorisés (section 14.4)
  config: any
  browsers: string[]
  progress: (pct: number, stage: string) => Promise<void>
  cancelled: () => Promise<boolean>
  log: (msg: string) => void
}

export class Collector {
  findings: F[] = []
  tests: Test[] = []
  metrics: Metric[] = []
  info: Record<string, any> = {}
  add(f: F) {
    if (!this.findings.some((x) => x.title === f.title && x.resource === f.resource)) this.findings.push(f)
  }
  test(group: string, name: string, ok: boolean | 'SKIP', detail = '', ms = 0, browser = '') {
    this.tests.push({ group, browser, name, status: ok === 'SKIP' ? 'SKIP' : ok ? 'PASS' : 'FAIL', detail: detail.slice(0, 800), durationMs: Math.round(ms) })
  }
  metric(group: string, name: string, value: number, unit: string) {
    this.metrics.push({ group, name, value: Math.round(value * 10) / 10, unit })
  }
}
