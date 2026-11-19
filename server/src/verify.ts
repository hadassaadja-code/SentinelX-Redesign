// Vérification de propriété d'une cible (14.4) : enregistrement DNS TXT, fichier .well-known ou balise meta.
import dns from 'node:dns'
import { safeRequest } from './scanners/http.js'

export const VERIFY_PREFIX = 'sentinelx-verify='

export type VerifyResult = { ok: boolean; method?: 'DNS' | 'HTTP' | 'META'; detail: string }

export async function verifyOwnership(appUrl: string, token: string): Promise<VerifyResult> {
  const u = new URL(appUrl)
  const expected = `${VERIFY_PREFIX}${token}`
  const tried: string[] = []
  // 1. DNS TXT sur _sentinelx.<hôte> ou sur l'hôte lui-même
  for (const name of [`_sentinelx.${u.hostname}`, u.hostname]) {
    try {
      const records = (await dns.promises.resolveTxt(name)).map((r) => r.join(''))
      if (records.some((r) => r.trim() === expected)) return { ok: true, method: 'DNS', detail: `Enregistrement TXT trouvé sur ${name}` }
      tried.push(`DNS TXT ${name} : ${records.length} enregistrement(s), aucun ne correspond`)
    } catch (e: any) {
      tried.push(`DNS TXT ${name} : ${e?.code ?? 'absent'}`)
    }
  }
  // 2. Fichier /.well-known/sentinelx-verification.txt
  try {
    const r = await safeRequest(`${u.origin}/.well-known/sentinelx-verification.txt`, { maxBytes: 2000 })
    if (r.status === 200 && r.body.trim().split(/\s+/).includes(expected)) return { ok: true, method: 'HTTP', detail: 'Fichier .well-known/sentinelx-verification.txt trouvé' }
    tried.push(`HTTP .well-known : ${r.status}`)
  } catch (e: any) {
    tried.push(`HTTP .well-known : ${e?.message ?? 'erreur'}`)
  }
  // 3. Balise <meta name="sentinelx-verify" content="…"> sur la page principale
  try {
    const r = await safeRequest(appUrl, { maxBytes: 500_000 })
    const m = r.body.match(/<meta[^>]+name=["']sentinelx-verify["'][^>]+content=["']([^"']+)["']/i) ?? r.body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']sentinelx-verify["']/i)
    if (m && m[1].trim() === token) return { ok: true, method: 'META', detail: 'Balise meta sentinelx-verify trouvée sur la page principale' }
    tried.push(`META : ${m ? 'balise présente mais jeton différent' : 'balise absente'}`)
  } catch (e: any) {
    tried.push(`META : ${e?.message ?? 'erreur'}`)
  }
  return { ok: false, detail: tried.join(' ; ') }
}
