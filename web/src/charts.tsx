// Graphiques SVG légers : un seul axe, marques fines, infobulles au survol, couleurs de statut réservées aux gravités.
import React, { useState } from 'react'

const nice = (n: number) => (Math.abs(n) >= 1000 ? `${Math.round(n / 100) / 10}k` : String(Math.round(n * 10) / 10))

export type Series = { name: string; values: Array<number | null>; color?: string }

/** Courbe(s) : une ou plusieurs séries sur un axe commun. */
export function LineChart({ labels, series, height = 160, unit = '', max: maxIn, formatLabel }: { labels: string[]; series: Series[]; height?: number; unit?: string; max?: number; formatLabel?: (l: string) => string }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 600, H = height, padL = 36, padR = 10, padT = 10, padB = 22
  const all = series.flatMap((s) => s.values).filter((v): v is number => v != null)
  if (!all.length) return <div className="empty">Pas encore de données.</div>
  const max = maxIn ?? Math.max(1, ...all) * 1.08
  const n = labels.length
  const x = (i: number) => padL + (n > 1 ? (i / (n - 1)) * (W - padL - padR) : (W - padL - padR) / 2)
  const y = (v: number) => padT + (1 - v / max) * (H - padT - padB)
  const colors = ['var(--accent)', 'var(--chart2)', 'var(--chart3)', 'var(--chart4)']
  const ticks = [0, 0.5, 1].map((t) => t * max)
  const fl = formatLabel ?? ((l: string) => l)
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Graphique" onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} className="grid" />
            <text x={padL - 6} y={y(t) + 3} className="tick" textAnchor="end">{nice(t)}</text>
          </g>
        ))}
        {series.map((s, si) => {
          const pts = s.values.map((v, i) => (v == null ? null : `${x(i)},${y(v)}`))
          const d = pts.reduce((acc, p, i) => (p == null ? acc : acc + (acc && pts[i - 1] != null ? ' L' : ' M') + p), '')
          return (
            <g key={s.name}>
              <path d={d} fill="none" stroke={s.color ?? colors[si % colors.length]} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              {s.values.map((v, i) => v != null && (n < 40 || hover === i) && <circle key={i} cx={x(i)} cy={y(v)} r={hover === i ? 5 : 3} fill={s.color ?? colors[si % colors.length]} stroke="var(--panel)" strokeWidth={2} />)}
            </g>
          )
        })}
        {labels.map((l, i) => (n <= 12 || i % Math.ceil(n / 8) === 0) && <text key={i} x={x(i)} y={H - 6} className="tick" textAnchor="middle">{fl(l)}</text>)}
        {hover != null && <line x1={x(hover)} x2={x(hover)} y1={padT} y2={H - padB} className="cross" />}
        {labels.map((_, i) => <rect key={i} x={x(i) - (W - padL - padR) / Math.max(1, n - 1) / 2} y={0} width={(W - padL - padR) / Math.max(1, n - 1)} height={H} fill="transparent" onMouseEnter={() => setHover(i)} />)}
      </svg>
      {hover != null && (
        <div className="tip">
          <b>{fl(labels[hover])}</b>
          {series.map((s, si) => <div key={s.name}><i style={{ background: s.color ?? colors[si % colors.length] }} />{s.name} : <b>{s.values[hover] == null ? '—' : `${nice(s.values[hover]!)}${unit}`}</b></div>)}
        </div>
      )}
      {series.length > 1 && <div className="legend">{series.map((s, si) => <span key={s.name}><i style={{ background: s.color ?? colors[si % colors.length] }} />{s.name}</span>)}</div>}
    </div>
  )
}

/** Barres verticales (une série). */
export function BarChart({ labels, values, height = 140, unit = '', color = 'var(--accent)', colors, formatLabel }: { labels: string[]; values: number[]; height?: number; unit?: string; color?: string; colors?: string[]; formatLabel?: (l: string) => string }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 600, H = height, padL = 30, padR = 6, padT = 8, padB = 22
  const max = Math.max(1, ...values) * 1.08
  const n = values.length
  const bw = (W - padL - padR) / Math.max(1, n)
  const y = (v: number) => padT + (1 - v / max) * (H - padT - padB)
  const fl = formatLabel ?? ((l: string) => l)
  if (!n) return <div className="empty">Pas encore de données.</div>
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Graphique en barres" onMouseLeave={() => setHover(null)}>
        {[0, 0.5, 1].map((t) => <g key={t}><line x1={padL} x2={W - padR} y1={y(t * max)} y2={y(t * max)} className="grid" /><text x={padL - 5} y={y(t * max) + 3} className="tick" textAnchor="end">{nice(t * max)}</text></g>)}
        {values.map((v, i) => (
          <g key={i} onMouseEnter={() => setHover(i)}>
            <rect x={padL + i * bw + 1} y={0} width={Math.max(1, bw - 2)} height={H} fill="transparent" />
            <rect x={padL + i * bw + bw * 0.2} y={y(v)} width={bw * 0.6} height={Math.max(0, H - padB - y(v))} rx={3} fill={colors?.[i] ?? color} opacity={hover == null || hover === i ? 1 : 0.55} />
          </g>
        ))}
        {labels.map((l, i) => (n <= 14 || i % Math.ceil(n / 10) === 0) && <text key={i} x={padL + i * bw + bw / 2} y={H - 6} className="tick" textAnchor="middle">{fl(l)}</text>)}
      </svg>
      {hover != null && <div className="tip"><b>{fl(labels[hover])}</b><div>{nice(values[hover])}{unit}</div></div>}
    </div>
  )
}

/** Barres horizontales : répartition par catégorie (gravités, statuts…). */
export function HBars({ items, max: maxIn }: { items: Array<{ label: string; value: number; color?: string; href?: string }>; max?: number }) {
  const max = Math.max(1, maxIn ?? Math.max(...items.map((i) => i.value)))
  return (
    <div className="hbars">
      {items.map((it) => (
        <div className="hbar" key={it.label}>
          <span className="lbl">{it.label}</span>
          <div className="bar"><i style={{ width: `${(it.value / max) * 100}%`, background: it.color ?? 'var(--accent)' }} /></div>
          <b>{it.value}</b>
        </div>
      ))}
    </div>
  )
}

/** Anneau de proportion avec valeur centrale. */
export function Donut({ value, label, size = 92, color }: { value: number | null; label?: string; size?: number; color?: string }) {
  const v = value ?? 0
  const c = color ?? (v >= 75 ? 'var(--ok)' : v >= 50 ? 'var(--med)' : 'var(--danger)')
  return (
    <div className="donut" style={{ width: size, height: size, background: `conic-gradient(${c} ${v}%, var(--panel2) 0)` }} title={label}>
      <b>{value == null ? '—' : Math.round(v)}</b>
    </div>
  )
}

/** Mini courbe de disponibilité / temps de réponse (sparkline). */
export function Sparkline({ points, height = 28, width = 140 }: { points: Array<{ up: boolean; responseMs: number | null }>; height?: number; width?: number }) {
  if (!points.length) return <span className="muted small">—</span>
  const max = Math.max(1, ...points.map((p) => p.responseMs ?? 0))
  const w = width / points.length
  return (
    <svg width={width} height={height} className="spark" aria-hidden="true">
      {points.map((p, i) => <rect key={i} x={i * w} y={p.up ? height - Math.max(3, ((p.responseMs ?? 0) / max) * height) : 0} width={Math.max(1, w - 1)} height={p.up ? Math.max(3, ((p.responseMs ?? 0) / max) * height) : height} rx={1} fill={p.up ? 'var(--ok)' : 'var(--danger)'} opacity={p.up ? 0.75 : 1} />)}
    </svg>
  )
}

/** Barre de progression. */
export const Progress = ({ value, label }: { value: number; label?: string }) => (
  <div className="progress" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
    <i style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    {label && <span>{label}</span>}
  </div>
)
