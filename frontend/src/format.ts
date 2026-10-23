/** Timestamps from the API are naive UTC ISO strings. */
export function formatTs(ts: string, withDate = false): string {
  const d = new Date(ts.endsWith('Z') ? ts : `${ts}Z`)
  if (Number.isNaN(d.getTime())) return ts
  const iso = d.toISOString()
  return withDate ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}` : iso.slice(11, 19)
}

export function formatRange(start: string, end: string): string {
  const a = formatTs(start, true)
  const b = formatTs(end, true)
  return a.slice(0, 10) === b.slice(0, 10) ? `${a} – ${b.slice(11)} UTC` : `${a} – ${b} UTC`
}

/** `/data/uploads/ab12/auth.log` -> `auth.log`; live syslog keeps its URI. */
export function fileName(sourceFile: string): string {
  if (sourceFile.startsWith('syslog://')) return sourceFile
  return sourceFile.replace(/^\w+:\/\//, '').replaceAll('\\', '/').split('/').pop() ?? sourceFile
}

/** `line:17` -> `line 17`, `record:1234` -> `record 1234`. */
export function position(recordRef: string): string {
  return recordRef.replace(':', ' ')
}

/** "auth.log, lines 4–17; access.log, line 6" for a set of events. */
export function describeOrigin(events: { source_file: string; record_ref: string }[]): string {
  const byFile = new Map<string, number[]>()
  const other = new Map<string, string[]>()
  for (const e of events) {
    const name = fileName(e.source_file)
    const [kind, n] = e.record_ref.split(':')
    if (kind === 'line' && /^\d+$/.test(n)) byFile.set(name, [...(byFile.get(name) ?? []), Number(n)])
    else other.set(name, [...(other.get(name) ?? []), position(e.record_ref)])
  }
  const parts = [...byFile].map(([name, nums]) => {
    const lo = Math.min(...nums)
    const hi = Math.max(...nums)
    return lo === hi ? `${name}, line ${lo}` : `${name}, lines ${lo}–${hi}`
  })
  for (const [name, refs] of other) parts.push(refs.length === 1 ? `${name}, ${refs[0]}` : `${name}, ${refs.length} records`)
  return parts.join('; ')
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'] as const

export function severityClass(sev: string): string {
  return (
    {
      critical: 'text-sev-critical',
      high: 'text-sev-high',
      medium: 'text-sev-medium',
      low: 'text-sev-low',
    }[sev] ?? 'text-sev-informational'
  )
}
