import { useQueries } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { api, type Event } from '../api/client'
import { formatTs } from '../format'
import { useEvidence, type EvidenceRequest } from './useEvidence'

const PAGE = 20

export function EvidenceDrawer() {
  const { current, close } = useEvidence()
  // Keyed by request so paging state resets whenever another marker is opened.
  return current ? <Drawer key={`${current.label}:${current.eventIds[0]}`} current={current} close={close} /> : null
}

function Drawer({ current, close }: { current: EvidenceRequest; close: () => void }) {
  const [page, setPage] = useState(0)
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    panel.current?.focus()
  }, [])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [close])

  const ids = current.eventIds
  const pageIds = ids.slice(page * PAGE, (page + 1) * PAGE)
  const missing = pageIds.filter((id) => !current.known?.has(id))
  const fetched = useQueries({ queries: missing.map((id) => ({ queryKey: ['event', id], queryFn: () => api.event(id) })) })
  const events: (Event | undefined)[] = pageIds.map((id) => current.known?.get(id) ?? fetched[missing.indexOf(id)]?.data)

  const nearby = useMemo(() => {
    if (!current.context || !ids.length) return []
    const cited = new Set(ids)
    const idx = current.context.findIndex((e) => cited.has(e.event_id))
    return idx < 0 ? [] : current.context.slice(Math.max(0, idx - 3), idx + 4)
  }, [current.context, ids])

  const pages = Math.ceil(ids.length / PAGE)

  return (
    <aside
      ref={panel}
      tabIndex={-1}
      role="dialog"
      aria-label={current.label}
      className="fixed inset-y-0 right-0 z-30 flex w-full max-w-xl flex-col border-l border-rule bg-panel shadow-2xl outline-none"
    >
      <header className="flex items-center justify-between border-b border-rule px-5 py-3">
        <div>
          <h2 className="text-base font-semibold">{current.label}</h2>
          <p className="text-sm text-muted">
            {ids.length === 1 ? 'The log line behind this statement' : `${ids.length} log lines behind this statement`}
          </p>
        </div>
        <button type="button" onClick={close} className="rounded px-2 py-1 text-muted hover:bg-raised hover:text-text">
          Close
        </button>
      </header>

      <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
        {events.map((e, i) =>
          e ? <EventCard key={e.event_id} event={e} /> : <div key={pageIds[i]} className="h-24 animate-pulse rounded bg-raised" />,
        )}
        {pages > 1 && (
          <nav className="flex items-center justify-between text-sm text-muted">
            <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)} className="disabled:opacity-40">
              Previous
            </button>
            <span>
              Page {page + 1} of {pages}
            </span>
            <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)} className="disabled:opacity-40">
              Next
            </button>
          </nav>
        )}
        {nearby.length > 0 && (
          <section>
            <h3 className="mb-2 text-sm font-semibold text-muted">Around it in the incident</h3>
            <ol className="space-y-1 font-mono text-xs">
              {nearby.map((e) => (
                <li key={e.event_id} className={ids.includes(e.event_id) ? 'text-evidence' : 'text-muted'}>
                  {formatTs(e.ts, true)} {e.host ?? ''} {e.action ?? e.event_code ?? ''} {e.user ?? ''} {e.src_ip ?? ''}
                </li>
              ))}
            </ol>
          </section>
        )}
      </div>
    </aside>
  )
}

function EventCard({ event: e }: { event: Event }) {
  const [showFields, setShowFields] = useState(false)
  const file = e.source_file.replaceAll('\\', '/').split('/').pop()
  return (
    <article className="rounded border border-rule bg-ink/60">
      <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-rule px-3 py-2 text-sm">
        <span>{formatTs(e.ts, true)}</span>
        <span className="text-muted">{e.source_type}</span>
        <span className="text-muted" title={e.source_file}>
          {file} {e.record_ref}
        </span>
      </div>
      <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-xs leading-relaxed">
        {e.raw}
      </pre>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 border-t border-rule px-3 py-2 text-xs">
        {(['host', 'user', 'src_ip', 'dst_ip', 'process', 'action', 'outcome', 'event_code'] as const)
          .filter((k) => e[k])
          .map((k) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd className="break-all">{String(e[k])}</dd>
            </div>
          ))}
      </dl>
      <div className="border-t border-rule px-3 py-1.5">
        <button type="button" onClick={() => setShowFields(!showFields)} className="text-xs text-muted hover:text-text">
          {showFields ? 'Hide all parsed fields' : 'Show all parsed fields'}
        </button>
        {showFields && (
          <pre className="mt-2 max-h-60 overflow-auto font-mono text-[11px]">{JSON.stringify(e.fields, null, 2)}</pre>
        )}
      </div>
    </article>
  )
}
