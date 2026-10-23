import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, type Event } from '../api/client'
import { useEvidence } from '../evidence/useEvidence'
import { fileName, formatTs, position } from '../format'

const FILTERS = [
  ['q', 'Text in the line'],
  ['host', 'Host'],
  ['user', 'User'],
  ['src_ip', 'Source IP'],
  ['action', 'Action'],
] as const
const PAGE = 100

/** Full logs: one file in its original line order, or everything in time order. */
export function EventsExplorer() {
  const [params, setParams] = useSearchParams()
  const file = params.get('file') ?? ''
  const focus = params.get('focus') ?? undefined
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [offset, setOffset] = useState(0)
  const { open } = useEvidence()
  const focusRow = useRef<HTMLTableRowElement>(null)

  const { data: files } = useQuery({ queryKey: ['sources'], queryFn: api.sources })
  const { data: incidents } = useQuery({ queryKey: ['incidents'], queryFn: api.incidents })
  const titles = new Map((incidents ?? []).map((i) => [i.incident_id, i.title]))
  const { data, isFetching, error } = useQuery({
    queryKey: ['events', file, filters, offset, focus],
    queryFn: () =>
      api.events({ ...filters, source_file: file, order: file ? 'file' : 'time', limit: PAGE, offset, focus }),
    placeholderData: keepPreviousData,
  })
  const current = files?.find((f) => f.source_file === file)

  // Jumped here from an incident: bring the focused line into view once its page has loaded.
  useEffect(() => {
    if (focus && data?.items.some((e) => e.event_id === focus)) {
      focusRow.current?.scrollIntoView({ block: 'center' })
    }
  }, [focus, data])

  const choose = (sourceFile: string) => {
    setOffset(0)
    setParams(sourceFile ? { file: sourceFile } : {})
  }
  const page = (next: number) => {
    setOffset(next)
    if (focus) setParams(file ? { file } : {}) // paging away from the jumped-to line
  }
  const apply = (e: FormEvent) => {
    e.preventDefault()
    setFilters(draft)
    page(0)
  }
  const shownOffset = data?.offset ?? offset

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <h2 className="text-2xl font-semibold tracking-tight">{current ? current.name : 'All logs'}</h2>
      <p className="mt-1 mb-5 text-sm text-muted">
        {current
          ? `${current.kind}: ${current.events.toLocaleString()} lines, ${formatTs(current.first_ts, true)} to ${formatTs(current.last_ts, true)} UTC. ${current.incidents} ${current.incidents === 1 ? 'incident uses' : 'incidents use'} lines from this file. Shown in original line order.`
          : 'Every stored line from every file, in time order. Pick a file to read it in its original order.'}
      </p>

      <form onSubmit={apply} className="mb-4 flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1 text-muted">
          Log file
          <select
            value={file}
            onChange={(e) => choose(e.target.value)}
            className="max-w-64 rounded border border-rule bg-panel px-2 py-1 text-text"
          >
            <option value="">All files</option>
            {files?.map((f) => (
              <option key={f.source_file} value={f.source_file} title={f.source_file}>
                {f.name} ({f.events} lines)
              </option>
            ))}
          </select>
        </label>
        {FILTERS.map(([key, label]) => (
          <label key={key} className="flex flex-col gap-1 text-muted">
            {label}
            <input
              value={draft[key] ?? ''}
              onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              className="w-36 rounded border border-rule bg-panel px-2 py-1 text-text"
            />
          </label>
        ))}
        <button type="submit" className="rounded border border-rule px-3 py-1 hover:bg-raised">
          Filter
        </button>
      </form>

      {error && <p className="text-sev-critical">{(error as Error).message}</p>}
      <p className="mb-2 text-sm text-muted" role="status">
        {data ? `${data.total.toLocaleString()} lines` : 'Loading…'} {isFetching && data ? '(updating)' : ''}
        {data && data.total > 0 && (
          <span className="ml-3">
            <span className="mr-1 inline-block h-3 w-1 bg-evidence align-middle" aria-hidden="true" /> part of an incident
          </span>
        )}
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-muted">
            <tr>
              <th className="py-1 pr-3 font-normal whitespace-nowrap">{file ? 'Line' : 'File'}</th>
              <th className="py-1 pr-3 font-normal whitespace-nowrap">Time (UTC)</th>
              <th className="py-1 pr-3 font-normal">Log line</th>
              <th className="py-1 font-normal whitespace-nowrap">Incident</th>
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {data?.items.map((e: Event) => {
              const inc = data.incidents?.[e.event_id] ?? []
              const isFocus = e.event_id === focus
              return (
                <tr
                  key={e.event_id}
                  ref={isFocus ? focusRow : undefined}
                  className={`border-t border-rule/60 align-top ${isFocus ? 'bg-evidence/15' : inc.length ? 'bg-evidence/5' : ''}`}
                >
                  <td
                    className={`border-l-2 py-1 pr-3 pl-2 whitespace-nowrap text-muted ${inc.length ? 'border-evidence' : 'border-transparent'}`}
                    title={e.source_file}
                  >
                    {file ? position(e.record_ref).replace(/^line /, '') : `${fileName(e.source_file)} ${position(e.record_ref)}`}
                  </td>
                  <td className="py-1 pr-3 whitespace-nowrap text-muted">{formatTs(e.ts, true)}</td>
                  <td className="py-1 pr-3">
                    <button
                      type="button"
                      onClick={() => open({ label: `${fileName(e.source_file)} ${position(e.record_ref)}`, eventIds: [e.event_id], known: new Map([[e.event_id, e]]) })}
                      className="w-full cursor-pointer text-left break-all whitespace-pre-wrap hover:text-text"
                      title="Show parsed fields"
                    >
                      {e.raw}
                    </button>
                  </td>
                  <td className="py-1 font-sans">
                    {inc.map((id) => (
                      <Link key={id} to={`/incidents/${id}`} className="block max-w-56 truncate text-xs text-evidence hover:underline" title={titles.get(id)}>
                        {titles.get(id) ?? id}
                      </Link>
                    ))}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {data && data.total > PAGE && (
        <nav className="mt-3 flex items-center gap-4 text-sm text-muted">
          <button type="button" disabled={shownOffset === 0} onClick={() => page(Math.max(0, shownOffset - PAGE))} className="disabled:opacity-40">
            Previous
          </button>
          <span>
            {shownOffset + 1}–{Math.min(shownOffset + PAGE, data.total)} of {data.total.toLocaleString()}
          </span>
          <button type="button" disabled={shownOffset + PAGE >= data.total} onClick={() => page(shownOffset + PAGE)} className="disabled:opacity-40">
            Next
          </button>
        </nav>
      )}
    </div>
  )
}
