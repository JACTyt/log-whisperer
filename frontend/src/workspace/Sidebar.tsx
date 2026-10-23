import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type DragEvent } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { api, type IncidentSummary } from '../api/client'
import { useJob } from '../api/useJob'
import { fileName, formatTs, severityClass } from '../format'

export function Sidebar() {
  return (
    <nav aria-label="Incidents" className="flex h-full flex-col border-r border-rule bg-panel">
      <div className="flex items-baseline justify-between px-4 pt-4 pb-3">
        <h1 className="text-lg font-semibold tracking-tight">Log Whisperer</h1>
        <NavLink to="/logs" end className="text-sm text-muted hover:text-text [&.active]:text-evidence">
          All logs
        </NavLink>
      </div>
      <Upload />
      <Live />
      <IncidentList />
    </nav>
  )
}

function Upload() {
  const qc = useQueryClient()
  const [jobId, setJobId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [over, setOver] = useState(false)
  const job = useJob(jobId, () => qc.invalidateQueries())

  const send = async (files: File[]) => {
    if (!files.length) return
    setError(null)
    try {
      setJobId((await api.upload(files)).id)
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setOver(false)
    void send([...e.dataTransfer.files])
  }
  const result = job?.status === 'done' ? (job.result as Record<string, number>) : null
  const progress = job?.progress as { done?: number; total?: number; stage?: string; parsed?: number } | undefined

  return (
    <div className="px-4 pb-3">
      <label
        onDragOver={(e) => {
          e.preventDefault()
          setOver(true)
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
        className={`block cursor-pointer rounded border border-dashed px-3 py-3 text-sm transition-colors
          ${over ? 'border-evidence bg-raised' : 'border-rule hover:border-muted'}`}
      >
        <input type="file" multiple className="sr-only" onChange={(e) => void send([...(e.target.files ?? [])])} />
        <span className="font-medium">Add log files</span>
        <span className="block text-muted">EVTX, Windows JSON, auth.log or web access logs. Drop here or browse.</span>
      </label>
      {job && job.status !== 'done' && job.status !== 'error' && (
        <p className="mt-2 text-sm text-muted" role="status">
          {progress?.stage === 'detect' || progress?.stage === 'incidents'
            ? 'Running detection…'
            : `Parsing ${progress?.done ?? 0}/${progress?.total ?? '…'} files, ${progress?.parsed ?? 0} events`}
        </p>
      )}
      {result && (
        <p className="mt-2 text-sm text-muted" role="status">
          Added {result.inserted} events, {result.new_detections ?? 0} new detections.
        </p>
      )}
      {(error || job?.error) && <p className="mt-2 text-sm text-sev-critical">{error ?? job?.error}</p>}
    </div>
  )
}

function Live() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['live'], queryFn: api.live, refetchInterval: 5000 })
  const toggle = async () => {
    await (data?.running ? api.liveStop() : api.liveStart())
    await qc.invalidateQueries({ queryKey: ['live'] })
  }
  return (
    <div className="flex items-center justify-between border-y border-rule px-4 py-2 text-sm">
      <span className="text-muted">
        {data?.running ? (
          <>
            <span className="mr-1.5 inline-block size-2 rounded-full bg-sev-low align-middle" aria-hidden="true" />
            Live: {data.events_total} events on port {data.syslog_port}
          </>
        ) : (
          'Live ingestion is off'
        )}
      </span>
      <button type="button" onClick={() => void toggle()} className="text-muted hover:text-text">
        {data?.running ? 'Stop' : 'Start'}
      </button>
    </div>
  )
}

/** Incidents grouped by the log file they come from; an incident built from several files appears under each. */
function groupByFile(incidents: IncidentSummary[]): [string, IncidentSummary[]][] {
  const groups = new Map<string, IncidentSummary[]>()
  for (const i of incidents) {
    for (const path of i.source_files?.length ? i.source_files : ['']) {
      groups.set(path, [...(groups.get(path) ?? []), i])
    }
  }
  return [...groups].sort(([a], [b]) => fileName(a).localeCompare(fileName(b)) || a.localeCompare(b))
}

function IncidentList() {
  const { data, isLoading, error } = useQuery({ queryKey: ['incidents'], queryFn: api.incidents, refetchInterval: 15000 })
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  if (isLoading) return <p className="px-4 py-3 text-sm text-muted">Loading incidents…</p>
  if (error) return <p className="px-4 py-3 text-sm text-sev-critical">{(error as Error).message}</p>
  if (!data?.length)
    return <p className="px-4 py-3 text-sm text-muted">No incidents yet. Add log files above to run detection.</p>
  const toggle = (name: string) => {
    const next = new Set(collapsed)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    setCollapsed(next)
  }
  return (
    <div className="flex-1 overflow-y-auto">
      {groupByFile(data).map(([path, incidents]) => {
        const open = !collapsed.has(path)
        const name = path ? fileName(path) : 'Unknown source'
        return (
          <section key={path} aria-label={`Incidents in ${name}`}>
            <h2 className="flex items-baseline border-b border-rule bg-ink/40 pr-4 hover:bg-raised">
              <button
                type="button"
                onClick={() => toggle(path)}
                aria-expanded={open}
                className="flex min-w-0 flex-1 items-baseline justify-between gap-2 py-2 pl-4 text-left"
              >
                <span className="truncate font-mono text-[13px]" title={path}>
                  <span className="mr-1.5 inline-block w-3 text-muted" aria-hidden="true">
                    {open ? '▾' : '▸'}
                  </span>
                  {name}
                </span>
                <span className="shrink-0 text-xs text-muted">
                  {incidents.length} {incidents.length === 1 ? 'incident' : 'incidents'}
                </span>
              </button>
              {path && (
                <Link
                  to={`/logs?file=${encodeURIComponent(path)}`}
                  className="ml-3 shrink-0 text-xs text-muted underline-offset-4 hover:text-text hover:underline"
                  aria-label={`Full log of ${name}`}
                >
                  Full log
                </Link>
              )}
            </h2>
            {open && (
              <ul>
                {incidents.map((i) => (
                  <IncidentItem
                    key={i.incident_id}
                    incident={i}
                    alsoIn={(i.source_files ?? []).filter((p) => p !== path).map(fileName)}
                  />
                ))}
              </ul>
            )}
          </section>
        )
      })}
    </div>
  )
}

function IncidentItem({ incident: i, alsoIn }: { incident: IncidentSummary; alsoIn: string[] }) {
  return (
    <li>
      <NavLink
        to={`/incidents/${i.incident_id}`}
        className="block border-b border-rule/60 px-4 py-2.5 hover:bg-raised [&.active]:bg-raised [&.active]:shadow-[inset_3px_0_0_var(--color-evidence)]"
      >
        <span className="flex items-baseline justify-between gap-2 text-xs">
          <span className={`font-semibold ${severityClass(i.severity)}`}>{i.severity}</span>
          <span className="text-muted">
            {i.ts_start.slice(0, 10)} {formatTs(i.ts_start)}
          </span>
        </span>
        <span className="mt-0.5 line-clamp-2 block text-sm">{i.title}</span>
        <span className="mt-0.5 block truncate text-xs text-muted">
          {[...i.hosts, ...i.src_ips].slice(0, 3).join(', ') || 'no host'}
          {i.has_narrative ? '' : ' (not yet explained)'}
        </span>
        {alsoIn.length > 0 && <span className="block truncate text-xs text-sev-medium">also in {alsoIn.join(', ')}</span>}
      </NavLink>
    </li>
  )
}
