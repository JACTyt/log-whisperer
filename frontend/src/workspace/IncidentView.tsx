import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type Event, type IncidentDetail, type LlmChoice, type RuleDraft, type SuggestedAction } from '../api/client'
import { useJob } from '../api/useJob'
import { EvidenceTag } from '../evidence/EvidenceTag'
import { useEvidence } from '../evidence/useEvidence'
import { describeOrigin, fileName, formatRange, formatTs, position, severityClass } from '../format'
import { useLlmChoice } from './llmChoice'

/** Hands out evidence numbers in reading order (recreated each render, so numbering is stable). */
function makeCounter() {
  let n = 0
  return () => ++n
}

export function IncidentView() {
  const { incidentId = '' } = useParams()
  const { data, error } = useQuery({
    queryKey: ['incident', incidentId],
    queryFn: () => api.incident(incidentId),
    enabled: !!incidentId,
  })
  const [llm, setLlm] = useLlmChoice()

  if (error) return <p className="p-8 text-sev-critical">{(error as Error).message}</p>
  // Any state without data (fetching, paused, queued) shows progress — never a silent blank page.
  if (!data) return <p className="p-8 text-muted">Loading incident…</p>
  return <Incident key={incidentId} detail={data} llm={llm} setLlm={setLlm} />
}

function Incident({ detail, llm, setLlm }: { detail: IncidentDetail; llm: LlmChoice; setLlm: (c: LlmChoice) => void }) {
  const inc = detail.incident
  const known = useMemo(() => new Map<string, Event>(detail.events.map((e) => [e.event_id, e])), [detail.events])
  const next = makeCounter()
  const { open } = useEvidence()
  const tag = (ids: string[]) => <EvidenceTag n={next()} eventIds={ids} known={known} context={detail.events} />
  const origin = (ids: string[]) => {
    const evs = ids.map((id) => known.get(id)).filter((e): e is Event => !!e)
    return evs.length ? <span className="block text-xs text-muted">from {describeOrigin(evs)}</span> : null
  }

  return (
    <article className="mx-auto max-w-[72ch] px-6 py-8">
      <header className="mb-8">
        <p className="text-sm text-muted">
          <span className={`font-semibold ${severityClass(inc.severity)}`}>{inc.severity}</span>
          <span className="mx-2">/</span>
          {formatRange(inc.ts_start, inc.ts_end)}
        </p>
        <h2 className="mt-1 text-2xl leading-tight font-semibold tracking-tight">{inc.title}</h2>
        <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-sm">
          {(
            [
              ['Hosts', inc.hosts],
              ['Users', inc.users],
              ['Source IPs', inc.src_ips],
            ] as const
          ).map(([label, values]) => (
            <div key={label} className="contents">
              <dt className="text-muted">{label}</dt>
              <dd>{values?.length ? values.join(', ') : '—'}</dd>
            </div>
          ))}
          <dt className="text-muted">Log files</dt>
          <dd>
            <ul className="flex flex-wrap gap-x-4 gap-y-1">
              {detail.sources.map((s) => (
                <li key={s.source_file}>
                  <button
                    type="button"
                    onClick={() => open({ label: `${s.name}: lines in this incident`, eventIds: s.event_ids, known, context: detail.events })}
                    title={`${s.source_file}\n${s.kind}. Show these lines.`}
                    className="underline decoration-rule underline-offset-4 hover:decoration-evidence"
                  >
                    {s.name}
                  </button>
                  <span className="text-muted">
                    {' '}
                    ({s.events} {s.events === 1 ? 'line' : 'lines'}, {s.kind}){' '}
                  </span>
                  <Link
                    to={`/logs?file=${encodeURIComponent(s.source_file)}&focus=${s.event_ids[0]}`}
                    className="text-muted underline underline-offset-4 hover:text-text"
                    aria-label={`Open the full ${s.name} at this incident`}
                  >
                    full log
                  </Link>
                </li>
              ))}
            </ul>
          </dd>
        </dl>
        <div className="mt-4 flex flex-wrap items-center gap-3 text-sm">
          <ModelPicker llm={llm} setLlm={setLlm} />
          <a className="text-muted underline-offset-2 hover:text-text hover:underline" href={api.reportUrl(inc.incident_id, 'md')}>
            Export Markdown
          </a>
          <a className="text-muted underline-offset-2 hover:text-text hover:underline" href={api.reportUrl(inc.incident_id, 'pdf')}>
            Export PDF
          </a>
        </div>
      </header>

      <Narrative detail={detail} llm={llm} tag={tag} origin={origin} />
      <Detections detail={detail} tag={tag} origin={origin} />
      <Attack detail={detail} />
      <Actions incidentId={inc.incident_id} llm={llm} tag={tag} />
      <RuleDraftSection incidentId={inc.incident_id} llm={llm} />
      <LogLines detail={detail} />
    </article>
  )
}

const PROVIDER_LABEL: Record<string, string> = { ollama: 'Local (Ollama)', anthropic: 'Anthropic', openai: 'OpenAI' }
const SEP = '\u0000'

function ModelPicker({ llm, setLlm }: { llm: LlmChoice; setLlm: (c: LlmChoice) => void }) {
  const { data } = useQuery({ queryKey: ['providers'], queryFn: api.providers })
  const value = llm.provider && llm.model ? `${llm.provider}${SEP}${llm.model}` : ''
  const groups = new Map<string, NonNullable<typeof data>['models']>()
  data?.models.forEach((m) => groups.set(m.provider, [...(groups.get(m.provider) ?? []), m]))
  return (
    <label className="flex items-center gap-2 text-muted">
      Model
      <select
        value={value}
        onChange={(e) => {
          const [provider, model] = e.target.value.split(SEP)
          setLlm(e.target.value ? { provider, model } : {})
        }}
        className="max-w-72 rounded border border-rule bg-panel px-2 py-1 text-text"
      >
        <option value="">Default ({data?.default_model ?? data?.default ?? '…'})</option>
        {[...groups].map(([provider, models]) => (
          <optgroup key={provider} label={PROVIDER_LABEL[provider] ?? provider}>
            {models.map((m) => (
              <option key={m.model} value={`${m.provider}${SEP}${m.model}`}>
                {m.model}
                {m.installed ? '' : ' (not installed)'}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      {data && !data.ollama_reachable && <span className="text-xs text-sev-high">Ollama is not running</span>}
    </label>
  )
}

type Tag = (ids: string[]) => React.ReactNode
type Origin = (ids: string[]) => React.ReactNode

const LOG_PREVIEW = 50

/** Every log line this incident is built from, with its file and line number. */
function LogLines({ detail }: { detail: IncidentDetail }) {
  const [all, setAll] = useState(false)
  const { data: incidents } = useQuery({ queryKey: ['incidents'], queryFn: api.incidents })
  const titles = new Map((incidents ?? []).map((i) => [i.incident_id, i.title]))
  const detected = new Set(detail.detections.flatMap((d) => d.event_ids))
  const shared = detail.shared ?? {}
  const sharedCount = Object.keys(shared).length
  const shown = all ? detail.events : detail.events.slice(0, LOG_PREVIEW)
  return (
    <Section title={`Log lines (${detail.events.length})`}>
      <p className="mb-3 text-sm text-muted">
        The original lines this incident is built from, in time order. Lines marked in amber triggered a detection; the
        others are surrounding activity from the same host, user or IP.
        {sharedCount > 0 &&
          ` ${sharedCount} ${sharedCount === 1 ? 'line is' : 'lines are'} also part of another incident and say which.`}
      </p>
      <ol className="space-y-px font-mono text-xs">
        {shown.map((e) => (
          <li
            key={e.event_id}
            className={`grid grid-cols-[5.5rem_minmax(8rem,auto)_1fr] gap-x-3 border-l-2 py-1 pl-2 ${
              detected.has(e.event_id) ? 'border-evidence bg-evidence/5' : 'border-transparent'
            }`}
          >
            <time className="text-muted" dateTime={e.ts}>
              {formatTs(e.ts)}
            </time>
            <span className="text-muted" title={e.source_file}>
              {fileName(e.source_file)} {position(e.record_ref)}
            </span>
            <span className="break-all whitespace-pre-wrap">
              {e.raw}
              {shared[e.event_id]?.map((id) => (
                <span key={id} className="mt-0.5 block font-sans text-sev-medium">
                  also in{' '}
                  <Link to={`/incidents/${id}`} className="underline underline-offset-2 hover:text-text">
                    {titles.get(id) ?? id}
                  </Link>
                </span>
              ))}
            </span>
          </li>
        ))}
      </ol>
      {detail.events.length > LOG_PREVIEW && (
        <button type="button" onClick={() => setAll(!all)} className="mt-2 text-sm text-muted hover:text-text">
          {all ? 'Show fewer' : `Show all ${detail.events.length} lines`}
        </button>
      )}
    </Section>
  )
}

function Section({ title, children, aside }: { title: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="mb-10">
      <div className="mb-3 flex items-baseline justify-between gap-4 border-b border-rule pb-1.5">
        <h3 className="text-base font-semibold">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  )
}

function JobButton({ label, busyLabel, run, onDone }: { label: string; busyLabel: string; run: () => Promise<{ id: string }>; onDone: (r: unknown) => void }) {
  const [jobId, setJobId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const job = useJob(jobId, (j) => {
    setJobId(null)
    if (j.status === 'error') setError(j.error)
    else onDone(j.result)
  })
  const busy = !!jobId
  return (
    <span className="flex items-baseline gap-3">
      {error && <span className="text-sm text-sev-critical">{error}</span>}
      <button
        type="button"
        disabled={busy}
        onClick={async () => {
          setError(null)
          try {
            setJobId((await run()).id)
          } catch (e) {
            setError((e as Error).message)
          }
        }}
        className="rounded border border-evidence/60 px-3 py-1 text-sm font-medium text-evidence hover:bg-evidence hover:text-evidence-ink disabled:cursor-wait disabled:opacity-60"
      >
        {busy ? `${busyLabel}${job?.progress?.model ? ` with ${String(job.progress.model)}` : ''}…` : label}
      </button>
    </span>
  )
}

function Narrative({ detail, llm, tag, origin }: { detail: IncidentDetail; llm: LlmChoice; tag: Tag; origin: Origin }) {
  const qc = useQueryClient()
  const stored = detail.narrative
  const nv = stored?.narrative
  const button = (
    <JobButton
      label={nv ? 'Regenerate' : 'Explain this incident'}
      busyLabel="Writing the timeline"
      run={() => api.narrate(detail.incident.incident_id, llm)}
      onDone={() => qc.invalidateQueries({ queryKey: ['incident', detail.incident.incident_id] })}
    />
  )

  if (!nv) {
    return (
      <Section title="What happened" aside={button}>
        <p className="text-muted">
          No explanation yet. The model writes a timeline from this incident’s {detail.events.length} log events, and every
          statement links to the lines that prove it. Statements it can’t back up are dropped.
        </p>
      </Section>
    )
  }

  return (
    <Section title="What happened" aside={button}>
      {nv.summary && (
        <p className="mb-6 text-[17px] leading-relaxed">
          {nv.summary.text} {tag(nv.summary.event_ids)}
          {nv.summary_is_template && (
            <span className="mt-1 block text-sm text-muted">
              Generated from detections because the model’s summary failed verification.
            </span>
          )}
        </p>
      )}
      <ol className="relative">
        {(nv.steps ?? []).map((s, i) => (
          <li key={i} className="grid grid-cols-[4.5rem_1rem_1fr] gap-x-3 pb-5 last:pb-0">
            <time className="pt-0.5 text-right font-mono text-xs text-muted" dateTime={s.ts}>
              {formatTs(s.ts)}
            </time>
            <span className="relative flex justify-center" aria-hidden="true">
              <span className="mt-1.5 size-2.5 rounded-full border-2 border-evidence bg-ink" />
              {i < (nv.steps ?? []).length - 1 && <span className="absolute top-4 -bottom-5 w-px bg-rule" />}
            </span>
            <div>
              <p>
                {s.text} {tag(s.event_ids)}
              </p>
              {origin(s.event_ids)}
              {!!s.techniques?.length && (
                <p className="mt-1 flex flex-wrap gap-1.5 text-xs">
                  {s.techniques.map((t) => (
                    <a
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded bg-raised px-1.5 py-0.5 text-muted hover:text-text"
                    >
                      {t}
                    </a>
                  ))}
                </p>
              )}
            </div>
          </li>
        ))}
      </ol>
      <p className="mt-4 text-xs text-muted">
        Written by {stored?.model} on {stored ? formatTs(stored.created_at, true) : ''} UTC.
      </p>
      {!!nv.rejected?.length && (
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer text-muted">
            {nv.rejected.length} statement{nv.rejected.length === 1 ? ' was' : 's were'} dropped because the logs don’t support
            {nv.rejected.length === 1 ? ' it' : ' them'}
          </summary>
          <ul className="mt-2 space-y-1.5">
            {nv.rejected.map((r, i) => (
              <li key={i} className="text-muted">
                <span className="line-through decoration-sev-critical/60">{r.text}</span>
                <span className="ml-2 font-mono text-xs">{r.reason}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </Section>
  )
}

function Detections({ detail, tag, origin }: { detail: IncidentDetail; tag: Tag; origin: Origin }) {
  return (
    <Section title={`Detections (${detail.detections.length})`}>
      <ul className="space-y-2 text-sm">
        {detail.detections.map((d) => (
          <li key={d.detection_id} className="grid grid-cols-[4.5rem_1fr_auto] items-start gap-x-3">
            <time className="text-right font-mono text-xs text-muted">{formatTs(d.ts_first)}</time>
            <span>
              {d.rule_title}{' '}
              <span className={`text-xs ${severityClass(d.severity)}`}>{d.severity}</span>{' '}
              <span className="text-xs text-muted">{d.rule_source === 'sigma' ? 'Sigma rule' : 'heuristic'}</span>
              {origin(d.event_ids)}
            </span>
            {tag(d.event_ids)}
          </li>
        ))}
      </ul>
    </Section>
  )
}

function Attack({ detail }: { detail: IncidentDetail }) {
  if (!detail.attack.length) return null
  return (
    <Section title="MITRE ATT&CK">
      <table className="w-full text-sm">
        <thead className="text-left text-muted">
          <tr>
            <th className="py-1 pr-3 font-normal">Tactic</th>
            <th className="py-1 pr-3 font-normal">Technique</th>
            <th className="py-1 font-normal">Seen in</th>
          </tr>
        </thead>
        <tbody>
          {detail.attack.map((r) => (
            <tr key={r.technique_id} className="border-t border-rule/60">
              <td className="py-1.5 pr-3 text-muted">{r.tactic.replaceAll('-', ' ')}</td>
              <td className="py-1.5 pr-3">
                <a href={r.url} target="_blank" rel="noreferrer" className="hover:underline">
                  <span className="font-mono text-xs text-muted">{r.technique_id}</span> {r.name}
                </a>
              </td>
              <td className="py-1.5 text-muted">
                {[
                  r.detection_ids?.length ? `${r.detection_ids.length} detection${r.detection_ids.length > 1 ? 's' : ''}` : '',
                  r.step_indexes?.length ? `${r.step_indexes.length} timeline step${r.step_indexes.length > 1 ? 's' : ''}` : '',
                ]
                  .filter(Boolean)
                  .join(', ')}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Section>
  )
}

function Actions({ incidentId, llm, tag }: { incidentId: string; llm: LlmChoice; tag: Tag }) {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['actions', incidentId], queryFn: () => api.actions(incidentId) })
  const [rejected, setRejected] = useState(0)
  return (
    <Section
      title="Response"
      aside={
        <JobButton
          label={data?.length ? 'Suggest again' : 'Suggest response actions'}
          busyLabel="Thinking through response"
          run={() => api.suggestActions(incidentId, llm)}
          onDone={(r) => {
            setRejected(((r as { rejected: unknown[] }).rejected ?? []).length)
            void qc.invalidateQueries({ queryKey: ['actions', incidentId] })
          }}
        />
      }
    >
      {data?.length ? (
        <>
          <p className="mb-3 text-sm text-muted">Suggestions only. Nothing has been executed.</p>
          <ol className="space-y-3">
            {data.map((a: SuggestedAction, i) => (
              <li key={i} className="grid grid-cols-[6.5rem_1fr] gap-x-3">
                <span className={`text-sm ${a.priority === 'immediate' ? 'text-sev-high' : 'text-muted'}`}>
                  {a.priority.replace('_', ' ')}
                </span>
                <span>
                  <span className="font-medium">{a.action}</span> {tag(a.event_ids)}
                  <span className="block text-sm text-muted">{a.rationale}</span>
                </span>
              </li>
            ))}
          </ol>
          {rejected > 0 && <p className="mt-2 text-xs text-muted">{rejected} uncited suggestion(s) were dropped.</p>}
        </>
      ) : (
        <p className="text-muted">Get containment and recovery steps, each tied to the evidence that justifies it.</p>
      )}
    </Section>
  )
}

function RuleDraftSection({ incidentId, llm }: { incidentId: string; llm: LlmChoice }) {
  const [draft, setDraft] = useState<RuleDraft | null>(null)
  return (
    <Section
      title="Detection rule"
      aside={
        <JobButton
          label="Draft a Sigma rule"
          busyLabel="Drafting and testing the rule"
          run={() => api.draftRule(incidentId, llm)}
          onDone={(r) => setDraft(r as RuleDraft)}
        />
      }
    >
      {!draft ? (
        <p className="text-muted">
          Draft a Sigma rule that would catch this next time. It is tested against this incident’s own events before it’s
          saved, and never switched on automatically.
        </p>
      ) : (
        <div>
          <p className={`mb-2 text-sm ${draft.status === 'accepted' ? 'text-sev-low' : 'text-sev-critical'}`}>
            {draft.status === 'accepted'
              ? `Matches ${draft.matched_event_ids.length} event(s) in this incident. Saved to ${draft.path} for review.`
              : `Not saved: ${draft.reason}`}
          </p>
          {draft.explanation && <p className="mb-2 text-sm text-muted">{draft.explanation}</p>}
          <pre className="overflow-x-auto rounded border border-rule bg-ink/60 p-3 font-mono text-xs">{draft.yaml}</pre>
        </div>
      )}
    </Section>
  )
}
