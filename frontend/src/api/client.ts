import type { components } from './schema'

type S = components['schemas']
export type Event = S['Event']
export type Detection = S['Detection']
export type IncidentSummary = S['IncidentSummary']
export type IncidentDetail = S['IncidentDetail']
export type StoredNarrative = S['StoredNarrative']
export type NarrativeStep = S['NarrativeStep']
export type AttackRow = S['AttackRow']
export type ChatOut = S['ChatOut']
export type EventPage = S['EventPage']
export type SourceSummary = S['SourceSummary']
export type SourceFile = S['SourceFile']

export interface Job {
  id: string
  kind: string
  status: 'queued' | 'running' | 'done' | 'error'
  progress: Record<string, unknown>
  result: unknown
  error: string | null
}

export interface LiveStatus {
  running: boolean
  sources: string[]
  events_total: number
  unparsed_total: number
  detections_total: number
  syslog_port: number | null
  last_error: string | null
}

export interface ModelOption {
  provider: string
  model: string
  installed: boolean
}

export interface ProviderInfo {
  default: string
  default_model: string | null
  models: ModelOption[]
  ollama_reachable: boolean
}

export interface SuggestedAction {
  action: string
  rationale: string
  priority: 'immediate' | 'short_term' | 'long_term'
  event_ids: string[]
  label: string
}

export interface RuleDraft {
  status: 'accepted' | 'rejected'
  reason: string | null
  yaml: string
  explanation: string
  path: string | null
  matched_event_ids: string[]
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`/api${path}`, init)
  } catch {
    throw new ApiError(0, 'The Log Whisperer backend is not reachable. Start it with `logw serve`.')
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail)
  }
  return (res.headers.get('content-type') ?? '').includes('json') ? res.json() : (res.text() as Promise<T>)
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })

function qs(params: Record<string, string | number | null | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export interface LlmChoice {
  provider?: string
  model?: string
}

export const api = {
  health: () => request<{ status: string; events: number }>('/health'),
  providers: () => request<ProviderInfo>('/providers'),
  incidents: () => request<IncidentSummary[]>('/incidents'),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  event: (id: string) => request<Event>(`/events/${id}`),
  events: (params: Record<string, string | number | null | undefined>) => request<EventPage>(`/events${qs(params)}`),
  sources: () => request<SourceFile[]>('/sources'),
  job: (id: string) => request<Job>(`/jobs/${id}`),
  upload: (files: File[]) => {
    const form = new FormData()
    files.forEach((f) => form.append('files', f))
    return request<Job>('/ingest', { method: 'POST', body: form })
  },
  detect: () => post<Job>('/detect'),
  narrate: (id: string, llm: LlmChoice) => post<Job>(`/incidents/${id}/narrative${qs({ ...llm })}`),
  suggestActions: (id: string, llm: LlmChoice) => post<Job>(`/incidents/${id}/actions${qs({ ...llm })}`),
  actions: (id: string) => request<SuggestedAction[]>(`/incidents/${id}/actions`),
  draftRule: (id: string, llm: LlmChoice) => post<Job>(`/incidents/${id}/rule-drafts${qs({ ...llm })}`),
  chat: (body: { message: string; session_id?: string; scope: 'incident' | 'global'; incident_id?: string } & LlmChoice) =>
    post<ChatOut>('/chat', body),
  live: () => request<LiveStatus>('/live/status'),
  liveStart: () => post<LiveStatus>('/live/start'),
  liveStop: () => post<LiveStatus>('/live/stop'),
  reportUrl: (id: string, format: 'md' | 'pdf') => `/api/incidents/${id}/report?format=${format}`,
}
