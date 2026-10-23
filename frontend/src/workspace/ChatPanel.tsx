import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { api, type ChatOut } from '../api/client'
import { EvidenceTag } from '../evidence/EvidenceTag'
import { readLlmChoice } from './llmChoice'

interface Turn {
  question: string
  answer?: ChatOut
  error?: string
}

export function ChatPanel() {
  const { incidentId } = useParams()
  const [scope, setScope] = useState<'incident' | 'global'>(incidentId ? 'incident' : 'global')
  const [turns, setTurns] = useState<Turn[]>([])
  const [session, setSession] = useState<string | undefined>()
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const end = useRef<HTMLDivElement>(null)

  // Block body on purpose: Chrome's scrollIntoView returns a Promise, which React would treat as a cleanup.
  useEffect(() => {
    end.current?.scrollIntoView({ block: 'end' })
  }, [turns])

  const ask = async (e: FormEvent) => {
    e.preventDefault()
    const question = text.trim()
    if (!question || busy) return
    setText('')
    setBusy(true)
    setTurns((t) => [...t, { question }])
    try {
      const answer = await api.chat({ message: question, session_id: session, scope, incident_id: incidentId, ...readLlmChoice() })
      setSession(answer.session_id)
      setTurns((t) => t.map((x, i) => (i === t.length - 1 ? { ...x, answer } : x)))
    } catch (err) {
      setTurns((t) => t.map((x, i) => (i === t.length - 1 ? { ...x, error: (err as Error).message } : x)))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-label="Ask about the logs" className="flex h-full flex-col border-l border-rule bg-panel">
      <div className="flex items-center justify-between border-b border-rule px-4 py-3">
        <h2 className="text-base font-semibold">Ask the logs</h2>
        <select
          value={scope}
          onChange={(e) => {
            setScope(e.target.value as 'incident' | 'global')
            setSession(undefined)
          }}
          className="rounded border border-rule bg-panel px-2 py-1 text-sm"
          aria-label="Search scope"
        >
          <option value="incident" disabled={!incidentId}>
            This incident
          </option>
          <option value="global">All data</option>
        </select>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto px-4 py-4 text-sm">
        {!turns.length && (
          <p className="text-muted">
            Try “Which hosts did this IP touch?” or “What did the new account do?”. Answers cite the log lines they rely on.
          </p>
        )}
        {turns.map((t, i) => (
          <div key={i}>
            <p className="mb-1.5 font-medium">{t.question}</p>
            {!t.answer && !t.error && <p className="text-muted">Looking through the logs…</p>}
            {t.error && <p className="text-sev-critical">{t.error}</p>}
            {t.answer && (
              <div className="space-y-1.5">
                {t.answer.sentences?.map((s, j) => (
                  <p key={j}>
                    {s.text} <EvidenceTag n={j + 1} eventIds={s.event_ids} />
                  </p>
                ))}
                {t.answer.no_data?.map((s, j) => (
                  <p key={`n${j}`} className="text-muted">
                    {s}
                  </p>
                ))}
                {!!t.answer.rejected?.length && (
                  <p className="text-xs text-muted">{t.answer.rejected.length} unverifiable sentence(s) removed.</p>
                )}
              </div>
            )}
          </div>
        ))}
        <div ref={end} />
      </div>

      <form onSubmit={ask} className="border-t border-rule p-3">
        <label htmlFor="chat-input" className="sr-only">
          Question
        </label>
        <div className="flex gap-2">
          <input
            id="chat-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Ask a question"
            className="min-w-0 flex-1 rounded border border-rule bg-ink px-3 py-1.5"
          />
          <button type="submit" disabled={busy || !text.trim()} className="rounded bg-evidence px-3 py-1.5 font-medium text-evidence-ink disabled:opacity-50">
            Ask
          </button>
        </div>
      </form>
    </section>
  )
}
