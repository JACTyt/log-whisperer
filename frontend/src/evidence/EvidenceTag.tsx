import type { Event } from '../api/client'
import { useEvidence } from './useEvidence'

interface Props {
  n: number
  eventIds: string[]
  known?: Map<string, Event>
  context?: Event[]
}

/** A numbered evidence marker. Each one opens the raw log lines that back a claim. */
export function EvidenceTag({ n, eventIds, known, context }: Props) {
  const { open } = useEvidence()
  const count = eventIds.length
  const label = `Evidence ${n}: ${count} log ${count === 1 ? 'line' : 'lines'}`
  return (
    <button
      type="button"
      onClick={() => open({ label: `Evidence ${n}`, eventIds, known, context })}
      aria-label={label}
      title={label}
      className="group relative inline-flex h-6 min-w-6 cursor-pointer items-end justify-center px-1 align-middle
                 text-[11px] font-semibold text-evidence-ink transition-transform hover:-translate-y-0.5"
    >
      <svg viewBox="0 0 24 22" className="absolute inset-0 h-full w-full" aria-hidden="true">
        <path d="M12 1.5 22.5 20.5H1.5Z" className="fill-evidence" strokeLinejoin="round" />
      </svg>
      <span className="relative pb-0.5 leading-none">{n}</span>
      {count > 1 && <span className="relative ml-0.5 pb-0.5 leading-none text-[9px] opacity-80">×{count}</span>}
    </button>
  )
}
