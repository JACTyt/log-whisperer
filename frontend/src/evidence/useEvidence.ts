import { createContext, useContext } from 'react'
import type { Event } from '../api/client'

export interface EvidenceRequest {
  label: string
  eventIds: string[]
  /** Events already loaded (e.g. the incident context) to avoid refetching. */
  known?: Map<string, Event>
  /** Surrounding events for the "nearby" list. */
  context?: Event[]
}

export interface EvidenceState {
  open: (req: EvidenceRequest) => void
  close: () => void
  current: EvidenceRequest | null
}

export const EvidenceCtx = createContext<EvidenceState | null>(null)

export function useEvidence(): EvidenceState {
  const ctx = useContext(EvidenceCtx)
  if (!ctx) throw new Error('useEvidence must be used inside EvidenceProvider')
  return ctx
}
