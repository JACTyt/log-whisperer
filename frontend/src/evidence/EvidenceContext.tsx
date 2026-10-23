import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { EvidenceCtx, type EvidenceRequest } from './useEvidence'

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<EvidenceRequest | null>(null)
  const open = useCallback((req: EvidenceRequest) => setCurrent(req), [])
  const close = useCallback(() => setCurrent(null), [])
  const value = useMemo(() => ({ open, close, current }), [open, close, current])
  return <EvidenceCtx.Provider value={value}>{children}</EvidenceCtx.Provider>
}
