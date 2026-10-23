import { useEffect, useState } from 'react'
import type { LlmChoice } from '../api/client'

const KEY = 'logw.llm'

/** Current choice from storage (chat reads it per question, so it follows the incident view's picker). */
export function readLlmChoice(): LlmChoice {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}') as LlmChoice
  } catch {
    return {}
  }
}

/** The provider/model the analyst picked, remembered per browser. Empty means server default. */
export function useLlmChoice(): [LlmChoice, (c: LlmChoice) => void] {
  const [choice, setChoice] = useState<LlmChoice>(readLlmChoice)
  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(choice))
    } catch {
      /* storage unavailable: keep in memory only */
    }
  }, [choice])
  return [choice, setChoice]
}
