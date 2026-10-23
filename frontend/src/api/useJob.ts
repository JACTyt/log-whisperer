import { useEffect, useRef, useState } from 'react'
import { api, type Job } from './client'

/** Follows a background job over SSE, falling back to polling if the stream drops. */
export function useJob(jobId: string | null, onDone?: (job: Job) => void): Job | null {
  const [job, setJob] = useState<Job | null>(null)
  const onDoneRef = useRef(onDone)
  useEffect(() => {
    onDoneRef.current = onDone
  })

  useEffect(() => {
    if (!jobId) return
    let closed = false
    let timer: ReturnType<typeof setInterval> | undefined
    const source = new EventSource(`/api/jobs/${jobId}/stream`)
    const finish = (j: Job) => {
      setJob(j)
      if (j.status === 'done' || j.status === 'error') {
        closed = true
        source.close()
        clearInterval(timer)
        onDoneRef.current?.(j)
      }
    }
    source.addEventListener('progress', (e) =>
      setJob((prev) => ({
        ...(prev?.id === jobId ? prev : ({ id: jobId, kind: '', status: 'running', result: null, error: null } as Job)),
        progress: JSON.parse((e as MessageEvent).data),
      })),
    )
    source.addEventListener('done', (e) => finish(JSON.parse((e as MessageEvent).data)))
    source.addEventListener('error', (e) => {
      const data = (e as MessageEvent).data
      if (data) return finish(JSON.parse(data))
      source.close()
      if (!closed) timer = setInterval(() => api.job(jobId).then(finish).catch(() => undefined), 1000)
    })
    return () => {
      closed = true
      source.close()
      clearInterval(timer)
    }
  }, [jobId])

  return jobId && job?.id === jobId ? job : null
}
