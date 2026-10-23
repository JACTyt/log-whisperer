import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { Event } from '../api/client'
import { formatRange, formatTs } from '../format'
import { EvidenceProvider } from './EvidenceContext'
import { EvidenceDrawer } from './EvidenceDrawer'
import { EvidenceTag } from './EvidenceTag'

function ev(id: string, raw: string, ts = '2026-03-14T14:02:01'): Event {
  return {
    event_id: id, seq: 1, ts, source_type: 'authlog', channel: 'auth', host: 'web01', user: 'root',
    src_ip: '203.0.113.7', dst_ip: null, process: 'sshd', command_line: null, action: 'ssh_auth', outcome: 'failure',
    event_code: null, source_file: 'C:\\logs\\auth.log', record_ref: 'line:4', raw, fields: { method: 'password' },
  } as Event
}

function setup(ids: string[], events: Event[]) {
  const known = new Map(events.map((e) => [e.event_id, e]))
  render(
    <QueryClientProvider client={new QueryClient()}>
      <EvidenceProvider>
        <p>
          Brute force <EvidenceTag n={3} eventIds={ids} known={known} context={events} />
        </p>
        <EvidenceDrawer />
      </EvidenceProvider>
    </QueryClientProvider>,
  )
}

describe('evidence markers', () => {
  it('shows the number and run size', () => {
    setup(['a', 'b'], [ev('a', 'one'), ev('b', 'two')])
    const tag = screen.getByRole('button', { name: 'Evidence 3: 2 log lines' })
    expect(tag).toHaveTextContent('3')
    expect(tag).toHaveTextContent('×2')
  })

  it('opens the raw lines in a drawer and closes with Escape', async () => {
    const user = userEvent.setup()
    setup(['a'], [ev('a', 'Failed password for root from 203.0.113.7 port 40001 ssh2')])
    await user.click(screen.getByRole('button', { name: /Evidence 3/ }))
    const drawer = screen.getByRole('dialog', { name: 'Evidence 3' })
    expect(drawer).toHaveTextContent('Failed password for root from 203.0.113.7')
    expect(drawer).toHaveTextContent('auth.log line:4')
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('pages long runs', async () => {
    const user = userEvent.setup()
    const events = Array.from({ length: 45 }, (_, i) => ev(`e${i}`, `line ${i}`))
    setup(events.map((e) => e.event_id), events)
    await user.click(screen.getByRole('button', { name: /Evidence 3/ }))
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument()
    expect(screen.getByText('line 20')).toBeInTheDocument()
  })
})

describe('format', () => {
  it('treats API timestamps as UTC', () => {
    expect(formatTs('2026-03-14T14:02:01')).toBe('14:02:01')
    expect(formatTs('2026-03-14T14:02:01', true)).toBe('2026-03-14 14:02:01')
  })
  it('shortens same-day ranges', () => {
    expect(formatRange('2026-03-14T14:02:01', '2026-03-14T14:11:31')).toBe('2026-03-14 14:02:01 – 14:11:31 UTC')
  })
})
