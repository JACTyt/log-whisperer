import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App'
import { createQueryClient } from '../queryClient'

function incident(id: string, title: string) {
  return {
    incident_id: id, title, ts_start: '2026-03-14T14:02:01', ts_end: '2026-03-14T14:11:31', severity: 'high',
    hosts: ['web01'], users: ['root'], src_ips: ['203.0.113.7'], techniques: ['T1110.001'],
    detection_ids: [`${id}-d`], context_event_ids: [`${id}-e`], updated_at: '2026-03-14T15:00:00',
  }
}

function detail(id: string, title: string) {
  const ev = {
    event_id: `${id}-e`, seq: 1, ts: '2026-03-14T14:02:01', source_type: 'authlog', channel: 'auth', host: 'web01',
    user: 'root', src_ip: '203.0.113.7', dst_ip: null, process: 'sshd', command_line: null, action: 'ssh_auth',
    outcome: 'failure', event_code: null, source_file: '/data/uploads/x1/auth.log', record_ref: 'line:4',
    raw: `Mar 14 14:02:01 web01 sshd[1]: Failed password for root (${id})`, fields: {},
  }
  return {
    incident: incident(id, title),
    detections: [{ detection_id: `${id}-d`, rule_id: 'r', rule_title: `Rule ${id}`, rule_source: 'sigma', severity: 'high',
      techniques: [], event_ids: [`${id}-e`], ts_first: ev.ts, ts_last: ev.ts, hosts: [], users: [], src_ips: [] }],
    events: [ev],
    sources: [{ name: 'auth.log', source_file: '/data/uploads/x1/auth.log', source_type: 'authlog',
                kind: 'Linux auth log', events: 1, event_ids: [`${id}-e`] }],
    attack: [], narrative: null,
  }
}

const BASE_ROUTES: Record<string, unknown> = {
  '/api/health': { status: 'ok', events: 2 },
  '/api/live/status': { running: false, sources: [], events_total: 0, unparsed_total: 0, detections_total: 0 },
  '/api/providers': {
    default: 'ollama', default_model: 'gemma4:26b-a4b', ollama_reachable: true,
    models: [
      { provider: 'ollama', model: 'gemma4:26b-a4b', installed: true },
      { provider: 'ollama', model: 'gemma4:e4b', installed: false },
      { provider: 'anthropic', model: 'claude-opus-5-5', installed: true },
    ],
  },
  '/api/incidents': [
    { ...incident('aaa', 'First incident'), has_narrative: false, detection_count: 1, event_count: 1,
      source_files: ['/data/uploads/x1/auth.log', '/data/uploads/x1/access.log'] },
    { ...incident('bbb', 'Second incident'), has_narrative: false, detection_count: 1, event_count: 1,
      source_files: ['/data/uploads/x1/access.log'] },
  ],
  '/api/sources': [
    { name: 'access.log', source_file: '/data/uploads/x1/access.log', source_type: 'web', kind: 'Web server access log',
      events: 11, first_ts: '2026-03-14T13:50:00', last_ts: '2026-03-14T14:01:40', incidents: 2 },
    { name: 'auth.log', source_file: '/data/uploads/x1/auth.log', source_type: 'authlog', kind: 'Linux auth log',
      events: 31, first_ts: '2026-03-14T13:55:01', last_ts: '2026-03-14T14:25:01', incidents: 1 },
  ],
  '/api/events': {
    total: 31, offset: 0,
    items: [1, 2, 3].map((n) => ({
      event_id: `auth-${n}`, seq: n, ts: `2026-03-14T13:55:0${n}`, source_type: 'authlog', channel: 'auth',
      host: 'web01', user: 'root', src_ip: null, dst_ip: null, process: 'sshd', command_line: null, action: null,
      outcome: null, event_code: null, source_file: '/data/uploads/x1/auth.log', record_ref: `line:${n}`,
      raw: `raw auth line ${n}`, fields: {},
    })),
    incidents: { 'auth-2': ['aaa'] },
  },
  '/api/incidents/aaa': detail('aaa', 'First incident'),
  '/api/incidents/bbb': detail('bbb', 'Second incident'),
  '/api/incidents/aaa/actions': [],
  '/api/incidents/bbb/actions': [],
}

let ROUTES: Record<string, unknown>

beforeEach(() => {
  ROUTES = { ...BASE_ROUTES }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const body = ROUTES[url.split('?')[0]]
    if (body === undefined) return new Response(JSON.stringify({ detail: 'nope' }), { status: 404 })
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
  }))
})
afterEach(() => vi.unstubAllGlobals())

import realIncidents from './__fixtures__/incidents.json'
import narrated from './__fixtures__/898f3d5b85759b2e.json'
import plain from './__fixtures__/1d01fe2a886a2469.json'

describe('switching incidents with real API data', () => {
  it.each([
    ['narrated -> plain', '898f3d5b85759b2e', '1d01fe2a886a2469'],
    ['plain -> narrated', '1d01fe2a886a2469', '898f3d5b85759b2e'],
  ])('%s', async (_, from, to) => {
    Object.assign(ROUTES, {
      '/api/incidents': realIncidents,
      '/api/incidents/898f3d5b85759b2e': narrated,
      '/api/incidents/1d01fe2a886a2469': plain,
      [`/api/incidents/${from}/actions`]: [],
      [`/api/incidents/${to}/actions`]: [],
    })
    const titles = Object.fromEntries(realIncidents.map((i) => [i.incident_id, i.title]))
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={[`/incidents/${from}`]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { level: 2, name: titles[from] })).toBeInTheDocument()
    const link = (await screen.findAllByRole('link')).find((a) => a.getAttribute('href') === `/incidents/${to}`)!
    await user.click(link)
    expect(await screen.findByRole('heading', { level: 2, name: titles[to] })).toBeInTheDocument()
  })
})

function renderAt(path: string) {
  render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('log file visibility', () => {
  it('groups the incident list by log file, with cross-file incidents under each file', async () => {
    renderAt('/incidents/aaa')
    const nav = await screen.findByRole('navigation', { name: 'Incidents' })
    const access = await within(nav).findByRole('region', { name: 'Incidents in access.log' })
    const auth = within(nav).getByRole('region', { name: 'Incidents in auth.log' })
    const incidentLinks = (region: HTMLElement) =>
      within(region).queryAllByRole('link').map((a) => a.getAttribute('href')).filter((h) => h?.startsWith('/incidents/'))
    expect(incidentLinks(access)).toEqual(['/incidents/aaa', '/incidents/bbb'])
    expect(incidentLinks(auth)).toEqual(['/incidents/aaa'])
    expect(within(access).getByRole('link', { name: 'Full log of access.log' })).toHaveAttribute(
      'href', `/logs?file=${encodeURIComponent('/data/uploads/x1/access.log')}`)
    expect(within(auth).getByText('also in access.log')).toBeInTheDocument()
    expect(within(access).getByText('also in auth.log')).toBeInTheDocument()
  })

  it('collapses a file group', async () => {
    const user = userEvent.setup()
    renderAt('/incidents/aaa')
    const nav = await screen.findByRole('navigation', { name: 'Incidents' })
    const header = await within(nav).findByRole('button', { name: /access\.log/ })
    await user.click(header)
    expect(header).toHaveAttribute('aria-expanded', 'false')
    const region = within(nav).getByRole('region', { name: 'Incidents in access.log' })
    expect(within(region).queryAllByRole('link').filter((a) => a.getAttribute('href')?.startsWith('/incidents/'))).toHaveLength(0)
  })

  it('marks a log line that also belongs to another incident', async () => {
    ROUTES['/api/incidents/aaa'] = { ...detail('aaa', 'First incident'), shared: { 'aaa-e': ['bbb'] } }
    renderAt('/incidents/aaa')
    const main = await screen.findByRole('main')
    expect(await within(main).findByText(/1 line is also part of another incident/)).toBeInTheDocument()
    const link = await within(main).findByRole('link', { name: 'Second incident' })
    expect(link).toHaveAttribute('href', '/incidents/bbb')
    expect(link.parentElement).toHaveTextContent('also in Second incident')
  })

  it('lists every incident a line belongs to in the full log', async () => {
    ROUTES['/api/events'] = { ...(BASE_ROUTES['/api/events'] as object), incidents: { 'auth-2': ['aaa', 'bbb'] } }
    renderAt(`/logs?file=${encodeURIComponent('/data/uploads/x1/auth.log')}`)
    const main = await screen.findByRole('main')
    const row = (await within(main).findByText('raw auth line 2')).closest('tr')!
    expect(within(row).getAllByRole('link').map((a) => a.textContent)).toEqual(['First incident', 'Second incident'])
  })

  it('shows the file, line number and raw text on the incident page', async () => {
    renderAt('/incidents/aaa')
    const main = await screen.findByRole('main')
    expect(await within(main).findByText('Log files')).toBeInTheDocument()
    expect(within(main).getByRole('button', { name: 'auth.log' })).toBeInTheDocument()
    expect(within(main).getByText(/1 line, Linux auth log/)).toBeInTheDocument()
    expect(within(main).getAllByText('from auth.log, line 4').length).toBeGreaterThan(0)
    expect(within(main).getByRole('heading', { name: 'Log lines (1)' })).toBeInTheDocument()
    expect(within(main).getByText('auth.log line 4')).toBeInTheDocument()
    expect(within(main).getByText(/Failed password for root \(aaa\)/)).toBeInTheDocument()
  })
})

describe('full log viewer', () => {
  it('opens a whole file from the sidebar and links lines to their incident', async () => {
    const user = userEvent.setup()
    renderAt('/incidents/aaa')
    const nav = await screen.findByRole('navigation', { name: 'Incidents' })
    await user.click(await within(nav).findByRole('link', { name: 'Full log of auth.log' }))
    const main = screen.getByRole('main')
    expect(await within(main).findByRole('heading', { level: 2, name: 'auth.log' })).toBeInTheDocument()
    expect(within(main).getByText(/Linux auth log: 31 lines/)).toBeInTheDocument()
    expect(within(main).getByRole('combobox', { name: 'Log file' })).toHaveValue('/data/uploads/x1/auth.log')
    const rows = within(main).getAllByRole('row').slice(1)
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringContaining('raw auth line 1'), expect.stringContaining('raw auth line 2'),
      expect.stringContaining('raw auth line 3'),
    ])
    const link = within(rows[1]).getByRole('link', { name: 'First incident' })
    expect(link).toHaveAttribute('href', '/incidents/aaa')
    // the request asked for this file in original line order
    const fetchMock = vi.mocked(fetch)
    expect(fetchMock.mock.calls.map(([u]) => String(u)).some((u) =>
      u.startsWith('/api/events?') && u.includes('order=file') && u.includes('source_file=%2Fdata%2Fuploads%2Fx1%2Fauth.log'),
    )).toBe(true)
  })

  it('jumps from an incident to its line in the full file', async () => {
    const user = userEvent.setup()
    renderAt('/incidents/aaa')
    const main = await screen.findByRole('main')
    await user.click(await within(main).findByRole('link', { name: 'Open the full auth.log at this incident' }))
    expect(await within(screen.getByRole('main')).findByRole('heading', { level: 2, name: 'auth.log' })).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.map(([u]) => String(u)).some((u) => u.includes('focus=aaa-e'))).toBe(true)
  })

  it('shows everything in time order when no file is picked', async () => {
    renderAt('/logs')
    expect(await screen.findByRole('heading', { level: 2, name: 'All logs' })).toBeInTheDocument()
    expect(await screen.findByText('auth.log line 1')).toBeInTheDocument()
  })
})

describe('opening an incident from the home page', () => {
  it('renders the incident (home -> incident)', async () => {
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={createQueryClient()}>
        <MemoryRouter initialEntries={['/']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { name: /Pick an incident/ })).toBeInTheDocument()
    await user.click((await screen.findAllByRole('link', { name: /First incident/ }))[0])
    expect(await screen.findByRole('heading', { level: 2, name: 'First incident' })).toBeInTheDocument()
  })
})

describe('model picker', () => {
  it('offers Gemma 4 4B and sends provider + model', async () => {
    const user = userEvent.setup()
    localStorage.clear()
    render(
      <QueryClientProvider client={createQueryClient()}>
        <MemoryRouter initialEntries={['/incidents/aaa']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    const picker = await screen.findByRole('combobox', { name: /Model/ })
    const option = await screen.findByRole('option', { name: 'gemma4:e4b (not installed)' })
    await user.selectOptions(picker, option)
    expect(JSON.parse(localStorage.getItem('logw.llm')!)).toEqual({ provider: 'ollama', model: 'gemma4:e4b' })
  })
})

describe('switching incidents after the browser reports offline', () => {
  it('still loads the incident (API is local)', async () => {
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={createQueryClient()}>
        <MemoryRouter initialEntries={['/incidents/aaa']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { level: 2, name: 'First incident' })).toBeInTheDocument()
    act(() => {
      window.dispatchEvent(new Event('offline'))
    })
    await user.click((await screen.findAllByRole('link', { name: /Second incident/ }))[0])
    expect(await screen.findByRole('heading', { level: 2, name: 'Second incident' })).toBeInTheDocument()
    act(() => {
      window.dispatchEvent(new Event('online'))
    })
  })
})

describe('switching incidents', () => {
  it('shows the newly selected incident without a reload', async () => {
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={['/incidents/aaa']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { level: 2, name: 'First incident' })).toBeInTheDocument()
    const links = await screen.findAllByRole('link', { name: /Second incident/ })
    await user.click(links[0])
    expect(await screen.findByRole('heading', { level: 2, name: 'Second incident' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { level: 2, name: 'First incident' })).not.toBeInTheDocument()
  })
})
