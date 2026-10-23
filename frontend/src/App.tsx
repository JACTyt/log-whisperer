import { useQuery } from '@tanstack/react-query'
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom'
import { api } from './api/client'
import { ErrorBoundary } from './ErrorBoundary'
import { EvidenceProvider } from './evidence/EvidenceContext'
import { EvidenceDrawer } from './evidence/EvidenceDrawer'
import { ChatPanel } from './workspace/ChatPanel'
import { EventsExplorer } from './workspace/EventsExplorer'
import { IncidentView } from './workspace/IncidentView'
import { Sidebar } from './workspace/Sidebar'

function BackendBanner() {
  const { error } = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 10000, retry: false })
  if (!error) return null
  return (
    <div role="alert" className="border-b border-sev-critical/50 bg-sev-critical/15 px-4 py-2 text-sm">
      {(error as Error).message}
    </div>
  )
}

function Welcome() {
  return (
    <div className="mx-auto max-w-[60ch] px-6 py-16">
      <h2 className="text-2xl font-semibold tracking-tight">Pick an incident to see what happened</h2>
      <p className="mt-3 text-muted">
        Log Whisperer groups detections into incidents and explains each one as a timeline. Every statement carries
        numbered evidence markers that open the exact log lines behind it, so you can check the story instead of trusting it.
      </p>
      <p className="mt-3 text-muted">
        To read whole log files, open <Link to="/logs" className="text-text underline underline-offset-4">All logs</Link>{' '}
        or use <span className="text-text">Full log</span> next to a file on the left.
      </p>
      <p className="mt-3 text-muted">Add log files on the left, or start live ingestion to receive syslog.</p>
    </div>
  )
}

function Workspace({ main }: { main: React.ReactNode }) {
  const { incidentId } = useParams()
  const { pathname } = useLocation()
  return (
    <div className="grid h-full grid-cols-1 lg:grid-cols-[300px_1fr_360px]">
      <div className="hidden min-h-0 lg:block">
        <Sidebar />
      </div>
      <main className="min-h-0 overflow-y-auto">
        {/* small screens: the incident list lives on the home page, detail pages link back to it */}
        {incidentId ? (
          <Link to="/" className="block px-6 pt-4 text-sm text-muted lg:hidden">
            Back to incidents
          </Link>
        ) : (
          <div className="lg:hidden">
            <Sidebar />
          </div>
        )}
        <ErrorBoundary key={pathname}>{main}</ErrorBoundary>
      </main>
      <div className="hidden min-h-0 lg:block">
        {/* a new conversation per incident */}
        <ChatPanel key={incidentId ?? 'global'} />
      </div>
    </div>
  )
}

export default function App() {
  return (
    <EvidenceProvider>
      <div className="flex h-full flex-col">
        <BackendBanner />
        <div className="min-h-0 flex-1">
          <Routes>
            <Route path="/" element={<Workspace main={<Welcome />} />} />
            <Route path="/incidents/:incidentId" element={<Workspace main={<IncidentView />} />} />
            <Route path="/logs" element={<Workspace main={<EventsExplorer />} />} />
            <Route path="/events" element={<Navigate to="/logs" replace />} />
          </Routes>
        </div>
      </div>
      <EvidenceDrawer />
    </EvidenceProvider>
  )
}
