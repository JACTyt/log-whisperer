import { Component, type ErrorInfo, type ReactNode } from 'react'

interface State {
  error: Error | null
}

/** Shows render errors instead of a blank page. Give it a `key` (e.g. the route) so navigating recovers. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Log Whisperer view crashed:', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div role="alert" className="mx-auto max-w-[60ch] px-6 py-10">
        <h2 className="text-lg font-semibold text-sev-critical">This view failed to render</h2>
        <p className="mt-2 font-mono text-sm break-all text-muted">{this.state.error.message}</p>
        <button
          type="button"
          onClick={() => this.setState({ error: null })}
          className="mt-4 rounded border border-rule px-3 py-1 text-sm hover:bg-raised"
        >
          Try again
        </button>
      </div>
    )
  }
}
