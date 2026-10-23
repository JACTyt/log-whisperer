import { QueryClient } from '@tanstack/react-query'

/**
 * The API is local (same machine / same compose stack), so the browser's internet connectivity is irrelevant.
 * With the default networkMode ('online'), an `offline` event from Windows network-adapter churn (Docker, VPN)
 * pauses every query until a reload — the incident view then stays blank.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { networkMode: 'always', staleTime: 5000, refetchOnWindowFocus: false },
      mutations: { networkMode: 'always' },
    },
  })
}
