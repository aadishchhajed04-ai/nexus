import { useCallback, useEffect, useState } from "react";

interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refresh: () => void;
}

/**
 * Fetches once immediately, then polls on an interval, and exposes a
 * manual refresh() for "refresh right now" triggers (e.g. a new
 * WebSocket message landed). Kept deliberately simple — no cache
 * layer, no request de-duping — this app talks to one local backend
 * with a handful of endpoints, not a large multi-client surface.
 */
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs = 5000): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    fetcher()
      .then((result) => {
        setData(result);
        setError(null);
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    refresh();
    if (!intervalMs) return;
    const id = setInterval(refresh, intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { data, error, loading, refresh };
}
