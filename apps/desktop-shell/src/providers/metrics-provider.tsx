import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState
} from 'react';

import { fetchMetrics, type DashboardMetrics } from '../lib/ipc';
import { useArtifact } from './artifact-provider';

const HISTORY_LIMIT = 60;

type MetricSnapshot = DashboardMetrics & { timestamp: number };

type MetricsContextValue = {
  history: MetricSnapshot[];
  latest: MetricSnapshot | null;
  loading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
};

const MetricsContext = createContext<MetricsContextValue | undefined>(undefined);

export function MetricsProvider({ children }: { children: React.ReactNode }) {
  const { status } = useArtifact();
  const offlineMode = Boolean(status?.loaded);
  const [history, setHistory] = useState<MetricSnapshot[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(false);
  const inFlightRef = useRef(false);

  const appendSnapshot = useCallback((metrics: DashboardMetrics) => {
    setHistory((previous) => {
      const timestamp = Date.now();
      const nextEntry: MetricSnapshot = { timestamp, ...metrics };
      const last = previous[previous.length - 1];
      if (
        last &&
        last.eventsTotal === nextEntry.eventsTotal &&
        last.queueDepth === nextEntry.queueDepth &&
        timestamp - last.timestamp < 500
      ) {
        return previous;
      }
      const next = [...previous.slice(-(HISTORY_LIMIT - 1)), nextEntry];
      return next;
    });
  }, []);

  const refresh = useCallback(async () => {
    if (offlineMode || inFlightRef.current) {
      return;
    }
    inFlightRef.current = true;
    setLoading(true);
    try {
      const snapshot = await fetchMetrics();
      appendSnapshot(snapshot);
      setError(null);
    } catch (rawError) {
      const nextError = rawError instanceof Error ? rawError : new Error(String(rawError));
      setError(nextError);
      throw nextError;
    } finally {
      inFlightRef.current = false;
      setLoading(false);
    }
  }, [appendSnapshot, offlineMode]);

  useEffect(() => {
    if (!offlineMode) {
      return;
    }
    if (status?.metrics) {
      setHistory([{ timestamp: Date.now(), ...status.metrics }]);
    } else {
      setHistory([]);
    }
    setError(null);
  }, [offlineMode, status?.metrics]);

  useEffect(() => {
    if (offlineMode) {
      return;
    }
    setHistory([]);
    let cancelled = false;

    const poll = async () => {
      try {
        await refresh();
      } catch (pollError) {
        if (cancelled) {
          return;
        }
        console.error('Failed to fetch metrics', pollError);
      }
    };

    void poll();
    const interval = window.setInterval(poll, 15_000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [offlineMode, refresh]);

  const value = useMemo<MetricsContextValue>(
    () => ({
      history,
      latest: history.length > 0 ? history[history.length - 1] : null,
      loading,
      error,
      refresh
    }),
    [history, loading, error, refresh]
  );

  return <MetricsContext.Provider value={value}>{children}</MetricsContext.Provider>;
}

export function useMetrics() {
  const context = useContext(MetricsContext);
  if (!context) {
    throw new Error('useMetrics must be used within a MetricsProvider');
  }
  return context;
}

export type { MetricSnapshot };
