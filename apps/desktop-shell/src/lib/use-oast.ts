import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, type Event } from '@tauri-apps/api/event';
import { z } from 'zod';

// Zod schemas for OAST data
const InteractionSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  type: z.string().default('http'),
  method: z.string().optional(),
  path: z.string().optional(),
  query: z.string().optional(),
  clientIP: z.string(),
  headers: z.record(z.array(z.string())).optional(),
  body: z.string().optional(),
  userAgent: z.string().optional(),
  testID: z.string().optional(),
  requestID: z.string().optional(),
});

const OASTStatusSchema = z.object({
  running: z.boolean(),
  port: z.number(),
  mode: z.string(),
});

const OASTStatsSchema = z.object({
  total: z.number(),
  uniqueIDs: z.number(),
  byType: z.record(z.number()),
});

const OASTResponseSchema = z.object({
  enabled: z.boolean(),
  status: OASTStatusSchema.optional(),
  interactions: z.array(InteractionSchema).optional(),
  stats: OASTStatsSchema.optional(),
});

// Export types from Zod schemas
export type Interaction = z.infer<typeof InteractionSchema>;
export type OASTStatus = z.infer<typeof OASTStatusSchema>;
export type OASTStats = z.infer<typeof OASTStatsSchema>;

interface OASTContextValue {
  isEnabled: boolean;
  status: OASTStatus | null;
  interactions: Interaction[];
  stats: OASTStats;
  loading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
  clearInteractions: () => void;
}

const DEFAULT_STATS: OASTStats = {
  total: 0,
  uniqueIDs: 0,
  byType: {},
};

const POLL_INTERVAL = 2000; // 2 seconds

export function useOAST(): OASTContextValue {
  const [isEnabled, setIsEnabled] = useState(false);
  const [status, setStatus] = useState<OASTStatus | null>(null);
  const [interactions, setInteractions] = useState<Interaction[]>([]);
  const [stats, setStats] = useState<OASTStats>(DEFAULT_STATS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const inFlightRef = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    setLoading(true);

    try {
      // Get OAST status
      const response = await invoke('oast_status');
      const parsed = OASTResponseSchema.parse(response);

      setIsEnabled(parsed.enabled);
      setStatus(parsed.status ?? null);

      if (parsed.enabled && parsed.interactions) {
        setInteractions(parsed.interactions);
      }

      if (parsed.stats) {
        setStats(parsed.stats);
      }

      setError(null);
    } catch (rawError) {
      const nextError = rawError instanceof Error ? rawError : new Error(String(rawError));
      setError(nextError);
      console.error('Failed to refresh OAST:', nextError);
    } finally {
      inFlightRef.current = false;
      setLoading(false);
    }
  }, []);

  const clearInteractions = useCallback(() => {
    setInteractions([]);
    setStats(DEFAULT_STATS);
  }, []);

  // Initial load and polling
  useEffect(() => {
    let cancelled = false;
    let intervalId: number | undefined;

    const poll = async () => {
      if (cancelled) return;
      await refresh();
    };

    void poll();
    intervalId = window.setInterval(poll, POLL_INTERVAL);

    return () => {
      cancelled = true;
      if (intervalId) {
        window.clearInterval(intervalId);
      }
    };
  }, [refresh]);

  // Subscribe to real-time OAST events
  useEffect(() => {
    let unsubscribe: (() => void) | undefined;

    const subscribe = async () => {
      try {
        unsubscribe = await listen<Interaction>('oast_interaction', (event: Event<Interaction>) => {
          const interaction = InteractionSchema.parse(event.payload);

          setInteractions((prev) => [interaction, ...prev]);
          setStats((prev) => ({
            total: prev.total + 1,
            uniqueIDs: prev.uniqueIDs, // Will be updated on next refresh
            byType: {
              ...prev.byType,
              [interaction.type]: (prev.byType[interaction.type] || 0) + 1,
            },
          }));
        });
      } catch (err) {
        console.error('Failed to subscribe to OAST events:', err);
      }
    };

    void subscribe();

    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, []);

  return useMemo(
    () => ({
      isEnabled,
      status,
      interactions,
      stats,
      loading,
      error,
      refresh,
      clearInteractions,
    }),
    [isEnabled, status, interactions, stats, loading, error, refresh, clearInteractions]
  );
}
