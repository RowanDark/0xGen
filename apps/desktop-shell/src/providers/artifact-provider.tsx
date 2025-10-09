import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import type { ArtifactStatus, OpenArtifactResponse } from '../lib/ipc';
import { getArtifactStatus } from '../lib/ipc';

interface ArtifactContextValue {
  status: ArtifactStatus | null;
  setStatusFromOpen: (summary: OpenArtifactResponse) => void;
  refreshStatus: () => Promise<void>;
}

const ArtifactContext = createContext<ArtifactContextValue | undefined>(undefined);

export function ArtifactProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<ArtifactStatus | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const next = await getArtifactStatus();
      setStatus(next);
    } catch (error) {
      console.error('Failed to load artifact status', error);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const setStatusFromOpen = useCallback((summary: OpenArtifactResponse) => {
    setStatus({
      loaded: true,
      manifest: summary.manifest,
      metrics: summary.metrics,
      caseCount: summary.caseCount,
      flowCount: summary.flowCount
    });
  }, []);

  const value = useMemo(
    () => ({
      status,
      setStatusFromOpen,
      refreshStatus
    }),
    [status, setStatusFromOpen, refreshStatus]
  );

  return <ArtifactContext.Provider value={value}>{children}</ArtifactContext.Provider>;
}

export function useArtifact() {
  const context = useContext(ArtifactContext);
  if (!context) {
    throw new Error('useArtifact must be used within an ArtifactProvider');
  }
  return context;
}
