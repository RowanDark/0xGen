import { ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/tauri';
import { save } from '@tauri-apps/api/dialog';
import { toast } from 'sonner';

import {
  type CrashBundleSummary,
  type CrashFilePreview,
} from '../types/crash';
import { CrashReviewDialog, type CrashPreviewEntry } from '../components/crash-review-dialog';

interface CrashReporterProviderProps {
  children: ReactNode;
}

export function CrashReporterProvider({ children }: CrashReporterProviderProps) {
  const [bundle, setBundle] = useState<CrashBundleSummary | null>(null);
  const [previews, setPreviews] = useState<Record<string, CrashPreviewEntry>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let isMounted = true;

    void invoke<CrashBundleSummary | null>('get_active_crash_bundle').then((existing) => {
      if (existing && isMounted) {
        setBundle(existing);
      }
    });

    const unlistenPromise = listen<CrashBundleSummary>('crash-bundle-ready', (event) => {
      setBundle(event.payload);
      setPreviews({});
    });

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      const reason = event.reason;
      const error =
        reason instanceof Error ? reason : new Error(typeof reason === 'string' ? reason : String(reason));
      void invoke('report_renderer_crash', {
        message: error.message ?? 'Unhandled renderer rejection',
        stack: error.stack ?? null,
      }).catch((reportError) => {
        console.error('Failed to report unhandled rejection', reportError);
      });
    };

    const handleWindowError = (event: ErrorEvent) => {
      const stack = event.error instanceof Error ? event.error.stack ?? null : null;
      const message = event.message || 'Unhandled renderer error';
      void invoke('report_renderer_crash', {
        message,
        stack,
      }).catch((reportError) => {
        console.error('Failed to report window error', reportError);
      });
    };

    window.addEventListener('unhandledrejection', handleUnhandledRejection);
    window.addEventListener('error', handleWindowError);

    return () => {
      isMounted = false;
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
      window.removeEventListener('error', handleWindowError);
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const loadPreview = useCallback(async (path: string) => {
    setPreviews((current) => ({
      ...current,
      [path]: { status: 'loading' },
    }));

    try {
      const preview = await invoke<CrashFilePreview>('preview_crash_file', { path });
      setPreviews((current) => ({
        ...current,
        [path]: {
          status: 'ready',
          content: preview.content,
          truncated: preview.truncated,
        },
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setPreviews((current) => ({
        ...current,
        [path]: {
          status: 'error',
          error: message,
        },
      }));
    }
  }, []);

  const handleSave = useCallback(async () => {
    if (!bundle) {
      return;
    }

    setSaving(true);
    try {
      const targetPath = await save({
        title: 'Save crash bundle',
        defaultPath: `${bundle.id}.tar.gz`,
      });

      if (!targetPath) {
        return;
      }

      await invoke('save_crash_bundle', { target: targetPath });
      toast.success(`Crash bundle saved to ${targetPath}`);
      let cleanupFailed = false;
      try {
        await invoke('discard_crash_bundle');
      } catch (error) {
        cleanupFailed = true;
        const message = error instanceof Error ? error.message : String(error);
        toast.error(`Saved bundle but failed to clean up temporary files: ${message}`);
      }
      if (!cleanupFailed) {
        setBundle(null);
        setPreviews({});
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to save crash bundle: ${message}`);
    } finally {
      setSaving(false);
    }
  }, [bundle]);

  const handleDiscard = useCallback(async () => {
    try {
      await invoke('discard_crash_bundle');
      toast.success('Crash bundle discarded');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to discard crash bundle: ${message}`);
      return;
    }

    setBundle(null);
    setPreviews({});
  }, []);

  const handleCopy = useCallback(async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied to clipboard`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(`Unable to copy ${label.toLowerCase()}: ${message}`);
    }
  }, []);

  const previewState = useMemo(() => previews, [previews]);

  return (
    <>
      {children}
      {bundle ? (
        <CrashReviewDialog
          bundle={bundle}
          previews={previewState}
          onRequestPreview={loadPreview}
          onSave={handleSave}
          onDiscard={handleDiscard}
          onCopy={handleCopy}
          saving={saving}
        />
      ) : null}
    </>
  );
}
