import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { AlertCircle, CheckCircle2, Loader2, Send, X } from 'lucide-react';
import { invoke } from '@tauri-apps/api/tauri';
import { toast } from 'sonner';

import { Button } from './ui/button';
import { useTheme } from '../providers/theme-provider';
import type { CrashBundleSummary } from '../types/crash';

interface FeedbackPanelProps {
  open: boolean;
  onClose: () => void;
}

interface FeedbackSubmissionResult {
  bundlePath: string;
  includedLogs: boolean;
  includedCrash: boolean;
  includedDiagnostics: boolean;
}

const categories = [
  { value: 'bug', label: 'Bug report' },
  { value: 'idea', label: 'Feature request' },
  { value: 'support', label: 'Support question' },
];

export function FeedbackPanel({ open, onClose }: FeedbackPanelProps) {
  const { prefersReducedMotion } = useTheme();
  const [category, setCategory] = useState('bug');
  const [message, setMessage] = useState('');
  const [contact, setContact] = useState('');
  const [includeLogs, setIncludeLogs] = useState(true);
  const [includeCrash, setIncludeCrash] = useState(false);
  const [includeDiagnostics, setIncludeDiagnostics] = useState(true);
  const [crashAvailable, setCrashAvailable] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<FeedbackSubmissionResult | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }

    setResult(null);
    let cancelled = false;

    void invoke<CrashBundleSummary | null>('get_active_crash_bundle')
      .then((bundle) => {
        if (cancelled) {
          return;
        }
        const available = Boolean(bundle);
        setCrashAvailable(available);
        setIncludeCrash(available);
      })
      .catch(() => {
        setCrashAvailable(false);
        setIncludeCrash(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose, open]);

  const resetForm = useCallback(() => {
    setCategory('bug');
    setMessage('');
    setContact('');
    setIncludeLogs(true);
    setIncludeCrash(false);
    setIncludeDiagnostics(true);
    setResult(null);
  }, []);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (submitting) {
        return;
      }

      const trimmedMessage = message.trim();
      if (!trimmedMessage) {
        toast.error('Add a short description before sending feedback.');
        return;
      }

      setSubmitting(true);
      try {
        const submission = await invoke<FeedbackSubmissionResult>('submit_feedback', {
          category,
          message: trimmedMessage,
          contact: contact.trim() ? contact.trim() : null,
          includeLogs,
          includeCrash: includeCrash && crashAvailable,
          includeDiagnostics,
        });
        setResult(submission);
        toast.success('Feedback package created');
        setMessage('');
        setContact('');
      } catch (error) {
        const details = error instanceof Error ? error.message : String(error);
        toast.error(`Failed to submit feedback: ${details}`);
      } finally {
        setSubmitting(false);
      }
    },
    [category, contact, crashAvailable, includeCrash, includeDiagnostics, includeLogs, message, submitting],
  );

  const handleCopyPath = useCallback(async (path: string) => {
    try {
      await navigator.clipboard.writeText(path);
      toast.success('Feedback bundle path copied');
    } catch (error) {
      const details = error instanceof Error ? error.message : String(error);
      toast.error(`Unable to copy path: ${details}`);
    }
  }, []);

  const animationDuration = prefersReducedMotion ? 0 : 0.2;

  if (!open) {
    return null;
  }

  return (
    <motion.div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: animationDuration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-labelledby="feedback-title"
        tabIndex={-1}
        className="mx-4 w-full max-w-2xl rounded-lg border border-border bg-background p-6 shadow-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        initial={{ y: prefersReducedMotion ? 0 : 24, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: prefersReducedMotion ? 0 : 24, opacity: 0 }}
        transition={{ duration: animationDuration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
      >
        <header className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="feedback-title" className="text-2xl font-semibold">
              Send feedback
            </h2>
            <p className="text-sm text-muted-foreground">
              Describe the issue or idea. The shell will bundle anonymized diagnostics so maintainers can reproduce it safely.
            </p>
          </div>
          <Button type="button" variant="ghost" size="icon" onClick={() => { onClose(); resetForm(); }}>
            <X className="h-4 w-4" aria-hidden="true" />
            <span className="sr-only">Close feedback panel</span>
          </Button>
        </header>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1">
            <label htmlFor="feedback-category" className="text-sm font-medium text-foreground">
              What kind of feedback is this?
            </label>
            <select
              id="feedback-category"
              className="rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={category}
              onChange={(event) => setCategory(event.target.value)}
            >
              {categories.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label htmlFor="feedback-message" className="text-sm font-medium text-foreground">
              Tell us what happened
            </label>
            <textarea
              id="feedback-message"
              className="min-h-[140px] rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Include any steps to reproduce, what you expected, and what you observed."
            />
          </div>

          <div className="flex flex-col gap-1">
            <label htmlFor="feedback-contact" className="text-sm font-medium text-foreground">
              Contact details (optional)
            </label>
            <input
              id="feedback-contact"
              type="text"
              className="rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={contact}
              onChange={(event) => setContact(event.target.value)}
              placeholder="Email or handle so we can follow up"
            />
            <p className="text-xs text-muted-foreground">
              We hash contact info before storing it. Maintainers will only see a masked version.
            </p>
          </div>

          <fieldset className="space-y-3 rounded-md border border-border p-4">
            <legend className="px-1 text-sm font-semibold">Include with submission</legend>
            <ToggleRow
              label="Recent shell logs"
              description="Helps diagnose non-fatal issues. Sensitive headers are automatically redacted."
              checked={includeLogs}
              onChange={setIncludeLogs}
            />
            <ToggleRow
              label="Current crash bundle"
              description={
                crashAvailable
                  ? 'Attach the most recent crash bundle so maintainers can replay the failure.'
                  : 'No crash bundle is available yet. Trigger a crash to capture one.'
              }
              disabled={!crashAvailable}
              checked={includeCrash && crashAvailable}
              onChange={(value) => setIncludeCrash(value)}
            />
            <ToggleRow
              label="Anonymized diagnostics"
              description="Captures OS version, CPU count, and uptime without personal identifiers."
              checked={includeDiagnostics}
              onChange={setIncludeDiagnostics}
            />
          </fieldset>

          {result ? (
            <div className="flex items-start gap-3 rounded-md border border-emerald-500/60 bg-emerald-500/10 p-4 text-sm text-emerald-900 dark:border-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-100">
              <CheckCircle2 className="mt-0.5 h-5 w-5" aria-hidden="true" />
              <div className="space-y-1">
                <p>Your feedback bundle is ready. Share the file below with the 0xgen maintainers.</p>
                <code className="block truncate rounded bg-background px-2 py-1 text-xs" title={result.bundlePath}>
                  {result.bundlePath}
                </code>
                <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <span>{result.includedLogs ? 'Logs attached' : 'Logs omitted'}</span>
                  <span>•</span>
                  <span>{result.includedCrash ? 'Crash bundle attached' : 'Crash bundle omitted'}</span>
                  <span>•</span>
                  <span>{result.includedDiagnostics ? 'Diagnostics captured' : 'Diagnostics omitted'}</span>
                </div>
                <div className="flex gap-2">
                  <Button type="button" variant="secondary" onClick={() => handleCopyPath(result.bundlePath)}>
                    Copy path
                  </Button>
                  <Button type="button" variant="ghost" onClick={() => { resetForm(); onClose(); }}>
                    Close
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-3 rounded-md border border-border bg-muted/40 p-4 text-sm text-muted-foreground">
              <AlertCircle className="mt-0.5 h-5 w-5" aria-hidden="true" />
              <p>
                Reviewing the generated bundle before sharing is recommended. Files live in a temporary directory so you can
                inspect them first.
              </p>
            </div>
          )}

          {!result ? (
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => { resetForm(); onClose(); }}>
                Cancel
              </Button>
              <Button type="submit" disabled={submitting} className="flex items-center gap-2">
                {submitting ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Send className="h-4 w-4" aria-hidden="true" />}
                {submitting ? 'Bundling…' : 'Create bundle'}
              </Button>
            </div>
          ) : null}
        </form>
      </motion.div>
    </motion.div>
  );
}

interface ToggleRowProps {
  label: string;
  description: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (value: boolean) => void;
}

function ToggleRow({ label, description, checked, disabled, onChange }: ToggleRowProps) {
  const id = useMemo(() => `toggle-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`, [label]);
  return (
    <label htmlFor={id} className={['flex items-start justify-between gap-3 rounded-md px-2 py-1', disabled ? 'opacity-60' : undefined].filter(Boolean).join(' ')}>
      <span className="flex-1">
        <span className="block text-sm font-medium text-foreground">{label}</span>
        <span className="block text-xs text-muted-foreground">{description}</span>
      </span>
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-1 h-4 w-4 rounded border-border accent-primary"
      />
    </label>
  );
}
