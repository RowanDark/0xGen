import { cn } from '../../lib/utils';

type StatusTone = 'neutral' | 'success' | 'warning' | 'critical';

const toneStyles: Record<StatusTone, string> = {
  neutral: 'border-border/60 bg-muted/40 text-muted-foreground',
  success: 'border-success/30 bg-success/10 text-success',
  warning: 'border-warning/30 bg-warning/10 text-warning',
  critical: 'border-error/40 bg-error/10 text-error'
};

const indicatorStyles: Record<StatusTone, string> = {
  neutral: 'bg-muted-foreground/80',
  success: 'bg-success',
  warning: 'bg-warning',
  critical: 'bg-error'
};

const resolveTone = (status: string): StatusTone => {
  const normalized = status.toLowerCase();

  if (normalized.includes('fail') || normalized.includes('error')) {
    return 'critical';
  }

  if (normalized.includes('success') || normalized.includes('pass') || normalized.includes('complete')) {
    return 'success';
  }

  if (normalized.includes('pending') || normalized.includes('wait') || normalized.includes('queue')) {
    return 'warning';
  }

  return 'neutral';
};

type StatusChipProps = {
  status: string;
  tone?: StatusTone;
  className?: string;
};

export function StatusChip({ status, tone, className }: StatusChipProps) {
  const resolvedTone = tone ?? resolveTone(status);

  return (
    <span
      className={cn(
        'inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide',
        'transition-colors duration-200',
        toneStyles[resolvedTone],
        className
      )}
      style={{ transitionTimingFunction: 'cubic-bezier(0.25, 0.1, 0.25, 1)' }}
    >
      <span className={cn('h-2 w-2 rounded-full', indicatorStyles[resolvedTone])} />
      {status}
    </span>
  );
}
