import { Info, ShieldAlert } from 'lucide-react';

import { cn } from '../lib/utils';

type RedactionNoticeProps = {
  capability: string;
  className?: string;
  message?: string;
};

export function RedactionNotice({ capability, className, message = 'Redacted by policy' }: RedactionNoticeProps) {
  const tooltip = `Requires ${capability} to view unredacted content.`;

  return (
    <div
      className={cn(
        'flex items-center gap-2 rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm text-sky-900 dark:text-sky-100',
        className
      )}
    >
      <ShieldAlert aria-hidden="true" className="h-4 w-4 text-sky-600 dark:text-sky-400" />
      <span>{message}</span>
      <span className="inline-flex items-center" role="img" aria-label={tooltip} title={tooltip}>
        <Info aria-hidden="true" className="h-3 w-3 text-sky-600 dark:text-sky-300" />
      </span>
    </div>
  );
}
