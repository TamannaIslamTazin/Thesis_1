import * as React from 'react';
import { cn } from '@/lib/utils';

type Tone = 'default' | 'ok' | 'warn' | 'danger';

const toneClasses: Record<Tone, string> = {
  default: 'bg-surface-raised text-muted',
  ok: 'bg-ok/15 text-ok',
  warn: 'bg-warn/15 text-warn',
  danger: 'bg-danger/15 text-danger',
};

export function Badge({
  className,
  tone = 'default',
  ...props
}: React.ComponentProps<'span'> & { tone?: Tone }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium',
        toneClasses[tone],
        className,
      )}
      {...props}
    />
  );
}
