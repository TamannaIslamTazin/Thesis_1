/**
 * Select Component - Custom compound dropdown
 *
 * Supports the shadcn/ui compound API:
 *   <Select value={v} onValueChange={set}>
 *     <SelectTrigger><SelectValue placeholder="Pick..." /></SelectTrigger>
 *     <SelectContent>
 *       <SelectItem value="a">Option A</SelectItem>
 *     </SelectContent>
 *   </Select>
 *
 * Also supports the simple options-array API:
 *   <Select options={[{value:'a', label:'A'}]} onValueChange={set} />
 */

'use client';

import * as React from 'react';
import { ChevronDown, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface SelectContextValue {
  value: string;
  onValueChange: (val: string) => void;
  open: boolean;
  setOpen: (open: boolean) => void;
  labelMap: Map<string, string>;
  registerLabel: (value: string, label: string) => void;
}

const SelectContext = React.createContext<SelectContextValue | null>(null);

function useSelectContext() {
  const ctx = React.useContext(SelectContext);
  if (!ctx) throw new Error('Select compound components must be used inside <Select>');
  return ctx;
}

// ---------------------------------------------------------------------------
// Select (root)
// ---------------------------------------------------------------------------

interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  /** Legacy: pass options directly instead of using compound children */
  options?: SelectOption[];
  placeholder?: string;
  children?: React.ReactNode;
  className?: string;
  disabled?: boolean;
}

const Select = ({
  value: controlledValue,
  defaultValue = '',
  onValueChange,
  options,
  placeholder,
  children,
  className,
  disabled,
}: SelectProps) => {
  const [internalValue, setInternalValue] = React.useState(defaultValue);
  const [open, setOpen] = React.useState(false);
  const [labelMap] = React.useState(() => new Map<string, string>());
  const containerRef = React.useRef<HTMLDivElement>(null);

  const value = controlledValue !== undefined ? controlledValue : internalValue;

  const handleValueChange = React.useCallback(
    (val: string) => {
      if (controlledValue === undefined) setInternalValue(val);
      onValueChange?.(val);
      setOpen(false);
    },
    [controlledValue, onValueChange]
  );

  const registerLabel = React.useCallback(
    (val: string, label: string) => {
      labelMap.set(val, label);
    },
    [labelMap]
  );

  // Close on outside click
  React.useEffect(() => {
    if (!open) return;
    function handleOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, [open]);

  // Simple options-array mode → native select
  if (options) {
    return (
      <div className={cn('relative', className)} ref={containerRef}>
        <select
          value={value}
          disabled={disabled}
          onChange={(e) => handleValueChange(e.target.value)}
          className={cn(
            'flex h-10 w-full appearance-none rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 pr-10'
          )}
        >
          {placeholder && (
            <option value="" disabled>
              {placeholder}
            </option>
          )}
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 opacity-50 pointer-events-none" />
      </div>
    );
  }

  return (
    <SelectContext.Provider value={{ value, onValueChange: handleValueChange, open, setOpen, labelMap, registerLabel }}>
      <div className={cn('relative', className)} ref={containerRef}>
        {children}
      </div>
    </SelectContext.Provider>
  );
};
Select.displayName = 'Select';

// ---------------------------------------------------------------------------
// SelectTrigger
// ---------------------------------------------------------------------------

interface SelectTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

const SelectTrigger = React.forwardRef<HTMLButtonElement, SelectTriggerProps>(
  ({ className, children, ...props }, ref) => {
    const { open, setOpen } = useSelectContext();
    return (
      <button
        type="button"
        ref={ref}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className={cn(
          'flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
          className
        )}
        {...props}
      >
        {children}
        <ChevronDown className={cn('h-4 w-4 opacity-50 transition-transform', open && 'rotate-180')} />
      </button>
    );
  }
);
SelectTrigger.displayName = 'SelectTrigger';

// ---------------------------------------------------------------------------
// SelectValue
// ---------------------------------------------------------------------------

interface SelectValueProps {
  placeholder?: string;
  children?: React.ReactNode;
}

const SelectValue = ({ placeholder }: SelectValueProps) => {
  const { value, labelMap } = useSelectContext();
  const displayLabel = value ? (labelMap.get(value) ?? value) : null;
  return <span className={cn(!displayLabel && 'text-muted-foreground')}>{displayLabel ?? placeholder}</span>;
};
SelectValue.displayName = 'SelectValue';

// ---------------------------------------------------------------------------
// SelectContent
// ---------------------------------------------------------------------------

interface SelectContentProps {
  children: React.ReactNode;
  className?: string;
}

const SelectContent = ({ children, className }: SelectContentProps) => {
  const { open } = useSelectContext();
  if (!open) return null;
  return (
    <div
      role="listbox"
      className={cn(
        'absolute left-0 top-[calc(100%+4px)] z-50 min-w-full overflow-hidden rounded-md border border-border bg-popover text-popover-foreground shadow-md',
        'animate-in fade-in-0 zoom-in-95',
        className
      )}
    >
      <div className="p-1">{children}</div>
    </div>
  );
};
SelectContent.displayName = 'SelectContent';

// ---------------------------------------------------------------------------
// SelectItem
// ---------------------------------------------------------------------------

interface SelectItemProps {
  value: string;
  children: React.ReactNode;
  className?: string;
}

const SelectItem = ({ value, children, className }: SelectItemProps) => {
  const { value: selectedValue, onValueChange, registerLabel } = useSelectContext();
  const isSelected = selectedValue === value;

  // Register label text for SelectValue display
  React.useEffect(() => {
    if (typeof children === 'string') {
      registerLabel(value, children);
    }
  }, [value, children, registerLabel]);

  return (
    <button
      type="button"
      role="option"
      aria-selected={isSelected}
      onClick={() => onValueChange(value)}
      className={cn(
        'relative flex w-full cursor-default select-none items-center gap-2 rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none',
        'hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground',
        isSelected && 'bg-accent/50',
        className
      )}
    >
      {isSelected && (
        <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
          <Check className="h-4 w-4" />
        </span>
      )}
      {children}
    </button>
  );
};
SelectItem.displayName = 'SelectItem';

// ---------------------------------------------------------------------------
// SelectLabel (optional group label)
// ---------------------------------------------------------------------------

const SelectLabel = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <div className={cn('px-2 py-1.5 text-xs font-semibold text-muted-foreground', className)}>{children}</div>
);
SelectLabel.displayName = 'SelectLabel';

export { Select, SelectTrigger, SelectValue, SelectContent, SelectItem, SelectLabel };

