/**
 * SSI Healthcare - Premium Input Component
 *
 * Neuromorphic input field with focus states, labels,
 * error handling, and animated transitions.
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

const premiumInputVariants = cva(
  `flex w-full rounded-xl bg-background px-4 py-3
   text-base transition-all duration-200
   file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground
   placeholder:text-muted-foreground
   focus-visible:outline-none
   disabled:cursor-not-allowed disabled:opacity-50`,
  {
    variants: {
      variant: {
        default: `
          border border-input
          focus:border-primary focus:ring-2 focus:ring-primary/20
          hover:border-muted-foreground/50
        `,
        filled: `
          bg-muted border-0
          focus:bg-background focus:ring-2 focus:ring-primary/20
        `,
        underline: `
          rounded-none border-0 border-b-2 border-input px-0
          focus:border-primary
        `,
        neuromorphic: `
          border border-input
          neu-pressed
          focus:border-primary focus:neu-glow-subtle
        `,
      },
      inputSize: {
        sm: 'h-9 px-3 text-sm',
        default: 'h-11 px-4',
        lg: 'h-14 px-5 text-lg',
      },
    },
    defaultVariants: {
      variant: 'default',
      inputSize: 'default',
    },
  }
);

export interface PremiumInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'>,
    VariantProps<typeof premiumInputVariants> {
  label?: string;
  error?: string;
  success?: boolean;
  hint?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

const PremiumInput = React.forwardRef<HTMLInputElement, PremiumInputProps>(
  (
    {
      className,
      variant,
      inputSize,
      type,
      label,
      error,
      success,
      hint,
      leftIcon,
      rightIcon,
      id,
      ...props
    },
    ref
  ) => {
    const inputId = id || React.useId();
    const hasError = !!error;
    const hasSuccess = success && !hasError;

    return (
      <div className="space-y-2">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-foreground"
          >
            {label}
          </label>
        )}
        
        <div className="relative">
          {leftIcon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
              {leftIcon}
            </div>
          )}
          
          <input
            type={type}
            id={inputId}
            className={cn(
              premiumInputVariants({ variant, inputSize }),
              leftIcon && 'pl-10',
              (rightIcon || hasError || hasSuccess) && 'pr-10',
              hasError && 'border-destructive focus:border-destructive focus:ring-destructive/20',
              hasSuccess && 'border-emerald-500 focus:border-emerald-500 focus:ring-emerald-500/20',
              className
            )}
            ref={ref}
            aria-invalid={hasError}
            aria-describedby={hasError ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined}
            {...props}
          />
          
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            {hasError && (
              <AlertCircle className="h-5 w-5 text-destructive" />
            )}
            {hasSuccess && (
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            )}
            {!hasError && !hasSuccess && rightIcon}
          </div>
        </div>
        
        <AnimatePresence mode="wait">
          {hasError && (
            <motion.p
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              id={`${inputId}-error`}
              className="text-sm text-destructive"
            >
              {error}
            </motion.p>
          )}
          {hint && !hasError && (
            <p id={`${inputId}-hint`} className="text-sm text-muted-foreground">
              {hint}
            </p>
          )}
        </AnimatePresence>
      </div>
    );
  }
);
PremiumInput.displayName = 'PremiumInput';

/** Textarea variant */
export interface PremiumTextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  hint?: string;
}

const PremiumTextarea = React.forwardRef<HTMLTextAreaElement, PremiumTextareaProps>(
  ({ className, label, error, hint, id, ...props }, ref) => {
    const textareaId = id || React.useId();
    const hasError = !!error;

    return (
      <div className="space-y-2">
        {label && (
          <label
            htmlFor={textareaId}
            className="block text-sm font-medium text-foreground"
          >
            {label}
          </label>
        )}
        
        <textarea
          id={textareaId}
          className={cn(
            `flex min-h-[120px] w-full rounded-xl border border-input bg-background px-4 py-3
             text-base transition-all duration-200
             placeholder:text-muted-foreground
             focus:border-primary focus:ring-2 focus:ring-primary/20 focus-visible:outline-none
             disabled:cursor-not-allowed disabled:opacity-50
             resize-none`,
            hasError && 'border-destructive focus:border-destructive focus:ring-destructive/20',
            className
          )}
          ref={ref}
          aria-invalid={hasError}
          aria-describedby={hasError ? `${textareaId}-error` : hint ? `${textareaId}-hint` : undefined}
          {...props}
        />
        
        <AnimatePresence mode="wait">
          {hasError && (
            <motion.p
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              id={`${textareaId}-error`}
              className="text-sm text-destructive"
            >
              {error}
            </motion.p>
          )}
          {hint && !hasError && (
            <p id={`${textareaId}-hint`} className="text-sm text-muted-foreground">
              {hint}
            </p>
          )}
        </AnimatePresence>
      </div>
    );
  }
);
PremiumTextarea.displayName = 'PremiumTextarea';

export { PremiumInput, PremiumTextarea, premiumInputVariants };
