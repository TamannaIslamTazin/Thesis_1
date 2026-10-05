/**
 * SSI Healthcare - Premium Button Component
 *
 * Neuromorphic button with multiple variants, sizes, and states.
 * Includes motion effects for press and hover interactions.
 */

'use client';

import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { motion, HTMLMotionProps } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

const premiumButtonVariants = cva(
  `inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl 
   text-sm font-semibold transition-all duration-200 ease-out
   focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2
   disabled:pointer-events-none disabled:opacity-50
   [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0`,
  {
    variants: {
      variant: {
        default: `
          bg-primary text-primary-foreground
          neu-flat hover:neu-glow-subtle
          active:neu-pressed
        `,
        premium: `
          btn-premium text-foreground
          shadow-lg hover:shadow-xl
          active:scale-[0.98]
        `,
        secondary: `
          bg-secondary text-secondary-foreground
          neu-flat hover:bg-secondary/80
          active:neu-pressed
        `,
        destructive: `
          bg-destructive text-destructive-foreground
          shadow-md hover:shadow-lg hover:shadow-red-500/20
          active:scale-[0.98]
        `,
        outline: `
          border-2 border-border bg-transparent
          hover:bg-accent hover:text-accent-foreground hover:border-accent
          active:bg-accent/80
        `,
        ghost: `
          hover:bg-accent hover:text-accent-foreground
          active:bg-accent/80
        `,
        link: `
          text-primary underline-offset-4 hover:underline
        `,
        glow: `
          bg-primary text-primary-foreground
          pulse-glow
          hover:shadow-xl
          active:scale-[0.98]
        `,
      },
      size: {
        default: 'h-11 px-6 py-2',
        sm: 'h-9 rounded-lg px-4 text-xs',
        lg: 'h-12 rounded-xl px-8 text-base',
        xl: 'h-14 rounded-2xl px-10 text-lg',
        icon: 'h-10 w-10',
        'icon-sm': 'h-8 w-8 rounded-lg',
        'icon-lg': 'h-12 w-12',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface PremiumButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof premiumButtonVariants> {
  asChild?: boolean;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  fullWidth?: boolean;
}

const PremiumButton = React.forwardRef<HTMLButtonElement, PremiumButtonProps>(
  (
    {
      className,
      variant,
      size,
      asChild = false,
      isLoading = false,
      leftIcon,
      rightIcon,
      fullWidth = false,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    const Comp = asChild ? Slot : 'button';
    
    // When using asChild, we need to pass children directly without wrapping
    // The Slot component requires a single React element child
    if (asChild) {
      return (
        <Comp
          className={cn(premiumButtonVariants({ variant, size, className }), fullWidth && 'w-full')}
          ref={ref}
          {...props}
        >
          {children}
        </Comp>
      );
    }
    
    return (
      <Comp
        className={cn(premiumButtonVariants({ variant, size, className }), fullWidth && 'w-full')}
        ref={ref}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading && <Loader2 className="animate-spin" />}
        {!isLoading && leftIcon}
        {children}
        {!isLoading && rightIcon}
      </Comp>
    );
  }
);
PremiumButton.displayName = 'PremiumButton';

/** Animated version with Framer Motion */
interface MotionButtonProps
  extends Omit<HTMLMotionProps<'button'>, 'children'>,
    VariantProps<typeof premiumButtonVariants> {
  children?: React.ReactNode;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

const MotionButton = React.forwardRef<HTMLButtonElement, MotionButtonProps>(
  (
    {
      className,
      variant,
      size,
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <motion.button
        className={cn(premiumButtonVariants({ variant, size, className }))}
        ref={ref}
        disabled={disabled || isLoading}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        transition={{ type: 'spring', stiffness: 400, damping: 25 }}
        {...props}
      >
        {isLoading && <Loader2 className="animate-spin" />}
        {!isLoading && leftIcon}
        {children}
        {!isLoading && rightIcon}
      </motion.button>
    );
  }
);
MotionButton.displayName = 'MotionButton';

export { PremiumButton, MotionButton, premiumButtonVariants };
