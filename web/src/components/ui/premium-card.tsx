/**
 * SSI Healthcare - Premium Card Component
 *
 * Neuromorphic card with elevated surface, hover effects,
 * and gradient overlays for visual depth.
 */

'use client';

import * as React from 'react';
import { motion, HTMLMotionProps } from 'framer-motion';
import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';

const premiumCardVariants = cva(
  `rounded-xl transition-all duration-300`,
  {
    variants: {
      variant: {
        default: `
          bg-card text-card-foreground
          border border-border
          neu-flat
        `,
        elevated: `
          bg-card text-card-foreground
          border border-border
          neu-raised
        `,
        glass: `
          glass
          border border-white/10
          text-foreground
        `,
        gradient: `
          bg-gradient-to-br from-card to-background
          border border-border
          neu-flat
        `,
        interactive: `
          bg-card text-card-foreground
          border border-border
          neu-flat
          cursor-pointer
          hover:border-primary/50
          card-hover
        `,
        outlined: `
          bg-transparent
          border-2 border-border
          hover:border-primary/50
        `,
        premium: `
          bg-card text-card-foreground
          border border-border
          gradient-subtle
          neu-raised
        `,
      },
      padding: {
        none: '',
        sm: 'p-4',
        default: 'p-6',
        lg: 'p-8',
      },
    },
    defaultVariants: {
      variant: 'default',
      padding: 'default',
    },
  }
);

export interface PremiumCardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof premiumCardVariants> {}

const PremiumCard = React.forwardRef<HTMLDivElement, PremiumCardProps>(
  ({ className, variant, padding, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(premiumCardVariants({ variant, padding, className }))}
      {...props}
    />
  )
);
PremiumCard.displayName = 'PremiumCard';

/** Animated card with hover and tap effects */
interface MotionCardProps
  extends Omit<HTMLMotionProps<'div'>, 'children'>,
    VariantProps<typeof premiumCardVariants> {
  children?: React.ReactNode;
  hoverEffect?: boolean;
}

const MotionCard = React.forwardRef<HTMLDivElement, MotionCardProps>(
  ({ className, variant, padding, hoverEffect = true, children, ...props }, ref) => (
    <motion.div
      ref={ref}
      className={cn(premiumCardVariants({ variant, padding, className }))}
      whileHover={hoverEffect ? { 
        y: -4, 
        boxShadow: '0 12px 24px rgba(0, 0, 0, 0.3), 0 0 20px rgba(59, 130, 246, 0.15)',
      } : undefined}
      whileTap={hoverEffect ? { scale: 0.98 } : undefined}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      {...props}
    >
      {children}
    </motion.div>
  )
);
MotionCard.displayName = 'MotionCard';

/** Card Header */
const PremiumCardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn('flex flex-col space-y-1.5', className)}
    {...props}
  />
));
PremiumCardHeader.displayName = 'PremiumCardHeader';

/** Card Title */
const PremiumCardTitle = React.forwardRef<
  HTMLHeadingElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn(
      'text-xl font-semibold leading-none tracking-tight text-foreground',
      className
    )}
    {...props}
  />
));
PremiumCardTitle.displayName = 'PremiumCardTitle';

/** Card Description */
const PremiumCardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn('text-sm text-muted-foreground', className)}
    {...props}
  />
));
PremiumCardDescription.displayName = 'PremiumCardDescription';

/** Card Content */
const PremiumCardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn('pt-4', className)} {...props} />
));
PremiumCardContent.displayName = 'PremiumCardContent';

/** Card Footer */
const PremiumCardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn('flex items-center pt-4', className)}
    {...props}
  />
));
PremiumCardFooter.displayName = 'PremiumCardFooter';

// Named exports for compatibility
const CardHeader = PremiumCardHeader;
const CardTitle = PremiumCardTitle;
const CardDescription = PremiumCardDescription;
const CardContent = PremiumCardContent;
const CardFooter = PremiumCardFooter;

export {
  PremiumCard,
  MotionCard,
  PremiumCardHeader,
  PremiumCardTitle,
  PremiumCardDescription,
  PremiumCardContent,
  PremiumCardFooter,
  premiumCardVariants,
  // Aliases for convenience
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
};
