/**
 * SSI Healthcare - Auth Method Buttons
 *
 * SSI-native authentication entry points: Passkey/WebAuthn, DID Wallet, and Magic Link.
 * No third-party OAuth — all identity is self-sovereign.
 */

'use client';

import * as React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Loader2, Fingerprint, Wallet, Mail } from 'lucide-react';

type AuthMethod = 'passkey' | 'did_wallet' | 'magic_link';

interface AuthMethodConfig {
  id: AuthMethod;
  name: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
}

const authMethods: Record<AuthMethod, AuthMethodConfig> = {
  passkey: {
    id: 'passkey',
    name: 'Passkey',
    description: 'Sign in with biometrics or device PIN',
    icon: <Fingerprint className="w-5 h-5" />,
    color: 'text-foreground',
    bgColor: 'bg-blue-600 hover:bg-blue-700',
  },
  did_wallet: {
    id: 'did_wallet',
    name: 'DID Wallet',
    description: 'Authenticate with your decentralized identity',
    icon: <Wallet className="w-5 h-5" />,
    color: 'text-foreground',
    bgColor: 'bg-purple-600 hover:bg-purple-700',
  },
  magic_link: {
    id: 'magic_link',
    name: 'Magic Link',
    description: 'Receive a secure link via email',
    icon: <Mail className="w-5 h-5" />,
    color: 'text-foreground',
    bgColor: 'bg-emerald-600 hover:bg-emerald-700',
  },
};

export interface AuthMethodButtonProps {
  method: AuthMethod;
  onClick?: () => void;
  isLoading?: boolean;
  disabled?: boolean;
  fullWidth?: boolean;
  compact?: boolean;
  className?: string;
}

export function AuthMethodButton({
  method,
  onClick,
  isLoading = false,
  disabled = false,
  fullWidth = true,
  compact = false,
  className,
}: AuthMethodButtonProps) {
  const config = authMethods[method];
  
  if (!config) {
    console.error(`Unknown auth method: ${method}`);
    return null;
  }

  return (
    <motion.button
      onClick={onClick}
      disabled={disabled || isLoading}
      className={cn(
        'relative flex items-center gap-3 rounded-xl font-medium',
        'transition-all duration-200',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        compact ? 'px-4 py-2.5' : 'px-6 py-3.5',
        config.bgColor,
        config.color,
        fullWidth && 'w-full',
        className
      )}
      whileHover={{ scale: disabled ? 1 : 1.01 }}
      whileTap={{ scale: disabled ? 1 : 0.99 }}
    >
      {isLoading ? (
        <Loader2 className="w-5 h-5 animate-spin" />
      ) : (
        config.icon
      )}
      <div className={cn('text-left', compact && 'flex items-center gap-2')}>
        <span className="block font-semibold">{config.name}</span>
        {!compact && (
          <span className="block text-xs opacity-80">{config.description}</span>
        )}
      </div>
    </motion.button>
  );
}

/** Container for SSI auth method buttons */
export function AuthMethodGroup({
  onSelect,
  loadingMethod,
  methods = ['passkey', 'did_wallet', 'magic_link'],
  className,
}: {
  onSelect: (method: AuthMethod) => void;
  loadingMethod?: AuthMethod | null;
  methods?: AuthMethod[];
  className?: string;
}) {
  return (
    <div className={cn('flex flex-col gap-3', className)}>
      {methods.map((method) => (
        <AuthMethodButton
          key={method}
          method={method}
          onClick={() => onSelect(method)}
          isLoading={loadingMethod === method}
          disabled={!!loadingMethod}
        />
      ))}
    </div>
  );
}

/** Divider with "or" text */
export function AuthDivider({ text = 'or' }: { text?: string }) {
  return (
    <div className="relative flex items-center my-6">
      <div className="flex-grow border-t border-border" />
      <span className="flex-shrink mx-4 text-sm text-muted-foreground">{text}</span>
      <div className="flex-grow border-t border-border" />
    </div>
  );
}

export type { AuthMethod };
