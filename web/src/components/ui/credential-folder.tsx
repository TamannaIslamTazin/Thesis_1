/**
 * SSI Healthcare - Credential Folder Component
 *
 * Skeuomorphic folder design for displaying healthcare credentials.
 * Each credential category has a distinct color and icon.
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { credentialCategories, type CredentialCategory } from '@/lib/design-system';
import {
  Droplet,
  Pill,
  Syringe,
  Scan,
  FlaskConical,
  ShieldCheck,
  FileText,
  ChevronRight,
  CheckCircle2,
  Clock,
  AlertTriangle,
} from 'lucide-react';

const categoryIcons: Record<CredentialCategory, React.ComponentType<{ className?: string }>> = {
  blood_work: Droplet,
  prescriptions: Pill,
  vaccinations: Syringe,
  imaging: Scan,
  lab_results: FlaskConical,
  insurance: ShieldCheck,
  general: FileText,
};

export interface CredentialFolderProps {
  category: CredentialCategory;
  title: string;
  subtitle?: string;
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
  status?: 'valid' | 'expired' | 'revoked' | 'pending';
  credentialCount?: number;
  onClick?: () => void;
  isSelected?: boolean;
  className?: string;
}

export function CredentialFolder({
  category,
  title,
  subtitle,
  issuer,
  issuedAt,
  expiresAt,
  status = 'valid',
  credentialCount,
  onClick,
  isSelected,
  className,
}: CredentialFolderProps) {
  const categoryData = credentialCategories[category] ?? credentialCategories.general;
  const IconComponent = categoryIcons[category] ?? FileText;
  
  const statusConfig = {
    valid: {
      icon: CheckCircle2,
      color: 'text-emerald-400',
      bg: 'bg-emerald-400/10',
      label: 'Valid',
    },
    expired: {
      icon: Clock,
      color: 'text-amber-400',
      bg: 'bg-amber-400/10',
      label: 'Expired',
    },
    revoked: {
      icon: AlertTriangle,
      color: 'text-red-400',
      bg: 'bg-red-400/10',
      label: 'Revoked',
    },
    pending: {
      icon: Clock,
      color: 'text-blue-400',
      bg: 'bg-blue-400/10',
      label: 'Pending',
    },
  };
  
  const StatusIcon = statusConfig[status].icon;

  return (
    <motion.div
      onClick={onClick}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && onClick) {
          e.preventDefault();
          onClick();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={`${title} credential from ${issuer} - ${statusConfig[status].label}`}
      aria-selected={isSelected}
      className={cn(
        'relative cursor-pointer group',
        className
      )}
      whileHover={{ y: -4, scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      layout
    >
      {/* Folder tab */}
      <div
        className="absolute -top-3 left-4 w-24 h-4 rounded-t-lg"
        style={{
          background: `linear-gradient(180deg, ${categoryData.color} 0%, ${categoryData.color}dd 100%)`,
        }}
      />
      
      {/* Main folder body */}
      <div
        className={cn(
          'relative rounded-xl overflow-hidden transition-all duration-300',
          isSelected && 'ring-2 ring-primary ring-offset-2 ring-offset-background',
        )}
        style={{
          background: `linear-gradient(180deg, ${categoryData.color}20 0%, ${categoryData.color}10 100%)`,
          borderColor: `${categoryData.color}40`,
        }}
      >
        {/* Folder shine effect */}
        <div
          className="absolute inset-0 opacity-50 group-hover:opacity-70 transition-opacity"
          style={{
            background: 'linear-gradient(135deg, rgba(255,255,255,0.1) 0%, transparent 50%)',
          }}
        />
        
        {/* Content */}
        <div className="relative p-5">
          <div className="flex items-start justify-between mb-4">
            {/* Category icon */}
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: `${categoryData.color}30` }}
            >
              <div style={{ color: categoryData.color }}>
                <IconComponent className="w-6 h-6" />
              </div>
            </div>
            
            {/* Status badge */}
            <div
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium',
                statusConfig[status].bg,
                statusConfig[status].color
              )}
            >
              <StatusIcon className="w-3.5 h-3.5" />
              {statusConfig[status].label}
            </div>
          </div>
          
          {/* Title and subtitle */}
          <div className="mb-3">
            <h3 className="text-lg font-semibold text-foreground line-clamp-1">
              {title}
            </h3>
            {subtitle && (
              <p className="text-sm text-muted-foreground line-clamp-1">
                {subtitle}
              </p>
            )}
          </div>
          
          {/* Metadata */}
          <div className="space-y-1.5 text-sm text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>Issuer</span>
              <span className="text-foreground font-medium truncate max-w-[60%]">
                {issuer}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Issued</span>
              <span className="text-foreground">
                {new Date(issuedAt).toLocaleDateString()}
              </span>
            </div>
            {expiresAt && (
              <div className="flex items-center justify-between">
                <span>Expires</span>
                <span className={cn(
                  'font-medium',
                  new Date(expiresAt) < new Date() ? 'text-amber-400' : 'text-foreground'
                )}>
                  {new Date(expiresAt).toLocaleDateString()}
                </span>
              </div>
            )}
          </div>
          
          {/* Credential count badge */}
          {credentialCount !== undefined && credentialCount > 1 && (
            <div className="absolute bottom-3 right-3">
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <span>{credentialCount} items</span>
              </div>
            </div>
          )}
          
          {/* Arrow indicator */}
          <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
            <ChevronRight className="w-5 h-5 text-muted-foreground" />
          </div>
        </div>
      </div>
    </motion.div>
  );
}

/** Grid container for credential folders */
export function CredentialFolderGrid({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      className={cn(
        'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6',
        className
      )}
      initial="initial"
      animate="animate"
      exit="exit"
      variants={{
        initial: {},
        animate: {
          transition: {
            staggerChildren: 0.05,
          },
        },
        exit: {
          transition: {
            staggerChildren: 0.03,
            staggerDirection: -1,
          },
        },
      }}
    >
      {children}
    </motion.div>
  );
}

/** Animated folder item for lists */
export function AnimatedCredentialFolder(props: CredentialFolderProps) {
  return (
    <motion.div
      variants={{
        initial: { opacity: 0, y: 20 },
        animate: { 
          opacity: 1, 
          y: 0,
          transition: { type: 'spring', stiffness: 400, damping: 30 },
        },
        exit: { 
          opacity: 0, 
          y: -10,
          transition: { duration: 0.2 },
        },
      }}
    >
      <CredentialFolder {...props} />
    </motion.div>
  );
}

/** Empty state for no credentials */
export function EmptyCredentialState({
  category,
  message = 'No credentials found',
}: {
  category?: CredentialCategory;
  message?: string;
}) {
  const IconComponent = category ? categoryIcons[category] : FileText;
  const color = category ? credentialCategories[category].color : '#6b7280';
  
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center justify-center py-12 px-4 text-center"
    >
      <div
        className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4"
        style={{ backgroundColor: `${color}20` }}
      >
        <IconComponent
          className="w-8 h-8"
          style={{ color }}
        />
      </div>
      <p className="text-muted-foreground">{message}</p>
    </motion.div>
  );
}
