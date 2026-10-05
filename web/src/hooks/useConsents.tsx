/**
 * SSI Healthcare - Consents Hook
 * 
 * React hook for managing user consents with real-time updates.
 */

'use client';

import { useState, useCallback, useEffect, useMemo } from 'react';
import { userApi, type Consent, type ConsentStats, ApiError } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UseConsentsOptions {
  autoFetch?: boolean;
  status?: 'active' | 'revoked' | 'expired';
}

interface UseConsentsReturn {
  consents: Consent[];
  stats: ConsentStats | null;
  isLoading: boolean;
  error: string | null;
  fetchConsents: () => Promise<void>;
  revokeConsent: (id: string, reason?: string) => Promise<void>;
  getActiveConsents: () => Consent[];
  getRevokedConsents: () => Consent[];
  getConsentsByVerifier: (verifierDid: string) => Consent[];
  clearError: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useConsents(options: UseConsentsOptions = {}): UseConsentsReturn {
  const { autoFetch = true, status } = options;
  
  const [consents, setConsents] = useState<Consent[]>([]);
  const [stats, setStats] = useState<ConsentStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const fetchConsents = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await userApi.getConsents({ status });
      if (response.data) {
        setConsents(response.data.consents);
        setStats(response.data.stats);
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to fetch consents';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [status]);
  
  const revokeConsent = useCallback(async (id: string, reason?: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await userApi.revokeConsent(id, reason);
      
      // Optimistic update
      setConsents(prev => prev.map(c => 
        c.id === id 
          ? { ...c, status: 'revoked' as const, revokedAt: new Date().toISOString() }
          : c
      ));
      
      // Update stats
      setStats(prev => prev ? {
        ...prev,
        active: prev.active - 1,
        revoked: prev.revoked + 1,
      } : null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to revoke consent';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  const getActiveConsents = useCallback((): Consent[] => {
    return consents.filter(c => c.status === 'active');
  }, [consents]);
  
  const getRevokedConsents = useCallback((): Consent[] => {
    return consents.filter(c => c.status === 'revoked');
  }, [consents]);
  
  const getConsentsByVerifier = useCallback((verifierDid: string): Consent[] => {
    return consents.filter(c => c.verifierDid === verifierDid);
  }, [consents]);
  
  const clearError = useCallback(() => setError(null), []);
  
  // Auto-fetch on mount
  useEffect(() => {
    if (autoFetch) {
      fetchConsents();
    }
  }, [autoFetch, fetchConsents]);
  
  return {
    consents,
    stats,
    isLoading,
    error,
    fetchConsents,
    revokeConsent,
    getActiveConsents,
    getRevokedConsents,
    getConsentsByVerifier,
    clearError,
  };
}

// ---------------------------------------------------------------------------
// Consent Timeline Hook
// ---------------------------------------------------------------------------

interface ConsentTimelineEntry {
  id: string;
  type: 'granted' | 'accessed' | 'revoked' | 'expired';
  consent: Consent;
  timestamp: string;
  description: string;
}

export function useConsentTimeline() {
  const { consents, ...rest } = useConsents();
  
  const timeline = useMemo((): ConsentTimelineEntry[] => {
    const entries: ConsentTimelineEntry[] = [];
    
    consents.forEach(consent => {
      // Grant event
      entries.push({
        id: `${consent.id}-granted`,
        type: 'granted',
        consent,
        timestamp: consent.grantedAt,
        description: `Granted access to ${consent.verifierName}`,
      });
      
      // Revoked event
      if (consent.revokedAt) {
        entries.push({
          id: `${consent.id}-revoked`,
          type: 'revoked',
          consent,
          timestamp: consent.revokedAt,
          description: `Revoked access from ${consent.verifierName}`,
        });
      }
      
      // Last access event
      if (consent.lastAccessedAt) {
        entries.push({
          id: `${consent.id}-accessed`,
          type: 'accessed',
          consent,
          timestamp: consent.lastAccessedAt,
          description: `${consent.verifierName} accessed your data`,
        });
      }
    });
    
    // Sort by timestamp, most recent first
    return entries.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [consents]);
  
  return { timeline, consents, ...rest };
}
