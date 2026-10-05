/**
 * SSI Healthcare - Credentials Hook
 * 
 * React hook for managing user credentials with caching and optimistic updates.
 */

'use client';

import { useState, useCallback, useEffect, useMemo } from 'react';
import { userApi, credentialApi, type Credential, type CredentialOffer, type CredentialStats, ApiError } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UseCredentialsOptions {
  autoFetch?: boolean;
  category?: string;
  status?: string;
}

interface UseCredentialsReturn {
  credentials: Credential[];
  credentialStats: CredentialStats | null;
  offers: CredentialOffer[];
  isLoading: boolean;
  error: string | null;
  fetchCredentials: () => Promise<void>;
  fetchOffers: () => Promise<void>;
  acceptOffer: (offerId: string) => Promise<Credential | undefined>;
  rejectOffer: (offerId: string, reason?: string) => Promise<void>;
  deleteCredential: (id: string) => Promise<void>;
  getCredential: (id: string) => Promise<Credential | undefined>;
  getCredentialsByType: (type: string) => Credential[];
  clearError: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useCredentials(options: UseCredentialsOptions = {}): UseCredentialsReturn {
  const { autoFetch = true, category, status } = options;
  
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [credentialStats, setCredentialStats] = useState<CredentialStats | null>(null);
  const [offers, setOffers] = useState<CredentialOffer[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const fetchCredentials = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await userApi.getCredentials({ category, status });
      const payload = response.data;
      // Backend returns { credentials: [...], stats: {...} }
      if (payload && typeof payload === 'object' && 'credentials' in payload) {
        setCredentials(Array.isArray(payload.credentials) ? payload.credentials : []);
        setCredentialStats(payload.stats || null);
      } else if (Array.isArray(payload)) {
        setCredentials(payload);
      } else {
        setCredentials([]);
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to fetch credentials';
      setError(message);
      setCredentials([]);
    } finally {
      setIsLoading(false);
    }
  }, [category, status]);
  
  const fetchOffers = useCallback(async () => {
    try {
      const response = await credentialApi.getOffers();
      const data = response.data;
      setOffers(Array.isArray(data) ? data : []);
    } catch (err) {
      // Offers are non-critical — don't block the UI
      console.warn('Failed to fetch credential offers:', err instanceof ApiError ? err.message : err);
      setOffers([]);
    }
  }, []);
  
  const acceptOffer = useCallback(async (offerId: string): Promise<Credential | undefined> => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await credentialApi.acceptOffer(offerId);
      
      // Optimistic update: remove offer and add credential
      setOffers(prev => prev.filter(o => o.id !== offerId));
      if (response.data) {
        setCredentials(prev => [...prev, response.data!]);
      }
      
      return response.data;
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to accept offer';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  const rejectOffer = useCallback(async (offerId: string, reason?: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await credentialApi.rejectOffer(offerId, reason);
      
      // Optimistic update: remove offer
      setOffers(prev => prev.filter(o => o.id !== offerId));
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to reject offer';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  const deleteCredential = useCallback(async (id: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await credentialApi.deleteCredential(id);
      
      // Optimistic update: remove credential
      setCredentials(prev => prev.filter(c => c.id !== id));
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to delete credential';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  const getCredential = useCallback(async (id: string): Promise<Credential | undefined> => {
    // Check cache first
    const cached = credentials.find(c => c.id === id);
    if (cached) return cached;
    
    try {
      const response = await userApi.getCredential(id);
      return response.data;
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Credential not found';
      setError(message);
      return undefined;
    }
  }, [credentials]);
  
  const getCredentialsByType = useCallback((credType: string): Credential[] => {
    return credentials.filter(c => c.type.includes(credType));
  }, [credentials]);
  
  const clearError = useCallback(() => setError(null), []);
  
  // Auto-fetch on mount
  useEffect(() => {
    if (autoFetch) {
      fetchCredentials();
      fetchOffers();
    }
  }, [autoFetch, fetchCredentials, fetchOffers]);
  
  return {
    credentials,
    credentialStats,
    offers,
    isLoading,
    error,
    fetchCredentials,
    fetchOffers,
    acceptOffer,
    rejectOffer,
    deleteCredential,
    getCredential,
    getCredentialsByType,
    clearError,
  };
}

// ---------------------------------------------------------------------------
// Grouped Credentials Hook
// ---------------------------------------------------------------------------

interface CredentialGroup {
  type: string;
  label: string;
  icon: string;
  credentials: Credential[];
  color: string;
}

export function useGroupedCredentials() {
  const { credentials, ...rest } = useCredentials();
  
  const groups = useMemo((): CredentialGroup[] => {
    const typeConfig: Record<string, { label: string; icon: string; color: string }> = {
      HealthRecordCredential: { label: 'Health Records', icon: 'FileHeart', color: 'rose' },
      PrescriptionCredential: { label: 'Prescriptions', icon: 'Pill', color: 'blue' },
      VaccinationCredential: { label: 'Vaccinations', icon: 'Syringe', color: 'green' },
      LabResultCredential: { label: 'Lab Results', icon: 'TestTube', color: 'purple' },
      InsuranceCredential: { label: 'Insurance', icon: 'Shield', color: 'amber' },
      BloodWorkCredential: { label: 'Blood Work', icon: 'Droplet', color: 'red' },
      ImagingCredential: { label: 'Imaging', icon: 'Scan', color: 'cyan' },
      MemberCredential: { label: 'Memberships', icon: 'BadgeCheck', color: 'emerald' },
    };
    
    const grouped = new Map<string, Credential[]>();
    
    credentials.forEach(cred => {
      // Get the most specific type (last non-VerifiableCredential type)
      const specificType = cred.type.find(t => t !== 'VerifiableCredential') || 'VerifiableCredential';
      const existing = grouped.get(specificType) || [];
      grouped.set(specificType, [...existing, cred]);
    });
    
    return Array.from(grouped.entries()).map(([type, creds]) => {
      const config = typeConfig[type] || { label: type, icon: 'FileText', color: 'gray' };
      return {
        type,
        ...config,
        credentials: creds.sort((a, b) => 
          new Date(b.issuedAt).getTime() - new Date(a.issuedAt).getTime()
        ),
      };
    });
  }, [credentials]);
  
  return { groups, credentials, ...rest };
}
