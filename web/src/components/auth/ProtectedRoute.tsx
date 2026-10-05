/**
 * SSI Healthcare - Protected Route Component
 * 
 * Client-side route protection that requires authentication.
 * Redirects unauthenticated users to the auth page.
 */

'use client';

import { useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/hooks/useAuth';
import { Loader2, ShieldAlert } from 'lucide-react';

// ---------------------------------------------------------------------------
// Loading Component
// ---------------------------------------------------------------------------

function LoadingScreen() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <p className="text-muted-foreground text-sm">Verifying authentication...</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Unauthorized Component
// ---------------------------------------------------------------------------

function UnauthorizedScreen({ message }: { message?: string }) {
  const router = useRouter();
  
  useEffect(() => {
    // FINDING-024: Redirect immediately — no delay. A 2-second window on a PHI page
    // is a privacy risk (screen readers, cached screenshots, automated scrapers).
    router.replace('/auth');
  }, [router]);
  
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4 text-center p-8">
        <ShieldAlert className="w-12 h-12 text-amber-500" />
        <h2 className="text-xl font-semibold text-foreground">Authentication Required</h2>
        <p className="text-muted-foreground text-sm max-w-md">
          {message || 'You need to be signed in to access this page.'}
        </p>
        <p className="text-muted-foreground text-xs">Redirecting to sign in...</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Wallet Required Component
// ---------------------------------------------------------------------------

function WalletRequiredScreen() {
  const router = useRouter();
  
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4 text-center p-8">
        <ShieldAlert className="w-12 h-12 text-amber-500" />
        <h2 className="text-xl font-semibold text-foreground">Wallet Setup Required</h2>
        <p className="text-muted-foreground text-sm max-w-md">
          You need to complete wallet setup before accessing this page.
        </p>
        <button
          onClick={() => router.push('/wallet/settings')}
          className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-foreground rounded-lg transition-colors"
        >
          Set Up Wallet
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Protected Route Props
// ---------------------------------------------------------------------------

interface ProtectedRouteProps {
  children: React.ReactNode;
  /** Require wallet to be set up (has DID) */
  requireWallet?: boolean;
  /** Custom message for unauthorized state */
  unauthorizedMessage?: string;
  /** Custom fallback while loading */
  loadingFallback?: React.ReactNode;
}

// ---------------------------------------------------------------------------
// Protected Route Component
// ---------------------------------------------------------------------------

/**
 * Wrap page content with this component to require authentication.
 * 
 * Usage:
 * ```tsx
 * export default function DashboardPage() {
 *   return (
 *     <ProtectedRoute>
 *       <Dashboard />
 *     </ProtectedRoute>
 *   );
 * }
 * ```
 */
export function ProtectedRoute({
  children,
  requireWallet = false,
  unauthorizedMessage,
  loadingFallback,
}: ProtectedRouteProps) {
  const { isLoading, isAuthenticated, user } = useAuth();
  const router = useRouter();
  
  // Show loading state while checking auth
  if (isLoading) {
    return loadingFallback ? <>{loadingFallback}</> : <LoadingScreen />;
  }
  
  // Redirect to auth if not authenticated
  if (!isAuthenticated) {
    return <UnauthorizedScreen message={unauthorizedMessage} />;
  }
  
  // Check for wallet requirement
  if (requireWallet && (!user?.walletSetup || !user?.did)) {
    return <WalletRequiredScreen />;
  }
  
  // Render protected content
  return <>{children}</>;
}

// ---------------------------------------------------------------------------
// Higher-Order Component Version
// ---------------------------------------------------------------------------

/**
 * HOC version for class components or when you prefer this pattern.
 * 
 * Usage:
 * ```tsx
 * export default withAuth(DashboardPage);
 * // or with wallet requirement:
 * export default withAuth(WalletPage, { requireWallet: true });
 * ```
 */
export function withAuth<P extends object>(
  Component: React.ComponentType<P>,
  options: Omit<ProtectedRouteProps, 'children'> = {}
) {
  return function ProtectedComponent(props: P) {
    return (
      <ProtectedRoute {...options}>
        <Component {...props} />
      </ProtectedRoute>
    );
  };
}

// ---------------------------------------------------------------------------
// Hook for Programmatic Auth Check
// ---------------------------------------------------------------------------

/**
 * Hook for programmatic auth checks in components.
 * Use this when you need to conditionally render based on auth
 * without blocking the entire page.
 * 
 * Usage:
 * ```tsx
 * const { isReady, canAccess, redirectToAuth } = useAuthGuard({ requireWallet: true });
 * 
 * if (!isReady) return <Loading />;
 * if (!canAccess) return <Unauthorized />;
 * return <ProtectedContent />;
 * ```
 */
export function useAuthGuard(options: { requireWallet?: boolean } = {}) {
  const { isLoading, isAuthenticated, user } = useAuth();
  const router = useRouter();
  
  const canAccess = isAuthenticated && 
    (!options.requireWallet || (user?.walletSetup && user?.did));
  
  const redirectToAuth = useCallback(() => {
    router.push('/auth');
  }, [router]);
  
  const redirectToWalletSetup = useCallback(() => {
    router.push('/wallet/settings');
  }, [router]);
  
  return {
    isReady: !isLoading,
    isAuthenticated,
    canAccess,
    user,
    redirectToAuth,
    redirectToWalletSetup,
  };
}
