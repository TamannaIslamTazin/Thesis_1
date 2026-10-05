'use client';

/**
 * Global Error Handler
 * 
 * Handles errors at the root level, including layout errors.
 * This is the last line of defense for catching errors.
 */

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log to error reporting service
    console.error('Global error:', error);
  }, [error]);

  return (
    <html lang="en">
      <body className="min-h-screen bg-zinc-950 text-zinc-100 font-sans antialiased">
        <div className="flex flex-col items-center justify-center min-h-screen p-4">
          <div className="max-w-md w-full bg-zinc-900 border border-zinc-800 rounded-xl p-8 text-center">
            <div className="w-16 h-16 rounded-full bg-red-500/10 flex items-center justify-center mx-auto mb-6">
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
            
            <h1 className="text-2xl font-bold mb-2">Something went wrong</h1>
            <p className="text-zinc-400 mb-6">
              An unexpected error occurred. Our team has been notified.
            </p>
            
            {error.digest && (
              <p className="text-xs text-zinc-600 mb-4 font-mono">
                Error ID: {error.digest}
              </p>
            )}
            
            <div className="flex gap-3 justify-center">
              <button
                onClick={() => reset()}
                className="inline-flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition-colors text-sm font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Try again
              </button>
              <a
                href="/"
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors text-sm font-medium"
              >
                <Home className="w-4 h-4" />
                Go home
              </a>
            </div>
          </div>
          
          <p className="mt-8 text-xs text-zinc-600">
            SSI Healthcare Portal
          </p>
        </div>
      </body>
    </html>
  );
}
