'use client';

/**
 * Route-level Error Handler
 * 
 * Catches errors in the route segment and its children.
 * Displays a user-friendly error page with recovery options.
 */

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, ArrowLeft, Home, Bug } from 'lucide-react';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log error to reporting service
    console.error('Route error:', error);
  }, [error]);

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-4rem)] p-8">
      <Card className="max-w-lg w-full">
        <CardHeader className="text-center">
          <div className="mx-auto w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center mb-4">
            <AlertTriangle className="w-8 h-8 text-destructive" />
          </div>
          <CardTitle className="text-2xl">Something went wrong</CardTitle>
          <CardDescription className="text-base">
            We encountered an unexpected error while loading this page.
            Don&apos;t worry, your data is safe.
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div className="bg-muted rounded-lg p-4">
            <p className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
              <Bug className="w-4 h-4" />
              Error Details
            </p>
            <p className="text-sm font-mono text-destructive">
              {error.message || 'An unknown error occurred'}
            </p>
            {error.digest && (
              <p className="text-xs text-muted-foreground mt-2">
                Reference: {error.digest}
              </p>
            )}
          </div>
          
          <div className="text-sm text-muted-foreground">
            <p>You can try:</p>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>Refreshing the page</li>
              <li>Going back to the previous page</li>
              <li>Returning to the dashboard</li>
            </ul>
          </div>
        </CardContent>
        
        <CardFooter className="flex flex-col sm:flex-row gap-3">
          <Button 
            variant="default" 
            onClick={() => reset()}
            className="w-full sm:w-auto"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Try Again
          </Button>
          <Button 
            variant="outline"
            onClick={() => window.history.back()}
            className="w-full sm:w-auto"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Go Back
          </Button>
          <a 
            href="/"
            className={cn(
              buttonVariants({ variant: "ghost" }),
              "w-full sm:w-auto"
            )}
          >
            <Home className="w-4 h-4 mr-2" />
            Dashboard
          </a>
        </CardFooter>
      </Card>
    </div>
  );
}
