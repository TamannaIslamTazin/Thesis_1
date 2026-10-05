'use client';

/**
 * 404 Not Found Page
 * 
 * Displayed when a route doesn't exist.
 */

import Link from 'next/link';
import { FileQuestion, Home, Search } from 'lucide-react';
import { buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

export default function NotFound() {
  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-4rem)] p-8">
      <Card className="max-w-lg w-full text-center">
        <CardHeader>
          <div className="mx-auto w-20 h-20 rounded-full bg-muted flex items-center justify-center mb-4">
            <FileQuestion className="w-10 h-10 text-muted-foreground" />
          </div>
          <CardTitle className="text-3xl">404</CardTitle>
          <CardDescription className="text-lg">
            Page not found
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          <p className="text-muted-foreground">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
            Check the URL or navigate back to a known page.
          </p>
        </CardContent>
        
        <CardFooter className="flex flex-col sm:flex-row gap-3 justify-center">
          <Link 
            href="/"
            className={cn(buttonVariants())}
          >
            <Home className="w-4 h-4 mr-2" />
            Go to Dashboard
          </Link>
          <Link 
            href="/wallet"
            className={cn(buttonVariants({ variant: "outline" }))}
          >
            <Search className="w-4 h-4 mr-2" />
            Open Wallet
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}
