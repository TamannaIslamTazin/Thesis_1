/**
 * SSI Healthcare - Admin Layout Wrapper
 *
 * Shared layout component for admin/portal routes.
 * Provides sidebar navigation + main content area.
 */

'use client';

import { AdminSidebar } from '@/components/layout/admin-sidebar';

export function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <AdminSidebar />
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}
