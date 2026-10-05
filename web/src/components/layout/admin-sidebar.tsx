/**
 * SSI Healthcare - Admin Sidebar
 *
 * Navigation sidebar for admin/portal routes (dashboard, issuer, verifier, admin).
 * Shows current user DID from auth context.
 */

'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Hospital,
  LayoutDashboard,
  FileSignature,
  ShieldCheck,
  Settings,
  User,
  Pill,
  AlertTriangle,
  FileHeart,
  LogOut,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/hooks/useAuth';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/issuer', label: 'Issue Credentials', icon: FileSignature },
  { href: '/verifier', label: 'Verify Credentials', icon: ShieldCheck },
  { href: '/pharmacy', label: 'Pharmacy', icon: Pill },
  { href: '/insurance', label: 'Insurance Claims', icon: FileHeart },
  { href: '/emergency', label: 'Emergency Access', icon: AlertTriangle },
  { href: '/admin', label: 'Admin Panel', icon: Settings },
];

export function AdminSidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  const displayName = user?.displayName ?? (user?.firstName ? `${user.firstName} ${user.lastName ?? ''}`.trim() : user?.email) ?? 'Admin User';
  const displayDid = user?.did
    ? `${user.did.slice(0, 16)}...${user.did.slice(-6)}`
    : 'No DID assigned';

  return (
    <aside className="w-64 bg-card border-r border-border flex flex-col shrink-0">
      <div className="p-6 border-b border-border">
        <Link href="/dashboard" className="flex items-center gap-2">
          <Hospital className="w-6 h-6 text-blue-400" />
          <h1 className="text-xl font-bold text-foreground">SSI Healthcare</h1>
        </Link>
        <p className="text-xs text-muted-foreground mt-1">Portal</p>
      </div>

      <nav className="flex-1 p-4 overflow-y-auto">
        <ul className="space-y-1">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive = pathname === href || pathname.startsWith(`${href}/`);
            return (
              <li key={href}>
                <Link
                  href={href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="p-4 border-t border-border space-y-2">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center shrink-0">
            <User className="w-4 h-4 text-foreground" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium text-foreground truncate">{displayName}</p>
            <p className="text-xs text-muted-foreground truncate">{displayDid}</p>
          </div>
        </div>
        <button
          onClick={() => logout()}
          className="flex items-center gap-2 px-3 py-2 w-full text-sm text-muted-foreground hover:text-destructive transition-colors rounded-lg hover:bg-destructive/10"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
