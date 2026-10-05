/**
 * SSI Healthcare - User Wallet Page
 *
 * Main wallet interface with credential folders, activity feed,
 * and quick actions. Premium neuromorphic design.
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Plus,
  Search,
  Bell,
  Settings,
  QrCode,
  Share2,
  Clock,
  ChevronRight,
  Filter,
  CheckCircle2,
  AlertTriangle,
  FileText,
  User,
  LogOut,
  Menu,
  X,
  Loader2,
  RefreshCw,
  Building2,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { PremiumInput } from '@/components/ui/premium-input';
import {
  CredentialFolder,
  CredentialFolderGrid,
  AnimatedCredentialFolder,
  EmptyCredentialState,
} from '@/components/ui/credential-folder';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import { type CredentialCategory } from '@/lib/design-system';
import { useAuth } from '@/hooks/useAuth';
import { useCredentials } from '@/hooks/useCredentials';
import { useConsents } from '@/hooks/useConsents';

export default function WalletPage() {
  const router = useRouter();
  const { user, isAuthenticated, isLoading: authLoading, logout } = useAuth();
  const { 
    credentials, 
    offers,
    isLoading: credLoading, 
    error: credError,
    fetchCredentials,
    fetchOffers,
    acceptOffer,
    rejectOffer,
  } = useCredentials({ autoFetch: true });
  const { consents, isLoading: consentsLoading } = useConsents({ autoFetch: true });
  
  const [searchQuery, setSearchQuery] = React.useState('');
  const [selectedCategory, setSelectedCategory] = React.useState<string>('all');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  // Redirect if not authenticated
  React.useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push('/auth');
    }
  }, [authLoading, isAuthenticated, router]);

  // Map credentials to UI format
  const mappedCredentials = React.useMemo(() => {
    if (!Array.isArray(credentials)) return [];
    return credentials.map((cred) => {
      // Map backend category to UI category
      const categoryMap: Record<string, CredentialCategory> = {
        'BLOOD_WORK': 'blood_work',
        'PRESCRIPTIONS': 'prescriptions',
        'VACCINATIONS': 'vaccinations',
        'IMAGING': 'imaging',
        'LAB_RESULTS': 'lab_results',
        'INSURANCE': 'insurance',
        'GENERAL': 'general',
        'IDENTITY': 'general',
        'PROFESSIONAL': 'general',
      };
      
      const category = categoryMap[cred.category] || 'general';
      
      // Determine status
      let status: 'valid' | 'pending' | 'expired' | 'revoked' = 'valid';
      let isExpiring = false;
      if (cred.status === 'REVOKED') {
        status = 'revoked';
      } else if (cred.status === 'EXPIRED') {
        status = 'expired';
      } else if (cred.status === 'PENDING') {
        status = 'pending';
      } else if (cred.expiresAt) {
        const expiresIn = new Date(cred.expiresAt).getTime() - Date.now();
        if (expiresIn < 0) {
          status = 'expired';
        } else if (expiresIn < 30 * 24 * 60 * 60 * 1000) { // 30 days
          isExpiring = true;
        }
      }
      
      return {
        id: cred.id,
        category,
        title: cred.name,
        subtitle: cred.description || 'No description',
        issuer: cred.issuerDid.split(':').pop() || 'Unknown Issuer',
        issuedAt: cred.issuedAt,
        expiresAt: cred.expiresAt,
        status,
        isExpiring, // Custom flag for UI
      };
    });
  }, [credentials]);

  const filteredCredentials = mappedCredentials.filter((cred) => {
    const matchesSearch =
      cred.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cred.issuer.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || cred.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Calculate category counts
  const categoryCounts = React.useMemo(() => {
    const counts: Record<string, number> = { all: mappedCredentials.length };
    mappedCredentials.forEach((cred) => {
      counts[cred.category] = (counts[cred.category] || 0) + 1;
    });
    return counts;
  }, [mappedCredentials]);

  const categories = [
    { id: 'all', label: 'All', count: categoryCounts.all || 0 },
    { id: 'vaccinations', label: 'Vaccinations', count: categoryCounts.vaccinations || 0 },
    { id: 'prescriptions', label: 'Prescriptions', count: categoryCounts.prescriptions || 0 },
    { id: 'blood_work', label: 'Blood Work', count: categoryCounts.blood_work || 0 },
    { id: 'insurance', label: 'Insurance', count: categoryCounts.insurance || 0 },
    { id: 'imaging', label: 'Imaging', count: categoryCounts.imaging || 0 },
  ];

  // Loading state
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading wallet...</p>
        </div>
      </div>
    );
  }

  // Not authenticated
  if (!isAuthenticated || !user) {
    return null; // Will redirect
  }

  const userName = user.displayName || user.firstName || user.email?.split('@')[0] || 'User';
  const userInitials = userName.slice(0, 2).toUpperCase();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link href="/" className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary-foreground" />
              </div>
              <span className="text-lg font-bold text-foreground hidden sm:block">
                SSI Health
              </span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-6">
              <Link
                href="/wallet"
                className="text-sm font-medium text-foreground"
              >
                Wallet
              </Link>
              <Link
                href="/wallet/consents"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Consents
              </Link>
              <Link
                href="/wallet/settings"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Settings
              </Link>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3">
              {/* Refresh button */}
              <button 
                onClick={() => { fetchCredentials(); fetchOffers(); }}
                disabled={credLoading}
                className="relative p-2 rounded-lg hover:bg-muted transition-colors"
              >
                <RefreshCw className={cn("w-5 h-5 text-muted-foreground", credLoading && "animate-spin")} />
              </button>
              
              {/* Notifications */}
              <button className="relative p-2 rounded-lg hover:bg-muted transition-colors">
                <Bell className="w-5 h-5 text-muted-foreground" />
                {offers.length > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-primary rounded-full" />
                )}
              </button>

              {/* User menu */}
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-muted transition-colors">
                  <Avatar className="w-8 h-8">
                    <AvatarImage src={user.avatarUrl || undefined} />
                    <AvatarFallback>{userInitials}</AvatarFallback>
                  </Avatar>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <div className="px-3 py-2">
                    <p className="text-sm font-medium text-foreground">{userName}</p>
                    <p className="text-xs text-muted-foreground">{user.email}</p>
                  </div>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => router.push('/wallet/settings')}>
                    <User className="w-4 h-4 mr-2" />
                    Profile
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push('/wallet/settings')}>
                    <Settings className="w-4 h-4 mr-2" />
                    Settings
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem 
                    className="text-red-400"
                    onClick={() => logout()}
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

              {/* Mobile menu button */}
              <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
                <SheetTrigger className="md:hidden p-2 rounded-lg hover:bg-muted transition-colors">
                  <Menu className="w-5 h-5 text-muted-foreground" />
                </SheetTrigger>
                <SheetContent side="right" className="w-72">
                  <nav className="flex flex-col gap-4 mt-8">
                    <Link
                      href="/wallet"
                      className="text-lg font-medium text-foreground"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Wallet
                    </Link>
                    <Link
                      href="/wallet/consents"
                      className="text-lg text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Consents
                    </Link>
                    <Link
                      href="/hospital"
                      className="text-lg text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Hospital Records
                    </Link>
                    <Link
                      href="/wallet/settings"
                      className="text-lg text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Settings
                    </Link>
                  </nav>
                </SheetContent>
              </Sheet>
            </div>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Welcome section */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Welcome back, {userName}
          </h1>
          <p className="text-muted-foreground">
            {credLoading ? (
              'Loading credentials...'
            ) : (
              `You have ${credentials.length} credential${credentials.length !== 1 ? 's' : ''} in your wallet`
            )}
          </p>
        </div>

        {/* Quick actions */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <QuickAction
            icon={QrCode}
            label="Scan QR"
            description="Receive credential"
            onClick={() => router.push('/wallet/scan?mode=receive')}
          />
          <QuickAction
            icon={Share2}
            label="Share"
            description="Present credential"
            onClick={() => router.push('/wallet/scan?mode=share')}
          />
          <QuickAction
            icon={Plus}
            label="Request"
            description="Get new credential"
            onClick={() => router.push('/wallet/request')}
          />
          <QuickAction
            icon={Shield}
            label="Verify"
            description="Check credential"
            onClick={() => router.push('/verifier')}
          />
          <QuickAction
            icon={Building2}
            label="Hospital"
            description="Sync health records"
            onClick={() => router.push('/hospital')}
          />
        </div>

        {/* Error display */}
        {credError && (
          <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/20">
            <p className="text-sm text-red-400">{credError}</p>
            <button 
              onClick={fetchCredentials}
              className="text-xs text-red-300 underline mt-2"
            >
              Try again
            </button>
          </div>
        )}

        {/* Main content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Credentials section */}
          <div className="lg:col-span-2">
            <Tabs defaultValue="credentials" className="w-full">
              <div className="flex items-center justify-between mb-6">
                <TabsList>
                  <TabsTrigger value="credentials">Credentials</TabsTrigger>
                  <TabsTrigger value="offers" className="relative">
                    Offers
                    {offers.length > 0 && (
                      <Badge variant="default" className="ml-2 h-5 px-1.5">
                        {offers.length}
                      </Badge>
                    )}
                  </TabsTrigger>
                  <TabsTrigger value="expired">Expired</TabsTrigger>
                </TabsList>
                
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-9 pr-4 py-2 w-48 bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                  </div>
                </div>
              </div>

              {/* Category filters */}
              <div className="flex items-center gap-2 mb-6 overflow-x-auto pb-2">
                {categories.map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedCategory(cat.id)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors',
                      selectedCategory === cat.id
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {cat.label}
                    <Badge variant="secondary" className="ml-1">
                      {cat.count}
                    </Badge>
                  </button>
                ))}
              </div>

              <TabsContent value="credentials">
                {credLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-6 h-6 animate-spin text-primary" />
                  </div>
                ) : filteredCredentials.length > 0 ? (
                  <CredentialFolderGrid>
                    {filteredCredentials.map((cred) => (
                      <AnimatedCredentialFolder
                        key={cred.id}
                        category={cred.category}
                        title={cred.title}
                        subtitle={cred.subtitle}
                        issuer={cred.issuer}
                        issuedAt={cred.issuedAt}
                        expiresAt={cred.expiresAt}
                        status={cred.status}
                        onClick={() => router.push(`/wallet/credential/${cred.id}`)}
                      />
                    ))}
                  </CredentialFolderGrid>
                ) : (
                  <EmptyCredentialState
                    message={
                      searchQuery
                        ? `No credentials matching "${searchQuery}"`
                        : 'No credentials yet'
                    }
                  />
                )}
              </TabsContent>

              <TabsContent value="offers">
                {offers.length > 0 ? (
                  <div className="space-y-4">
                    {offers.map((offer) => (
                      <div
                        key={offer.id}
                        className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/20"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-foreground">
                              {offer.credentialType}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              From: {offer.issuerDid.split(':').pop()}
                            </p>
                          </div>
                          <div className="flex gap-2">
                            <PremiumButton size="sm" variant="default" onClick={() => acceptOffer(offer.id)}>
                              Accept
                            </PremiumButton>
                            <PremiumButton size="sm" variant="ghost" onClick={() => rejectOffer(offer.id)}>
                              Decline
                            </PremiumButton>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyCredentialState message="No pending offers" />
                )}
              </TabsContent>

              <TabsContent value="expired">
                {mappedCredentials.filter(c => c.status === 'expired').length > 0 ? (
                  <CredentialFolderGrid>
                    {mappedCredentials
                      .filter((cred) => cred.status === 'expired')
                      .map((cred) => (
                        <AnimatedCredentialFolder
                          key={cred.id}
                          category={cred.category}
                          title={cred.title}
                          subtitle={cred.subtitle}
                          issuer={cred.issuer}
                          issuedAt={cred.issuedAt}
                          expiresAt={cred.expiresAt}
                          status={cred.status}
                          onClick={() => router.push(`/wallet/credential/${cred.id}`)}
                        />
                      ))}
                  </CredentialFolderGrid>
                ) : (
                  <EmptyCredentialState message="No expired credentials" />
                )}
              </TabsContent>
            </Tabs>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Pending offers card */}
            {offers.length > 0 && (
              <PremiumCard variant="elevated" className="border-amber-500/30">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                    Pending Offers
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-3">
                    You have {offers.length} credential offer{offers.length !== 1 ? 's' : ''} waiting
                  </p>
                  <PremiumButton 
                    size="sm" 
                    className="w-full"
                    onClick={() => {
                      const tabsList = document.querySelector('[value="offers"]') as HTMLElement;
                      tabsList?.click();
                    }}
                  >
                    View Offers
                  </PremiumButton>
                </CardContent>
              </PremiumCard>
            )}

            {/* Quick stats */}
            <PremiumCard variant="elevated">
              <CardContent className="pt-6">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <p className="text-3xl font-bold text-foreground">
                      {credLoading ? '...' : credentials.length}
                    </p>
                    <p className="text-xs text-muted-foreground">Credentials</p>
                  </div>
                  <div className="text-center">
                    <p className="text-3xl font-bold text-foreground">
                      {consentsLoading ? '...' : consents.length}
                    </p>
                    <p className="text-xs text-muted-foreground">Consents</p>
                  </div>
                  <div className="text-center">
                    <p className="text-3xl font-bold text-foreground">
                      {offers.length}
                    </p>
                    <p className="text-xs text-muted-foreground">Offers</p>
                  </div>
                  <div className="text-center">
                    <p className="text-3xl font-bold text-foreground">
                      {mappedCredentials.filter(c => c.isExpiring).length}
                    </p>
                    <p className="text-xs text-muted-foreground">Expiring</p>
                  </div>
                </div>
              </CardContent>
            </PremiumCard>

            {/* Wallet status */}
            <PremiumCard variant="elevated">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Wallet Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Setup</span>
                    <Badge variant={user.walletSetup ? 'default' : 'secondary'}>
                      {user.walletSetup ? 'Complete' : 'Pending'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">DID</span>
                    <Badge variant={user.did ? 'default' : 'secondary'}>
                      {user.did ? 'Active' : 'Not Created'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Biometrics</span>
                    <Badge variant={user.biometricEnabled ? 'default' : 'secondary'}>
                      {user.biometricEnabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                </div>
                
                {!user.walletSetup && (
                  <PremiumButton 
                    size="sm" 
                    className="w-full mt-4"
                    onClick={() => router.push('/wallet/settings')}
                  >
                    Complete Setup
                  </PremiumButton>
                )}
              </CardContent>
            </PremiumCard>
          </div>
        </div>
      </main>
    </div>
  );
}

function QuickAction({
  icon: Icon,
  label,
  description,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <motion.button
      onClick={onClick}
      className="flex flex-col items-center p-4 rounded-xl bg-muted/50 border border-border hover:border-primary/50 hover:bg-muted transition-all group"
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.98 }}
    >
      <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-3 group-hover:bg-primary/20 transition-colors">
        <Icon className="w-6 h-6 text-primary" />
      </div>
      <p className="text-sm font-medium text-foreground">{label}</p>
      <p className="text-xs text-muted-foreground">{description}</p>
    </motion.button>
  );
}
