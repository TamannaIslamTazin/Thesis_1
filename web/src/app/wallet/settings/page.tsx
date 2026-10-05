/**
 * SSI Healthcare - User Settings Page
 *
 * Account settings, security configuration, notifications,
 * emergency contacts, and data management.
 */

'use client';

import * as React from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useTheme } from 'next-themes';
import { toast } from 'sonner';
import {
  ArrowLeft,
  User,
  Shield,
  Bell,
  Key,
  Smartphone,
  Users,
  Download,
  Trash2,
  ChevronRight,
  AlertTriangle,
  Fingerprint,
  Moon,
  Sun,
  Plus,
  X,
  Pencil,
  Loader2,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/premium-card';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAuth } from '@/hooks/useAuth';
import { userApi } from '@/lib/api';

type EmergencyContact = { id: string; name: string; relationship: string; email?: string | null; canAccess: string[] };

export default function SettingsPage() {
  const { user, logout, refreshUser } = useAuth();
  const { theme, setTheme } = useTheme();
  const router = useRouter();
  const [notifications, setNotifications] = React.useState({
    credentialReceived: true,
    verificationRequest: true,
    consentExpiring: true,
    securityAlerts: true,
    marketing: false,
  });
  const [isSavingNotifications, setIsSavingNotifications] = React.useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = React.useState(false);
  const [isDeletingAccount, setIsDeletingAccount] = React.useState(false);
  const [emergencyContacts, setEmergencyContacts] = React.useState<EmergencyContact[]>([]);
  const [isLoadingContacts, setIsLoadingContacts] = React.useState(true);

  // Profile edit dialog state
  const [showProfileEdit, setShowProfileEdit] = React.useState(false);
  const [profileForm, setProfileForm] = React.useState({
    firstName: user?.firstName || '',
    lastName: user?.lastName || '',
    displayName: user?.displayName || '',
    phone: '',
  });
  const [isSavingProfile, setIsSavingProfile] = React.useState(false);

  // Emergency contact dialog state
  const [showAddContact, setShowAddContact] = React.useState(false);
  const [contactForm, setContactForm] = React.useState({ name: '', relationship: '', email: '', phone: '' });
  const [isAddingContact, setIsAddingContact] = React.useState(false);

  // Security toggles state
  const [biometricEnabled, setBiometricEnabled] = React.useState(user?.biometricEnabled ?? false);
  const [autoLockMinutes, setAutoLockMinutes] = React.useState(user?.autoLockMinutes ?? 5);
  const [isSavingSecurity, setIsSavingSecurity] = React.useState(false);

  // Load notification prefs from backend on mount
  React.useEffect(() => {
    async function loadPrefs() {
      try {
        const res = await userApi.getNotifications();
        if (res.data) {
          const evPrefs = (res.data.eventPreferences as Record<string, boolean>) || {};
          setNotifications({
            credentialReceived: evPrefs.credential_received ?? true,
            verificationRequest: evPrefs.verification_request ?? true,
            consentExpiring: evPrefs.consent_expiring ?? true,
            securityAlerts: evPrefs.security_alert ?? true,
            marketing: evPrefs.marketing ?? false,
          });
        }
      } catch {
        // Fall back to defaults — non-critical
      }
    }
    loadPrefs();
  }, []);

  // Load emergency contacts from API
  React.useEffect(() => {
    async function loadContacts() {
      try {
        const res = await userApi.getProfile();
        if (res.data) {
          const profile = res.data as unknown as Record<string, unknown>;
          const contacts = (profile.emergencyContacts || []) as EmergencyContact[];
          setEmergencyContacts(contacts);
        }
      } catch {
        // Fall back to empty
      } finally {
        setIsLoadingContacts(false);
      }
    }
    loadContacts();
  }, []);

  // Sync biometricEnabled from user when user loads
  React.useEffect(() => {
    if (user) {
      setBiometricEnabled(user.biometricEnabled ?? false);
      setAutoLockMinutes(user.autoLockMinutes ?? 5);
      setProfileForm({
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        displayName: user.displayName || '',
        phone: '',
      });
    }
  }, [user]);

  const persistNotifications = React.useCallback(async (prefs: typeof notifications) => {
    setIsSavingNotifications(true);
    try {
      await userApi.updateNotifications({
        eventPreferences: {
          credential_received: prefs.credentialReceived,
          verification_request: prefs.verificationRequest,
          consent_expiring: prefs.consentExpiring,
          security_alert: prefs.securityAlerts,
          marketing: prefs.marketing,
        },
      });
    } catch {
      toast.error('Failed to save notification preferences');
    } finally {
      setIsSavingNotifications(false);
    }
  }, []);

  const handleNotificationChange = React.useCallback(
    (key: keyof typeof notifications, checked: boolean) => {
      setNotifications((prev) => {
        const next = { ...prev, [key]: checked };
        persistNotifications(next);
        return next;
      });
    },
    [persistNotifications]
  );

  const handleBiometricToggle = React.useCallback(async (checked: boolean) => {
    setBiometricEnabled(checked);
    setIsSavingSecurity(true);
    try {
      await userApi.updateSecurity({ biometricEnabled: checked });
      await refreshUser();
      toast.success(`Biometric authentication ${checked ? 'enabled' : 'disabled'}`);
    } catch {
      setBiometricEnabled(!checked); // revert
      toast.error('Failed to update security settings');
    } finally {
      setIsSavingSecurity(false);
    }
  }, [refreshUser]);

  const handleAutoLockChange = React.useCallback(async (minutes: number) => {
    setAutoLockMinutes(minutes);
    try {
      await userApi.updateSecurity({ autoLockMinutes: minutes });
      await refreshUser();
      toast.success(`Auto-lock set to ${minutes} minute${minutes !== 1 ? 's' : ''}`);
    } catch {
      toast.error('Failed to update auto-lock setting');
    }
  }, [refreshUser]);

  const handleSaveProfile = React.useCallback(async () => {
    setIsSavingProfile(true);
    try {
      await userApi.updateProfile({
        firstName: profileForm.firstName || undefined,
        lastName: profileForm.lastName || undefined,
        displayName: profileForm.displayName || undefined,
        phone: profileForm.phone || undefined,
      });
      await refreshUser();
      setShowProfileEdit(false);
      toast.success('Profile updated');
    } catch {
      toast.error('Failed to update profile');
    } finally {
      setIsSavingProfile(false);
    }
  }, [profileForm, refreshUser]);

  const handleAddEmergencyContact = React.useCallback(async () => {
    if (!contactForm.name || !contactForm.relationship) {
      toast.error('Name and relationship are required');
      return;
    }
    setIsAddingContact(true);
    try {
      const res = await userApi.addEmergencyContact({
        name: contactForm.name,
        relationship: contactForm.relationship,
        email: contactForm.email || undefined,
        phone: contactForm.phone || undefined,
      });
      if (res.data) {
        setEmergencyContacts((prev) => [...prev, res.data!]);
      }
      setContactForm({ name: '', relationship: '', email: '', phone: '' });
      setShowAddContact(false);
      toast.success('Emergency contact added');
    } catch {
      toast.error('Failed to add emergency contact');
    } finally {
      setIsAddingContact(false);
    }
  }, [contactForm]);

  const handleRemoveContact = React.useCallback(async (contactId: string) => {
    try {
      await userApi.deleteEmergencyContact(contactId);
      setEmergencyContacts((prev) => prev.filter((c) => c.id !== contactId));
      toast.success('Contact removed');
    } catch {
      toast.error('Failed to remove contact');
    }
  }, []);

  const handleDeleteAccount = React.useCallback(async () => {
    setIsDeletingAccount(true);
    try {
      await userApi.deleteAccount();
      toast.success('Account deleted');
      await logout();
    } catch {
      toast.error('Failed to delete account');
      setIsDeletingAccount(false);
    }
  }, [logout]);

  const isDark = theme === 'dark';
  const displayName = user?.displayName || user?.firstName || 'User';
  const userEmail = user?.email || '';
  const userDid = user?.did || 'No DID configured';
  const userCreatedAt = (user as unknown as Record<string, string>)?.createdAt || new Date().toISOString();

  const SettingRow = ({
    icon: Icon,
    title,
    description,
    action,
    onClick,
  }: {
    icon: React.ComponentType<{ className?: string }>;
    title: string;
    description?: string;
    action?: React.ReactNode;
    onClick?: () => void;
  }) => (
    <div
      className={cn(
        'flex items-center gap-4 p-4 -mx-4 rounded-lg transition-colors',
        onClick && 'cursor-pointer hover:bg-muted/50'
      )}
      onClick={onClick}
    >
      <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center flex-shrink-0">
        <Icon className="w-5 h-5 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-medium text-foreground">{title}</div>
        {description && (
          <div className="text-sm text-muted-foreground truncate">{description}</div>
        )}
      </div>
      {action || (onClick && <ChevronRight className="w-5 h-5 text-muted-foreground" />)}
    </div>
  );

  return (
    <ProtectedRoute>
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-4xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <Link
              href="/wallet"
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="hidden sm:inline">Back to Wallet</span>
            </Link>
            <h1 className="font-semibold text-foreground">Settings</h1>
            <div className="w-32" />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="space-y-6"
        >
          {/* Profile Section */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <User className="w-5 h-5" />
                Profile
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                  <span className="text-2xl font-semibold text-primary">
                    {displayName.charAt(0)}
                  </span>
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-foreground text-lg">{displayName}</h3>
                  <p className="text-sm text-muted-foreground">{userEmail}</p>
                  <p className="text-xs text-muted-foreground font-mono mt-1 truncate max-w-xs">
                    {userDid}
                  </p>
                </div>
                <PremiumButton
                  variant="outline"
                  size="sm"
                  onClick={() => setShowProfileEdit(true)}
                >
                  <Pencil className="w-4 h-4 mr-1" />
                  Edit
                </PremiumButton>
              </div>
              
              <div className="pt-4 border-t border-border">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Member since</span>
                  <span className="text-foreground">
                    {new Date(userCreatedAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </CardContent>
          </PremiumCard>

          {/* Profile Edit Dialog */}
          <Dialog open={showProfileEdit} onOpenChange={setShowProfileEdit}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Edit Profile</DialogTitle>
                <DialogDescription>Update your personal information</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-sm font-medium text-foreground">First name</label>
                    <Input
                      value={profileForm.firstName}
                      onChange={(e) => setProfileForm((p) => ({ ...p, firstName: e.target.value }))}
                      placeholder="First name"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm font-medium text-foreground">Last name</label>
                    <Input
                      value={profileForm.lastName}
                      onChange={(e) => setProfileForm((p) => ({ ...p, lastName: e.target.value }))}
                      placeholder="Last name"
                    />
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Display name</label>
                  <Input
                    value={profileForm.displayName}
                    onChange={(e) => setProfileForm((p) => ({ ...p, displayName: e.target.value }))}
                    placeholder="Display name"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Phone</label>
                  <Input
                    value={profileForm.phone}
                    onChange={(e) => setProfileForm((p) => ({ ...p, phone: e.target.value }))}
                    placeholder="+1 (555) 000-0000"
                    type="tel"
                  />
                </div>
              </div>
              <DialogFooter>
                <PremiumButton variant="outline" onClick={() => setShowProfileEdit(false)}>
                  Cancel
                </PremiumButton>
                <PremiumButton onClick={handleSaveProfile} disabled={isSavingProfile}>
                  {isSavingProfile ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                  Save Changes
                </PremiumButton>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Security Section */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Security
                {isSavingSecurity && (
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground ml-auto" />
                )}
              </CardTitle>
              <CardDescription>
                Manage authentication methods and security settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <SettingRow
                icon={Key}
                title="Passkey"
                description="FIDO2 WebAuthn credential"
                action={
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">Primary</Badge>
                    <Switch checked={!!user?.walletSetup} disabled />
                  </div>
                }
              />
              <SettingRow
                icon={Fingerprint}
                title="Biometric Authentication"
                description="Face ID or Fingerprint unlock"
                action={
                  <Switch
                    checked={biometricEnabled}
                    onCheckedChange={handleBiometricToggle}
                    disabled={isSavingSecurity}
                  />
                }
              />
              <SettingRow
                icon={Smartphone}
                title="Auto-Lock Timeout"
                description={`Lock wallet after ${autoLockMinutes} minute${autoLockMinutes !== 1 ? 's' : ''} of inactivity`}
                action={
                  <select
                    value={autoLockMinutes}
                    onChange={(e) => handleAutoLockChange(Number(e.target.value))}
                    className="text-sm border rounded px-2 py-1 bg-background text-foreground"
                  >
                    {[1, 2, 5, 10, 15, 30, 60].map((m) => (
                      <option key={m} value={m}>{m} min</option>
                    ))}
                  </select>
                }
              />
              <SettingRow
                icon={Smartphone}
                title="Trusted Devices"
                description="Manage sessions from devices"
                onClick={() => router.push('/wallet/sessions')}
                action={<ChevronRight className="w-5 h-5 text-muted-foreground" />}
              />
            </CardContent>
          </PremiumCard>

          {/* Notifications Section */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Bell className="w-5 h-5" />
                Notifications
                {isSavingNotifications && (
                  <span className="text-xs text-muted-foreground font-normal ml-auto">Saving…</span>
                )}
              </CardTitle>
              <CardDescription>
                Choose what notifications you receive
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { key: 'credentialReceived' as const, label: 'Credential Received', desc: 'When you receive a new credential' },
                { key: 'verificationRequest' as const, label: 'Verification Requests', desc: 'When someone requests to verify your credentials' },
                { key: 'consentExpiring' as const, label: 'Expiring Consents', desc: 'Remind me before consents expire' },
                { key: 'securityAlerts' as const, label: 'Security Alerts', desc: 'Important security-related notifications' },
                { key: 'marketing' as const, label: 'Product Updates', desc: 'News and feature announcements' },
              ].map(({ key, label, desc }) => (
                <div key={key} className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-foreground">{label}</div>
                    <div className="text-sm text-muted-foreground">{desc}</div>
                  </div>
                  <Switch
                    checked={notifications[key]}
                    onCheckedChange={(checked) => handleNotificationChange(key, checked)}
                  />
                </div>
              ))}
            </CardContent>
          </PremiumCard>

          {/* Emergency Contacts */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Users className="w-5 h-5" />
                Emergency Contacts
              </CardTitle>
              <CardDescription>
                People who can access your medical information in emergencies
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {isLoadingContacts ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <>
                  {emergencyContacts.map((contact) => (
                    <div
                      key={contact.id}
                      className="flex items-center gap-4 p-4 rounded-lg bg-muted/30"
                    >
                      <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                        <span className="font-medium text-primary">
                          {contact.name.charAt(0)}
                        </span>
                      </div>
                      <div className="flex-1">
                        <div className="font-medium text-foreground">{contact.name}</div>
                        <div className="text-sm text-muted-foreground">{contact.relationship}</div>
                        {contact.canAccess.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {contact.canAccess.map((access) => (
                              <Badge key={access} variant="secondary" className="text-xs">
                                {access}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      <button
                        onClick={() => handleRemoveContact(contact.id)}
                        className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                        title="Remove contact"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))}

                  <PremiumButton
                    variant="outline"
                    fullWidth
                    onClick={() => setShowAddContact(true)}
                  >
                    <Plus className="w-4 h-4 mr-2" />
                    Add Emergency Contact
                  </PremiumButton>
                </>
              )}
            </CardContent>
          </PremiumCard>

          {/* Add Emergency Contact Dialog */}
          <Dialog open={showAddContact} onOpenChange={setShowAddContact}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Emergency Contact</DialogTitle>
                <DialogDescription>
                  Add someone who can access your medical information in an emergency
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Full name *</label>
                  <Input
                    value={contactForm.name}
                    onChange={(e) => setContactForm((p) => ({ ...p, name: e.target.value }))}
                    placeholder="Jane Doe"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Relationship *</label>
                  <Input
                    value={contactForm.relationship}
                    onChange={(e) => setContactForm((p) => ({ ...p, relationship: e.target.value }))}
                    placeholder="e.g. Spouse, Parent, Doctor"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Email</label>
                  <Input
                    value={contactForm.email}
                    onChange={(e) => setContactForm((p) => ({ ...p, email: e.target.value }))}
                    placeholder="jane@example.com"
                    type="email"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-medium text-foreground">Phone</label>
                  <Input
                    value={contactForm.phone}
                    onChange={(e) => setContactForm((p) => ({ ...p, phone: e.target.value }))}
                    placeholder="+1 (555) 000-0000"
                    type="tel"
                  />
                </div>
              </div>
              <DialogFooter>
                <PremiumButton variant="outline" onClick={() => setShowAddContact(false)}>
                  Cancel
                </PremiumButton>
                <PremiumButton onClick={handleAddEmergencyContact} disabled={isAddingContact}>
                  {isAddingContact ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
                  Add Contact
                </PremiumButton>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Appearance */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                {isDark ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
                Appearance
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {isDark ? (
                    <Moon className="w-5 h-5 text-muted-foreground" />
                  ) : (
                    <Sun className="w-5 h-5 text-muted-foreground" />
                  )}
                  <div>
                    <div className="font-medium text-foreground">Dark Mode</div>
                    <div className="text-sm text-muted-foreground">
                      Use dark theme throughout the app
                    </div>
                  </div>
                </div>
                <Switch
                  checked={isDark}
                  onCheckedChange={(checked) => setTheme(checked ? 'dark' : 'light')}
                />
              </div>
            </CardContent>
          </PremiumCard>

          {/* Data Management */}
          <PremiumCard variant="elevated">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Download className="w-5 h-5" />
                Data Management
              </CardTitle>
              <CardDescription>
                Export or delete your data
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <SettingRow
                icon={Download}
                title="Export Wallet Backup"
                description="Download wallet profile backup (JSON, unencrypted — store securely)"
                onClick={async () => {
                  try {
                    const res = await userApi.getProfile();
                    if (res.data) {
                      // FINDING-016: Export is plaintext JSON. Label corrected to avoid misleading users.
                      // Future: encrypt with user-supplied passphrase before download.
                      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `wallet-backup-${new Date().toISOString().slice(0, 10)}.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                      toast.success('Backup downloaded — keep this file private');
                    }
                  } catch {
                    toast.error('Failed to export backup');
                  }
                }}
              />
              
              <div className="pt-4 border-t border-border">
                <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                  <DialogTrigger
                    render={
                      <PremiumButton variant="destructive" fullWidth>
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete Account
                      </PremiumButton>
                    }
                  />
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle className="flex items-center gap-2 text-red-500">
                        <AlertTriangle className="w-5 h-5" />
                        Delete Account
                      </DialogTitle>
                      <DialogDescription>
                        This action cannot be undone. This will permanently delete your
                        account, credentials, and all associated data.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="py-4">
                      <p className="text-sm text-muted-foreground">
                        Make sure you have exported your wallet backup before proceeding.
                        Once deleted, your credentials cannot be recovered.
                      </p>
                    </div>
                    <DialogFooter>
                      <PremiumButton
                        variant="outline"
                        onClick={() => setShowDeleteDialog(false)}
                        disabled={isDeletingAccount}
                      >
                        Cancel
                      </PremiumButton>
                      <PremiumButton
                        variant="destructive"
                        onClick={handleDeleteAccount}
                        disabled={isDeletingAccount}
                      >
                        {isDeletingAccount ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                        Delete Permanently
                      </PremiumButton>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </div>
            </CardContent>
          </PremiumCard>

          {/* App Info */}
          <div className="text-center text-sm text-muted-foreground pt-8">
            <p>SSI Healthcare Wallet v1.0.0</p>
            <p className="mt-1">
              <Link href="/privacy" className="hover:underline">Privacy Policy</Link>
              {' | '}
              <Link href="/terms" className="hover:underline">Terms of Service</Link>
            </p>
          </div>
        </motion.div>
      </main>
    </div>
    </ProtectedRoute>
  );
}

