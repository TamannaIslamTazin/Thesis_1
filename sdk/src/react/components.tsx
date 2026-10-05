/**
 * SSI Healthcare SDK - React Components
 *
 * Pre-built UI components for quick SSI integration.
 */

import {
  useState,
  useEffect,
  type ReactNode,
  type CSSProperties,
} from 'react';
import { useAuth, useCredentials } from './hooks';
import type { Identity } from '../types';
// Wallet-held credentials use the shared envelope (metadata + signed VC).
import type { WalletCredential } from '@ssi-healthcare/shared';

// ============================================================
// Styles (inline for zero-dependency)
// ============================================================

const baseStyles: Record<string, CSSProperties> = {
  button: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    padding: '0.625rem 1rem',
    fontSize: '0.875rem',
    fontWeight: 500,
    borderRadius: '0.5rem',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 150ms ease',
    fontFamily: 'inherit',
  },
  primaryButton: {
    backgroundColor: '#3b82f6',
    color: 'white',
  },
  secondaryButton: {
    backgroundColor: '#1e293b',
    color: '#e2e8f0',
    border: '1px solid #334155',
  },
  card: {
    backgroundColor: '#1e293b',
    borderRadius: '0.75rem',
    padding: '1rem',
    border: '1px solid #334155',
  },
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '0.25rem 0.5rem',
    fontSize: '0.75rem',
    fontWeight: 500,
    borderRadius: '9999px',
    backgroundColor: '#334155',
    color: '#94a3b8',
  },
  text: {
    color: '#e2e8f0',
    margin: 0,
  },
  mutedText: {
    color: '#94a3b8',
    margin: 0,
  },
};

// ============================================================
// Login Button
// ============================================================

export interface SSILoginButtonProps {
  /** Button text when logged out */
  loginText?: string;
  /** Button text when logged in (shows identity) */
  logoutText?: string;
  /** Provider to use */
  provider?: 'google' | 'apple' | 'microsoft' | 'email';
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Callback after successful login */
  onLogin?: (identity: Identity) => void;
  /** Callback after logout */
  onLogout?: () => void;
  /** Show loading state */
  showLoading?: boolean;
  /** Variant */
  variant?: 'primary' | 'secondary';
}

/**
 * Pre-built login/logout button
 *
 * @example
 * ```tsx
 * <SSILoginButton
 *   loginText="Sign in with SSI"
 *   onLogin={(identity) => console.log('Logged in:', identity)}
 * />
 * ```
 */
export function SSILoginButton({
  loginText = 'Sign in',
  logoutText = 'Sign out',
  provider = 'email',
  style,
  className,
  onLogin,
  onLogout,
  showLoading = true,
  variant = 'primary',
}: SSILoginButtonProps) {
  const { login, logout, isAuthenticated, isLoading, identity } = useAuth();
  const [localLoading, setLocalLoading] = useState(false);

  const handleClick = async () => {
    setLocalLoading(true);
    try {
      if (isAuthenticated) {
        await logout();
        onLogout?.();
      } else {
        // Use the identity returned from login to avoid stale closure reference
        const freshIdentity = await login({ provider });
        if (freshIdentity) {
          onLogin?.(freshIdentity);
        }
      }
    } finally {
      setLocalLoading(false);
    }
  };

  const loading = isLoading || localLoading;
  const buttonStyle: CSSProperties = {
    ...baseStyles.button,
    ...(variant === 'primary' ? baseStyles.primaryButton : baseStyles.secondaryButton),
    ...(loading ? { opacity: 0.7, cursor: 'not-allowed' } : {}),
    ...style,
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      style={buttonStyle}
      className={className}
      type="button"
    >
      {showLoading && loading ? (
        <span>Loading...</span>
      ) : isAuthenticated ? (
        <>
          {identity?.label && <span>{identity.label}</span>}
          <span>{logoutText}</span>
        </>
      ) : (
        <span>{loginText}</span>
      )}
    </button>
  );
}

// ============================================================
// Identity Badge
// ============================================================

export interface SSIIdentityBadgeProps {
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Show DID (truncated) */
  showDid?: boolean;
  /** Click handler */
  onClick?: () => void;
}

/**
 * Badge showing current identity
 */
export function SSIIdentityBadge({
  style,
  className,
  showDid = false,
  onClick,
}: SSIIdentityBadgeProps) {
  const { isAuthenticated, identity } = useAuth();

  if (!isAuthenticated || !identity) {
    return null;
  }

  const did = identity.did ?? '';
  const truncatedDid = did.length > 28
    ? did.slice(0, 20) + '...' + did.slice(-8)
    : did || identity.displayName || identity.email || 'Unknown';

  const badgeStyle: CSSProperties = {
    ...baseStyles.badge,
    cursor: onClick ? 'pointer' : 'default',
    ...style,
  };

  return (
    <button
      onClick={onClick}
      style={badgeStyle}
      className={className}
      type="button"
    >
      <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#22c55e' }} />
      <span>{identity.label ?? 'Anonymous'}</span>
      {showDid && <span style={{ opacity: 0.7 }}>({truncatedDid})</span>}
    </button>
  );
}

// ============================================================
// Credential Card
// ============================================================

export interface SSICredentialCardProps {
  /** Credential to display */
  credential: WalletCredential;
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Click handler */
  onClick?: (credential: WalletCredential) => void;
  /** Show full details */
  expanded?: boolean;
}

/**
 * Card displaying a credential
 */
export function SSICredentialCard({
  credential,
  style,
  className,
  onClick,
  expanded = false,
}: SSICredentialCardProps) {
  // The issuer lives on the VC, not on the wallet envelope. Reading
  // `credential.issuer` here dereferenced a field the server never sent.
  // `issuer` may be a bare DID string or an object per the W3C data model.
  const vcIssuer = credential.credential.issuer;
  const issuerName = typeof vcIssuer === 'string'
    ? vcIssuer
    : vcIssuer.name ?? vcIssuer.id;

  const cardStyle: CSSProperties = {
    ...baseStyles.card,
    cursor: onClick ? 'pointer' : 'default',
    ...style,
  };

  // Prefer the server's lifecycle verdict over a local date comparison: only
  // `status` knows about revocation, which no expiry check can infer.
  const isExpired = credential.status === 'EXPIRED'
    || credential.status === 'REVOKED'
    || credential.status === 'SUSPENDED'
    || (credential.expiresAt ? new Date(credential.expiresAt) < new Date() : false);

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (onClick && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      onClick(credential);
    }
  };

  return (
    <div
      onClick={() => onClick?.(credential)}
      onKeyDown={handleKeyDown}
      style={cardStyle}
      className={className}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      aria-label={`${credential.type.filter((t) => t !== 'VerifiableCredential').join(', ')} credential from ${issuerName}`}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
        <div>
          <p style={{ ...baseStyles.text, fontWeight: 600, fontSize: '1rem' }}>
            {credential.type.filter((t) => t !== 'VerifiableCredential').join(', ')}
          </p>
          <p style={{ ...baseStyles.mutedText, fontSize: '0.875rem' }}>
            Issued by {issuerName}
          </p>
        </div>
        <span
          style={{
            ...baseStyles.badge,
            backgroundColor: isExpired ? '#7f1d1d' : '#14532d',
            color: isExpired ? '#fca5a5' : '#86efac',
          }}
          role="status"
          aria-label={isExpired ? 'Credential expired' : 'Credential valid'}
        >
          {isExpired ? 'Expired' : 'Valid'}
        </span>
      </div>

      {expanded && (
        <div style={{ borderTop: '1px solid #334155', paddingTop: '0.75rem', marginTop: '0.75rem' }}>
          <p style={{ ...baseStyles.mutedText, fontSize: '0.75rem', marginBottom: '0.5rem' }}>
            Attributes
          </p>
          <dl style={{ margin: 0 }}>
            {Object.entries(credential.credential.credentialSubject)
              .filter(([key]) => key !== 'id')
              .map(([key, value]) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <dt style={{ ...baseStyles.mutedText, fontSize: '0.875rem' }}>{key}</dt>
                  <dd style={{ ...baseStyles.text, fontSize: '0.875rem', margin: 0 }}>{String(value)}</dd>
                </div>
              ))}
          </dl>
        </div>
      )}

      <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.75rem' }}>
        <span style={baseStyles.mutedText}>
          Issued: {new Date(credential.issuedAt).toLocaleDateString()}
        </span>
        {credential.expiresAt && (
          <span style={baseStyles.mutedText}>
            Expires: {new Date(credential.expiresAt).toLocaleDateString()}
          </span>
        )}
      </div>
    </div>
  );
}

// ============================================================
// Credential List
// ============================================================

export interface SSICredentialListProps {
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Credential click handler */
  onCredentialClick?: (credential: WalletCredential) => void;
  /** Empty state content */
  emptyContent?: ReactNode;
  /** Show loading skeleton */
  showSkeleton?: boolean;
}

/**
 * List of user's credentials
 */
export function SSICredentialList({
  style,
  className,
  onCredentialClick,
  emptyContent = 'No credentials yet',
  showSkeleton = true,
}: SSICredentialListProps) {
  const { credentials, isLoading, error, refresh } = useCredentials();

  const containerStyle: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
    ...style,
  };

  if (isLoading && showSkeleton) {
    return (
      <div style={containerStyle} className={className}>
        {[1, 2, 3].map((i) => (
          <div
            key={i}
            style={{
              ...baseStyles.card,
              height: '100px',
              animation: 'pulse 2s infinite',
              background: 'linear-gradient(90deg, #1e293b 0%, #334155 50%, #1e293b 100%)',
            }}
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div style={containerStyle} className={className}>
        <div style={{ ...baseStyles.card, textAlign: 'center' }}>
          <p style={{ ...baseStyles.text, color: '#ef4444' }}>Failed to load credentials</p>
          <button
            onClick={refresh}
            style={{ ...baseStyles.button, ...baseStyles.secondaryButton, marginTop: '0.5rem' }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (credentials.length === 0) {
    return (
      <div style={containerStyle} className={className}>
        <div style={{ ...baseStyles.card, textAlign: 'center' }}>
          <p style={baseStyles.mutedText}>{emptyContent}</p>
        </div>
      </div>
    );
  }

  return (
    <div style={containerStyle} className={className}>
      {credentials.map((credential) => (
        <SSICredentialCard
          key={credential.id}
          credential={credential}
          onClick={onCredentialClick}
        />
      ))}
    </div>
  );
}

// ============================================================
// Auth Gate
// ============================================================

export interface SSIAuthGateProps {
  /** Content to show when authenticated */
  children: ReactNode;
  /** Content to show when not authenticated */
  fallback?: ReactNode;
  /** Show loading state */
  showLoading?: boolean;
}

/**
 * Gate component that shows children only when authenticated
 */
export function SSIAuthGate({
  children,
  fallback,
  showLoading = true,
}: SSIAuthGateProps) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading && showLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
        <span style={baseStyles.mutedText}>Loading...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return fallback ? <>{fallback}</> : null;
  }

  return <>{children}</>;
}

// ============================================================
// QR Code Scanner Trigger
// ============================================================

export interface SSIQRScanButtonProps {
  /** Button text */
  text?: string;
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Callback when QR data is scanned */
  onScan?: (data: string) => void;
  /** Variant */
  variant?: 'primary' | 'secondary';
}

/**
 * Button to trigger QR code scanning
 *
 * Note: This is a placeholder that needs to be connected to
 * an actual QR scanner implementation in the consuming app.
 */
export function SSIQRScanButton({
  text = 'Scan QR Code',
  style,
  className,
  onScan,
  variant = 'secondary',
}: SSIQRScanButtonProps) {
  const buttonStyle: CSSProperties = {
    ...baseStyles.button,
    ...(variant === 'primary' ? baseStyles.primaryButton : baseStyles.secondaryButton),
    ...style,
  };

  const handleClick = () => {
    // Emit custom event for QR scan request
    if (typeof window !== 'undefined') {
      const event = new CustomEvent('ssi:qr-scan-request', {
        detail: { onScan },
      });
      window.dispatchEvent(event);
    }
  };

  return (
    <button onClick={handleClick} style={buttonStyle} className={className} type="button">
      {text}
    </button>
  );
}

// ============================================================
// Branded Sign In Button
// ============================================================

export interface SSISignInButtonProps {
  /** Theme variant */
  theme?: 'light' | 'dark' | 'auto';
  /** Size variant */
  size?: 'sm' | 'md' | 'lg';
  /** Full width */
  fullWidth?: boolean;
  /** Show SSI logo */
  showLogo?: boolean;
  /** Custom text */
  text?: string;
  /** Provider hint */
  provider?: 'google' | 'apple' | 'microsoft' | 'email';
  /** Custom styles */
  style?: CSSProperties;
  /** Custom class name */
  className?: string;
  /** Callback after successful login */
  onSuccess?: (identity: Identity) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

const signInButtonSizes = {
  sm: { padding: '0.5rem 0.875rem', fontSize: '0.8125rem', iconSize: 16 },
  md: { padding: '0.625rem 1.125rem', fontSize: '0.875rem', iconSize: 20 },
  lg: { padding: '0.75rem 1.5rem', fontSize: '1rem', iconSize: 24 },
};

/**
 * Branded "Sign in with SSI" button with official styling
 *
 * @example
 * ```tsx
 * <SSISignInButton
 *   theme="dark"
 *   size="lg"
 *   onSuccess={(identity) => {
 *     console.log('Logged in:', identity.label);
 *     router.push('/dashboard');
 *   }}
 *   onError={(err) => showToast(err.message)}
 * />
 * ```
 */
export function SSISignInButton({
  theme = 'auto',
  size = 'md',
  fullWidth = false,
  showLogo = true,
  text = 'Sign in with SSI',
  provider = 'email',
  style,
  className,
  onSuccess,
  onError,
}: SSISignInButtonProps) {
  const { login, isLoading } = useAuth();
  const [localLoading, setLocalLoading] = useState(false);

  // Determine actual theme — use state + effect to avoid SSR hydration mismatch
  const [isDark, setIsDark] = useState(theme === 'dark');
  useEffect(() => {
    if (theme === 'auto' && typeof window !== 'undefined') {
      setIsDark(window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false);
    } else {
      setIsDark(theme === 'dark');
    }
  }, [theme]);

  const sizeConfig = signInButtonSizes[size];

  const handleClick = async () => {
    setLocalLoading(true);
    try {
      // Use the identity returned from login to avoid stale closure reference
      const freshIdentity = await login({ provider });
      if (freshIdentity) {
        onSuccess?.(freshIdentity);
      }
    } catch (error) {
      onError?.(error instanceof Error ? error : new Error('Sign in failed'));
    } finally {
      setLocalLoading(false);
    }
  };

  const loading = isLoading || localLoading;

  const buttonStyle: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    padding: sizeConfig.padding,
    fontSize: sizeConfig.fontSize,
    fontWeight: 600,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
    borderRadius: '0.5rem',
    border: 'none',
    cursor: loading ? 'not-allowed' : 'pointer',
    transition: 'all 150ms ease',
    width: fullWidth ? '100%' : 'auto',
    opacity: loading ? 0.7 : 1,
    // Brand colors
    backgroundColor: isDark ? '#3b82f6' : '#2563eb',
    color: '#ffffff',
    boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)',
    ...style,
  };

  // SSI Logo SVG
  const Logo = () => (
    <svg
      width={sizeConfig.iconSize}
      height={sizeConfig.iconSize}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" />
      <path
        d="M12 6v6l4 2"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="2" fill="currentColor" />
    </svg>
  );

  // Loading spinner
  const Spinner = () => (
    <svg
      width={sizeConfig.iconSize}
      height={sizeConfig.iconSize}
      viewBox="0 0 24 24"
      fill="none"
      style={{
        animation: 'ssi-spin 1s linear infinite',
      }}
    >
      <style>{`@keyframes ssi-spin { to { transform: rotate(360deg); } }`}</style>
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="31.4 31.4"
        strokeLinecap="round"
      />
    </svg>
  );

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      style={buttonStyle}
      className={className}
      type="button"
      aria-label={text}
    >
      {loading ? <Spinner /> : showLogo && <Logo />}
      <span>{loading ? 'Signing in...' : text}</span>
    </button>
  );
}

// ============================================================
// Consent Dialog
// ============================================================

export interface SSIConsentDialogProps {
  /** Whether the dialog is open */
  isOpen: boolean;
  /** Close handler */
  onClose: () => void;
  /** Approve handler */
  onApprove: () => void | Promise<void>;
  /** App requesting consent */
  appName: string;
  /** App logo URL */
  appLogoUrl?: string;
  /** Data types being requested */
  dataTypes: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;
  /** Duration of consent */
  duration?: '30d' | '90d' | '1y' | 'indefinite';
  /** Custom styles */
  style?: CSSProperties;
}

/**
 * Consent dialog for permission requests
 *
 * @example
 * ```tsx
 * <SSIConsentDialog
 *   isOpen={showConsent}
 *   onClose={() => setShowConsent(false)}
 *   onApprove={handleApprove}
 *   appName="City Hospital"
 *   dataTypes={[
 *     { name: 'Name', description: 'Your full legal name', required: true },
 *     { name: 'Date of Birth', description: 'For age verification' },
 *   ]}
 *   duration="90d"
 * />
 * ```
 */
export function SSIConsentDialog({
  isOpen,
  onClose,
  onApprove,
  appName,
  appLogoUrl,
  dataTypes,
  duration = '30d',
  style,
}: SSIConsentDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleApprove = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      await onApprove();
      // Success - dialog should close via parent state
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to grant consent');
    } finally {
      setIsSubmitting(false);
    }
  };

  const durationText = {
    '30d': '30 days',
    '90d': '90 days',
    '1y': '1 year',
    indefinite: 'Until you revoke',
  }[duration];

  const overlayStyle: CSSProperties = {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    padding: '1rem',
  };

  const dialogStyle: CSSProperties = {
    backgroundColor: '#1e293b',
    borderRadius: '1rem',
    padding: '1.5rem',
    maxWidth: '400px',
    width: '100%',
    color: '#e2e8f0',
    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
    ...style,
  };

  const headerStyle: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    marginBottom: '1rem',
  };

  const listStyle: CSSProperties = {
    margin: '1rem 0',
    padding: 0,
    listStyle: 'none',
  };

  const listItemStyle: CSSProperties = {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.5rem',
    padding: '0.5rem 0',
    borderBottom: '1px solid #334155',
  };

  const buttonGroupStyle: CSSProperties = {
    display: 'flex',
    gap: '0.75rem',
    marginTop: '1.5rem',
  };

  return (
    <div style={overlayStyle} onClick={onClose} role="dialog" aria-modal="true">
      <div style={dialogStyle} onClick={(e) => e.stopPropagation()}>
        <div style={headerStyle}>
          {appLogoUrl && (
            <img
              src={appLogoUrl}
              alt={appName}
              style={{ width: 40, height: 40, borderRadius: 8 }}
            />
          )}
          <div>
            <h3 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 600 }}>
              {appName}
            </h3>
            <p style={{ margin: 0, fontSize: '0.875rem', color: '#94a3b8' }}>
              wants to access your information
            </p>
          </div>
        </div>

        <ul style={listStyle}>
          {dataTypes.map((dt) => (
            <li key={dt.name} style={listItemStyle}>
              <span style={{ color: '#22c55e', marginTop: 2 }}>✓</span>
              <div>
                <div style={{ fontWeight: 500 }}>
                  {dt.name}
                  {dt.required && (
                    <span style={{ color: '#f59e0b', marginLeft: 4 }}>*</span>
                  )}
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>
                  {dt.description}
                </div>
              </div>
            </li>
          ))}
        </ul>

        <p
          style={{
            fontSize: '0.8125rem',
            color: '#94a3b8',
            textAlign: 'center',
            margin: '1rem 0',
          }}
        >
          Access will be valid for {durationText}
        </p>

        {error && (
          <p
            style={{
              fontSize: '0.8125rem',
              color: '#ef4444',
              textAlign: 'center',
              margin: '0.5rem 0',
              padding: '0.5rem',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              borderRadius: '0.375rem',
            }}
          >
            {error}
          </p>
        )}

        <div style={buttonGroupStyle}>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            style={{
              ...baseStyles.button,
              ...baseStyles.secondaryButton,
              flex: 1,
              opacity: isSubmitting ? 0.7 : 1,
            }}
            type="button"
          >
            Decline
          </button>
          <button
            onClick={handleApprove}
            disabled={isSubmitting}
            style={{
              ...baseStyles.button,
              ...baseStyles.primaryButton,
              flex: 1,
              opacity: isSubmitting ? 0.7 : 1,
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
            }}
            type="button"
          >
            {isSubmitting ? 'Processing...' : 'Allow'}
          </button>
        </div>
      </div>
    </div>
  );
}
