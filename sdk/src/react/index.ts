/**
 * SSI Healthcare SDK - React Bindings
 *
 * React hooks and components for seamless SSI integration.
 */

// Hooks
export {
  SSIProvider,
  useAuth,
  useCredentials,
  useCredential,
  usePresentation,
  useConsents,
  useCredentialOffer,
  useSSIClient,
} from './hooks';

// Components
export {
  SSILoginButton,
  SSISignInButton,
  SSIIdentityBadge,
  SSICredentialCard,
  SSICredentialList,
  SSIAuthGate,
  SSIQRScanButton,
  SSIConsentDialog,
  type SSILoginButtonProps,
  type SSISignInButtonProps,
  type SSIIdentityBadgeProps,
  type SSICredentialCardProps,
  type SSICredentialListProps,
  type SSIAuthGateProps,
  type SSIQRScanButtonProps,
  type SSIConsentDialogProps,
} from './components';
