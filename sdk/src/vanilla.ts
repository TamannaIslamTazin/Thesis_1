/**
 * SSI Healthcare SDK - Vanilla JavaScript API
 *
 * Zero-dependency wrapper for using the SSI SDK without React.
 * Provides a simple, event-driven API for any JavaScript application.
 *
 * @example Browser (ES Module)
 * ```html
 * <script type="module">
 *   import { createSSI } from '@ssi-healthcare/sdk/vanilla';
 *
 *   const ssi = createSSI({
 *     apiUrl: 'https://api.ssi-healthcare.com',
 *     clientId: 'your-app-id',
 *   });
 *
 *   // Handle auth state changes
 *   ssi.onAuthChange((state) => {
 *     if (state.isAuthenticated) {
 *       console.log('User logged in:', state.identity);
 *     }
 *   });
 *
 *   // Login button
 *   document.getElementById('login-btn').onclick = () => ssi.login();
 * </script>
 * ```
 *
 * @example Browser (UMD)
 * ```html
 * <script src="https://unpkg.com/@ssi-healthcare/sdk/dist/vanilla.umd.js"></script>
 * <script>
 *   const ssi = SSIHealthcare.createSSI({ apiUrl: '...', clientId: '...' });
 * </script>
 * ```
 *
 * @example Node.js
 * ```javascript
 * const { createSSI } = require('@ssi-healthcare/sdk/vanilla');
 *
 * const ssi = createSSI({
 *   apiUrl: 'https://api.ssi-healthcare.com',
 *   clientId: 'your-app-id',
 * });
 *
 * await ssi.login({ provider: 'email', email: 'user@example.com' });
 * const credentials = await ssi.getCredentials();
 * ```
 */

import { SSIClient } from './core/client';
import type {
  SSIClientConfig,
  AuthState,
  Credential,
  Consent,
  PresentationRequest,
  DisclosureSelection,
  Identity,
} from './types';
// Wallet-held credentials use the shared envelope (metadata + signed VC).
import type { WalletCredential } from '@ssi-healthcare/shared';

/**
 * Vanilla JS SSI instance interface
 */
export interface VanillaSSI {
  /** Get current auth state */
  getAuthState(): AuthState;

  /** Check if user is authenticated */
  isAuthenticated(): boolean;

  /** Get current identity (if authenticated) */
  getIdentity(): Identity | undefined;

  /** Login with SSI */
  login(options?: {
    provider?: 'google' | 'apple' | 'microsoft' | 'email';
    email?: string;
    method?: 'popup' | 'redirect';
  }): Promise<AuthState>;

  /** Logout */
  logout(): Promise<void>;

  /** Handle OAuth callback (for redirect flow) */
  handleCallback(params?: URLSearchParams): Promise<AuthState>;

  /** Get all credentials */
  getCredentials(options?: { page?: number; limit?: number }): Promise<{
    items: WalletCredential[];
    total: number;
    hasMore: boolean;
  }>;

  /** Get a specific credential */
  getCredential(id: string): Promise<WalletCredential | null>;

  /** Delete a credential */
  deleteCredential(id: string): Promise<void>;

  /** Get all consents */
  getConsents(options?: { active?: boolean }): Promise<{
    items: Consent[];
    total: number;
  }>;

  /** Revoke a consent */
  revokeConsent(id: string): Promise<void>;

  /** Present credentials */
  presentCredentials(
    request: PresentationRequest,
    selections: DisclosureSelection[]
  ): Promise<void>;

  /** Subscribe to auth state changes */
  onAuthChange(callback: (state: AuthState) => void): () => void;

  /** Subscribe to credential events */
  onCredentialChange(
    callback: (event: 'received' | 'deleted', credential?: Credential) => void
  ): () => void;

  /** Subscribe to consent events */
  onConsentChange(
    callback: (event: 'granted' | 'revoked', consent?: Consent) => void
  ): () => void;

  /** Subscribe to errors */
  onError(callback: (error: Error) => void): () => void;

  /** Get the underlying SSIClient (for advanced use) */
  getClient(): SSIClient;

  /** Destroy the instance and cleanup */
  destroy(): void;
}

/**
 * Create a vanilla JS SSI instance
 *
 * @param config - SSI client configuration
 * @returns VanillaSSI instance
 *
 * @example
 * ```javascript
 * const ssi = createSSI({
 *   apiUrl: 'https://api.ssi-healthcare.com',
 *   clientId: 'my-app',
 *   redirectUri: 'https://myapp.com/callback',
 * });
 *
 * // Subscribe to auth changes
 * const unsubscribe = ssi.onAuthChange((state) => {
 *   updateUI(state);
 * });
 *
 * // Login
 * await ssi.login({ provider: 'google' });
 *
 * // Get credentials
 * const { items: credentials } = await ssi.getCredentials();
 *
 * // Cleanup when done
 * unsubscribe();
 * ssi.destroy();
 * ```
 */
export function createSSI(config: SSIClientConfig): VanillaSSI {
  const client = new SSIClient(config);
  const subscriptions: Array<() => void> = [];

  // Track auth state locally for sync access
  let currentAuthState = client.getAuthState();

  // Subscribe to auth events to keep local state in sync
  const authSub = client.on('auth:login', () => {
    currentAuthState = client.getAuthState();
  });
  subscriptions.push(authSub);

  const logoutSub = client.on('auth:logout', () => {
    currentAuthState = client.getAuthState();
  });
  subscriptions.push(logoutSub);

  return {
    getAuthState() {
      return client.getAuthState();
    },

    isAuthenticated() {
      return client.isAuthenticated();
    },

    getIdentity() {
      return currentAuthState.identity;
    },

    async login(options) {
      const state = await client.authenticate(options);
      currentAuthState = state;
      return state;
    },

    async logout() {
      await client.logout();
      currentAuthState = client.getAuthState();
    },

    async handleCallback(params) {
      const state = await client.handleCallback(params);
      currentAuthState = state;
      return state;
    },

    async getCredentials(options) {
      const response = await client.getCredentials({
        page: options?.page,
        limit: options?.limit,
      });
      const total = response.stats?.total ?? response.credentials.length;
      const pageSize = options?.limit ?? 20;
      const currentPage = options?.page ?? 1;
      return {
        items: response.credentials,
        total,
        hasMore: currentPage * pageSize < total,
      };
    },

    async getCredential(id) {
      return client.getCredential(id);
    },

    async deleteCredential(id) {
      await client.deleteCredential(id);
    },

    async getConsents(options) {
      const response = await client.getConsents({
        active: options?.active,
      });
      return {
        items: response.consents,
        total: response.stats?.total ?? response.consents.length,
      };
    },

    async revokeConsent(id) {
      await client.revokeConsent(id);
    },

    async presentCredentials(request, selections) {
      await client.presentCredentials(request, selections);
    },

    onAuthChange(callback) {
      // Emit current state immediately
      callback(client.getAuthState());

      // Subscribe to changes
      const loginUnsub = client.on('auth:login', () => {
        callback(client.getAuthState());
      });
      const logoutUnsub = client.on('auth:logout', () => {
        callback(client.getAuthState());
      });

      const unsubscribe = () => {
        loginUnsub();
        logoutUnsub();
        // Remove self from subscriptions array to prevent memory leaks
        const index = subscriptions.indexOf(unsubscribe);
        if (index > -1) {
          subscriptions.splice(index, 1);
        }
      };

      subscriptions.push(unsubscribe);
      return unsubscribe;
    },

    onCredentialChange(callback) {
      const receivedUnsub = client.on('credential:received', (event) => {
        const payload = event.payload as { credential?: Credential };
        callback('received', payload.credential);
      });
      const deletedUnsub = client.on('credential:deleted', (event) => {
        const payload = event.payload as { credential?: Credential };
        callback('deleted', payload.credential);
      });

      const unsubscribe = () => {
        receivedUnsub();
        deletedUnsub();
        // Remove self from subscriptions array
        const index = subscriptions.indexOf(unsubscribe);
        if (index > -1) {
          subscriptions.splice(index, 1);
        }
      };

      subscriptions.push(unsubscribe);
      return unsubscribe;
    },

    onConsentChange(callback) {
      const grantedUnsub = client.on('consent:granted', (event) => {
        const payload = event.payload as { consent?: Consent };
        callback('granted', payload.consent);
      });
      const revokedUnsub = client.on('consent:revoked', (event) => {
        const payload = event.payload as { consent?: Consent };
        callback('revoked', payload.consent);
      });

      const unsubscribe = () => {
        grantedUnsub();
        revokedUnsub();
        // Remove self from subscriptions array
        const index = subscriptions.indexOf(unsubscribe);
        if (index > -1) {
          subscriptions.splice(index, 1);
        }
      };

      subscriptions.push(unsubscribe);
      return unsubscribe;
    },

    onError(callback) {
      const clientUnsub = client.on('error', (event) => {
        const payload = event.payload as { error: Error };
        callback(payload.error);
      });

      const unsubscribe = () => {
        clientUnsub();
        // Remove self from subscriptions array
        const index = subscriptions.indexOf(unsubscribe);
        if (index > -1) {
          subscriptions.splice(index, 1);
        }
      };

      subscriptions.push(unsubscribe);
      return unsubscribe;
    },

    getClient() {
      return client;
    },

    destroy() {
      // Cleanup all subscriptions
      subscriptions.forEach((unsub) => unsub());
      subscriptions.length = 0;
    },
  };
}

/**
 * SSI Sign-In Button - Web Component
 *
 * A standalone web component for easy integration without any framework.
 *
 * @example
 * ```html
 * <ssi-sign-in-button
 *   client-id="your-app-id"
 *   api-url="https://api.ssi-healthcare.com"
 *   redirect-uri="https://yourapp.com/callback"
 *   login-text="Sign in with SSI"
 *   theme="dark"
 * ></ssi-sign-in-button>
 *
 * <script>
 *   document.querySelector('ssi-sign-in-button')
 *     .addEventListener('ssi-login', (e) => {
 *       console.log('Logged in:', e.detail.identity);
 *     });
 * </script>
 * ```
 */
export class SSISignInButton extends HTMLElement {
  private ssi: VanillaSSI | null = null;
  private button: HTMLButtonElement | null = null;
  private unsubscribe: (() => void) | null = null;
  private boundClickHandler: (() => void) | null = null;

  static get observedAttributes() {
    return [
      'client-id',
      'api-url',
      'redirect-uri',
      'login-text',
      'logout-text',
      'theme',
      'provider',
    ];
  }

  connectedCallback() {
    this.render();
    this.initSSI();
  }

  disconnectedCallback() {
    this.cleanup();
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      // Remove old click handler before re-rendering
      if (this.button && this.boundClickHandler) {
        this.button.removeEventListener('click', this.boundClickHandler);
      }
      this.render();
      this.initSSI();
    }
  }

  private cleanup() {
    // Remove click handler
    if (this.button && this.boundClickHandler) {
      this.button.removeEventListener('click', this.boundClickHandler);
    }
    this.boundClickHandler = null;
    this.button = null;
    this.unsubscribe?.();
    this.ssi?.destroy();
    this.ssi = null;
    this.unsubscribe = null;
  }

  private initSSI() {
    const apiUrl = this.getAttribute('api-url');
    const clientId = this.getAttribute('client-id');

    if (!apiUrl || !clientId) {
      console.warn('SSISignInButton: api-url and client-id are required');
      return;
    }

    this.cleanup();

    this.ssi = createSSI({
      apiUrl,
      clientId,
      redirectUri: this.getAttribute('redirect-uri') || undefined,
    });

    this.unsubscribe = this.ssi.onAuthChange((state) => {
      this.updateButton(state);
    });
  }

  private render() {
    const theme = this.getAttribute('theme') || 'dark';
    const isDark = theme === 'dark';

    const styles = `
      :host {
        display: inline-block;
      }
      .ssi-btn {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 16px;
        font-size: 14px;
        font-weight: 500;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        border-radius: 8px;
        border: none;
        cursor: pointer;
        transition: all 150ms ease;
        background: ${isDark ? '#3b82f6' : '#2563eb'};
        color: white;
      }
      .ssi-btn:hover {
        background: ${isDark ? '#2563eb' : '#1d4ed8'};
      }
      .ssi-btn:disabled {
        opacity: 0.7;
        cursor: not-allowed;
      }
      .ssi-btn--authenticated {
        background: ${isDark ? '#1e293b' : '#f1f5f9'};
        color: ${isDark ? '#e2e8f0' : '#334155'};
        border: 1px solid ${isDark ? '#334155' : '#e2e8f0'};
      }
      .ssi-btn--authenticated:hover {
        background: ${isDark ? '#334155' : '#e2e8f0'};
      }
      .ssi-icon {
        width: 20px;
        height: 20px;
      }
      .ssi-spinner {
        width: 16px;
        height: 16px;
        border: 2px solid transparent;
        border-top-color: currentColor;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    `;

    const loginText = this.getAttribute('login-text') || 'Sign in with SSI';

    // Only attach shadow DOM if it doesn't exist (shadow can only be attached once)
    if (!this.shadowRoot) {
      this.attachShadow({ mode: 'open' });
    }

    this.shadowRoot!.innerHTML = `
      <style>${styles}</style>
      <button class="ssi-btn" type="button">
        <svg class="ssi-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/>
          <path d="M12 6v6l4 2"/>
        </svg>
        <span class="ssi-text">${loginText}</span>
      </button>
    `;

    // Store bound handler for proper cleanup
    this.boundClickHandler = () => this.handleClick();
    this.button = this.shadowRoot!.querySelector('.ssi-btn');
    this.button?.addEventListener('click', this.boundClickHandler);
  }

  private updateButton(state: AuthState) {
    if (!this.button) return;

    const textEl = this.button.querySelector('.ssi-text');
    if (!textEl) return;

    if (state.isLoading) {
      // Use DOM methods instead of innerHTML to avoid XSS risk patterns
      textEl.textContent = '';
      const spinner = document.createElement('span');
      spinner.className = 'ssi-spinner';
      textEl.appendChild(spinner);
      this.button.disabled = true;
    } else if (state.isAuthenticated) {
      const logoutText = this.getAttribute('logout-text') || 'Sign out';
      textEl.textContent = state.identity?.label
        ? `${state.identity.label} · ${logoutText}`
        : logoutText;
      this.button.classList.add('ssi-btn--authenticated');
      this.button.disabled = false;
    } else {
      const loginText = this.getAttribute('login-text') || 'Sign in with SSI';
      textEl.textContent = loginText;
      this.button.classList.remove('ssi-btn--authenticated');
      this.button.disabled = false;
    }
  }

  private async handleClick() {
    if (!this.ssi) return;

    try {
      if (this.ssi.isAuthenticated()) {
        await this.ssi.logout();
        this.dispatchEvent(
          new CustomEvent('ssi-logout', {
            bubbles: true,
            composed: true,
          })
        );
      } else {
        const provider = this.getAttribute('provider') as
          | 'google'
          | 'apple'
          | 'microsoft'
          | 'email'
          | null;

        const state = await this.ssi.login({
          provider: provider || 'email',
        });

        this.dispatchEvent(
          new CustomEvent('ssi-login', {
            bubbles: true,
            composed: true,
            detail: { identity: state.identity },
          })
        );
      }
    } catch (error) {
      this.dispatchEvent(
        new CustomEvent('ssi-error', {
          bubbles: true,
          composed: true,
          detail: { error },
        })
      );
    }
  }
}

// Register web component if in browser
if (typeof customElements !== 'undefined') {
  customElements.define('ssi-sign-in-button', SSISignInButton);
}

// Export for UMD build
export default {
  createSSI,
  SSISignInButton,
};
