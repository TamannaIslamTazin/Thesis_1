/**
 * SSI Healthcare - Developer Documentation Page
 *
 * Interactive documentation for SDK integration.
 */

'use client';

import * as React from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import {
  ArrowLeft,
  Code2,
  Terminal,
  Package,
  Layers,
  Zap,
  Shield,
  Copy,
  Check,
  ExternalLink,
  ChevronRight,
  BookOpen,
  Puzzle,
  Webhook,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/premium-card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';

// Code examples
const installCode = `npm install @ssi-healthcare/sdk
# or
pnpm add @ssi-healthcare/sdk`;

const basicUsageCode = `import { SSIClient } from '@ssi-healthcare/sdk';

// Initialize the client
const ssi = new SSIClient({
  apiUrl: 'https://api.ssi-healthcare.com',
  clientId: 'your-app-id',
  redirectUri: 'https://yourapp.com/callback',
});

// Authenticate user (OAuth2-like flow)
await ssi.authenticate({ provider: 'google' });

// Get user's credentials
const { items: credentials } = await ssi.getCredentials();

// Present credentials for verification
await ssi.presentCredentials(request, [
  { credentialId: 'cred-123', attributes: ['name', 'dateOfBirth'] }
]);`;

const reactSetupCode = `import { SSIProvider, useAuth, useCredentials } from '@ssi-healthcare/sdk/react';

function App() {
  return (
    <SSIProvider config={{ 
      apiUrl: 'https://api.ssi-healthcare.com',
      clientId: 'your-app-id' 
    }}>
      <YourApp />
    </SSIProvider>
  );
}

function CredentialList() {
  const { isAuthenticated, login } = useAuth();
  const { credentials, isLoading } = useCredentials();

  if (!isAuthenticated) {
    return (
      <button onClick={() => login({ provider: 'google' })}>
        Sign in with SSI
      </button>
    );
  }

  if (isLoading) return <Spinner />;

  return (
    <ul>
      {credentials.map(cred => (
        <li key={cred.id}>
          {cred.type.join(', ')} - Issued by {cred.issuer}
        </li>
      ))}
    </ul>
  );
}`;

const presenterCode = `import { usePresentation } from '@ssi-healthcare/sdk/react';

function VerificationHandler({ qrData }) {
  const { 
    request, 
    matchingCredentials, 
    submit, 
    isSubmitting 
  } = usePresentation(qrData);

  const [selected, setSelected] = useState<DisclosureSelection[]>([]);

  return (
    <div>
      <h2>{request?.purpose}</h2>
      
      {matchingCredentials.map(({ credential, matchedAttributes }) => (
        <CredentialSelector
          key={credential.id}
          credential={credential}
          requestedAttributes={matchedAttributes}
          onSelect={(selection) => setSelected([...selected, selection])}
        />
      ))}
      
      <button 
        onClick={() => submit(selected)}
        disabled={isSubmitting || selected.length === 0}
      >
        {isSubmitting ? 'Sharing...' : 'Share Credentials'}
      </button>
    </div>
  );
}`;

function CodeBlock({ code, language = 'typescript' }: { code: string; language?: string }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      <pre className="bg-background border border-border rounded-lg p-4 overflow-x-auto text-sm">
        <code className="text-foreground/80">{code}</code>
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-2 rounded-md bg-muted/80 text-muted-foreground hover:text-foreground opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  );
}

const features = [
  {
    icon: Zap,
    title: 'OAuth2-like API',
    description: 'Familiar authentication patterns. If you know OAuth2, you already know SSI SDK.',
  },
  {
    icon: Shield,
    title: 'Zero Knowledge Ready',
    description: 'Built-in support for selective disclosure and ZK proofs.',
  },
  {
    icon: Layers,
    title: 'Framework Agnostic',
    description: 'Works with any JavaScript framework. React bindings included.',
  },
  {
    icon: Package,
    title: 'Tree Shakeable',
    description: 'Import only what you need. Minimal bundle size impact.',
  },
];

const apiEndpoints = [
  { method: 'POST', path: '/auth/authorize', description: 'Start authentication flow' },
  { method: 'POST', path: '/auth/token', description: 'Exchange code for token' },
  { method: 'GET', path: '/credentials', description: 'List user credentials' },
  { method: 'POST', path: '/credentials/accept', description: 'Accept credential offer' },
  { method: 'POST', path: '/presentations/submit', description: 'Submit presentation' },
  { method: 'GET', path: '/consents', description: 'List active consents' },
  { method: 'POST', path: '/consents/:id/revoke', description: 'Revoke consent' },
  { method: 'POST', path: '/verify/credential', description: 'Verify credential' },
];

export default function DevelopersPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <Link
              href="/"
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="hidden sm:inline">Back</span>
            </Link>
            <div className="flex items-center gap-2">
              <Code2 className="w-5 h-5 text-primary" />
              <span className="font-semibold text-foreground">Developer Docs</span>
            </div>
            <div className="flex items-center gap-2">
              <PremiumButton variant="outline" size="sm">
                API Reference
              </PremiumButton>
              <PremiumButton variant="premium" size="sm">
                Get Started
              </PremiumButton>
            </div>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative py-20 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 to-transparent" />
        <div className="relative max-w-6xl mx-auto px-4 sm:px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center max-w-3xl mx-auto"
          >
            <Badge variant="secondary" className="mb-4">
              v0.1.0
            </Badge>
            <h1 className="text-4xl sm:text-5xl font-bold text-foreground mb-6">
              SSI SDK
            </h1>
            <p className="text-xl text-muted-foreground mb-8">
              Integrate Self-Sovereign Identity into your application in minutes.
              OAuth2-like API. TypeScript-first. Framework agnostic.
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <PremiumButton variant="premium" size="lg">
                <Terminal className="w-5 h-5 mr-2" />
                Quick Start
              </PremiumButton>
              <PremiumButton variant="outline" size="lg">
                <BookOpen className="w-5 h-5 mr-2" />
                Full Documentation
              </PremiumButton>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features */}
      <section className="py-16 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <PremiumCard variant="elevated" className="h-full">
                  <CardContent className="pt-6">
                    <feature.icon className="w-10 h-10 text-primary mb-4" />
                    <h3 className="font-semibold text-foreground mb-2">{feature.title}</h3>
                    <p className="text-sm text-muted-foreground">{feature.description}</p>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Installation */}
      <section className="py-16 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="max-w-3xl">
            <h2 className="text-2xl font-bold text-foreground mb-4">Installation</h2>
            <p className="text-muted-foreground mb-6">
              Install the SDK using your preferred package manager.
            </p>
            <CodeBlock code={installCode} language="bash" />
          </div>
        </div>
      </section>

      {/* Code Examples */}
      <section className="py-16 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <h2 className="text-2xl font-bold text-foreground mb-8">Examples</h2>
          
          <Tabs defaultValue="basic" className="space-y-6">
            <TabsList>
              <TabsTrigger value="basic">Basic Usage</TabsTrigger>
              <TabsTrigger value="react">React Setup</TabsTrigger>
              <TabsTrigger value="presentation">Presentations</TabsTrigger>
            </TabsList>
            
            <TabsContent value="basic">
              <PremiumCard variant="elevated">
                <CardHeader>
                  <CardTitle>Basic Client Usage</CardTitle>
                  <CardDescription>
                    Initialize the client and authenticate users with familiar OAuth2-like patterns.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <CodeBlock code={basicUsageCode} />
                </CardContent>
              </PremiumCard>
            </TabsContent>
            
            <TabsContent value="react">
              <PremiumCard variant="elevated">
                <CardHeader>
                  <CardTitle>React Integration</CardTitle>
                  <CardDescription>
                    Use the React provider and hooks for seamless state management.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <CodeBlock code={reactSetupCode} />
                </CardContent>
              </PremiumCard>
            </TabsContent>
            
            <TabsContent value="presentation">
              <PremiumCard variant="elevated">
                <CardHeader>
                  <CardTitle>Credential Presentations</CardTitle>
                  <CardDescription>
                    Handle verification requests with the usePresentation hook.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <CodeBlock code={presenterCode} />
                </CardContent>
              </PremiumCard>
            </TabsContent>
          </Tabs>
        </div>
      </section>

      {/* API Reference */}
      <section className="py-16 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <h2 className="text-2xl font-bold text-foreground mb-8">API Endpoints</h2>
          
          <PremiumCard variant="elevated">
            <CardContent className="pt-6">
              <div className="space-y-4">
                {apiEndpoints.map((endpoint) => (
                  <div
                    key={endpoint.path}
                    className="flex items-center gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <Badge
                      variant="secondary"
                      className={cn(
                        'font-mono text-xs min-w-[60px] justify-center',
                        endpoint.method === 'POST' && 'bg-emerald-500/20 text-emerald-400',
                        endpoint.method === 'GET' && 'bg-blue-500/20 text-blue-400'
                      )}
                    >
                      {endpoint.method}
                    </Badge>
                    <code className="text-sm font-mono text-foreground flex-1">
                      {endpoint.path}
                    </code>
                    <span className="text-sm text-muted-foreground hidden sm:block">
                      {endpoint.description}
                    </span>
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                ))}
              </div>
            </CardContent>
          </PremiumCard>
        </div>
      </section>

      {/* Hooks Reference */}
      <section className="py-16 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <h2 className="text-2xl font-bold text-foreground mb-8">React Hooks</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[
              { name: 'useAuth', description: 'Authentication state and methods' },
              { name: 'useCredentials', description: 'List and manage credentials' },
              { name: 'useCredential', description: 'Single credential operations' },
              { name: 'usePresentation', description: 'Handle presentation requests' },
              { name: 'useConsents', description: 'Manage data sharing consents' },
              { name: 'useCredentialOffer', description: 'Accept credential offers' },
            ].map((hook) => (
              <PremiumCard key={hook.name} variant="interactive">
                <CardContent className="pt-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <code className="text-primary font-semibold">{hook.name}()</code>
                      <p className="text-sm text-muted-foreground mt-1">{hook.description}</p>
                    </div>
                    <ChevronRight className="w-5 h-5 text-muted-foreground" />
                  </div>
                </CardContent>
              </PremiumCard>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 text-center">
          <h2 className="text-3xl font-bold text-foreground mb-4">
            Ready to integrate SSI?
          </h2>
          <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
            Join developers building the future of decentralized identity.
            Get started in minutes with our comprehensive SDK.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <PremiumButton variant="premium" size="lg">
              Start Building
            </PremiumButton>
            <PremiumButton variant="outline" size="lg">
              <ExternalLink className="w-4 h-4 mr-2" />
              GitHub Repository
            </PremiumButton>
          </div>
        </div>
      </section>
    </div>
  );
}
