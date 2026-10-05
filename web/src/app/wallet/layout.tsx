/**
 * SSI Healthcare - Wallet Layout
 * 
 * Clean layout for user wallet pages — no admin sidebar.
 */

export default function WalletLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background">
      {children}
    </div>
  );
}
