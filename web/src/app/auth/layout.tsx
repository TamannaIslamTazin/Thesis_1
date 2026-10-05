/**
 * SSI Healthcare - Auth Layout
 * 
 * Minimal layout for authentication pages — no sidebar, no nav.
 */

export default function AuthLayout({
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
