"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";

import { AppShell } from "@/components/shell/app-shell";
import { AuthProvider, useAuth } from "@/lib/auth-context";

function AuthGate({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { user, loading } = useAuth();

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/login");
    }
  }, [loading, user, router]);

  if (loading) {
    return (
      <div className="flex h-dvh items-center justify-center bg-bg-base">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent-primary border-t-transparent" />
      </div>
    );
  }

  if (!user) return null;

  return <>{children}</>;
}

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <AuthGate>
        <AppShell>{children}</AppShell>
      </AuthGate>
    </AuthProvider>
  );
}
