import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { ShieldAlert, LayoutDashboard, Upload, Siren, History, LogOut, Radar } from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/upload", label: "Upload & Analyze", icon: Upload },
  { to: "/alerts", label: "Security Alerts", icon: Siren },
  { to: "/history", label: "History", icon: History },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);
  const [email, setEmail] = useState<string | null>(null);
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  useEffect(() => {
    const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
      setEmail(session?.user.email ?? null);
      if (!session) navigate({ to: "/auth" });
    });
    supabase.auth.getSession().then(({ data }) => {
      setEmail(data.session?.user.email ?? null);
      setReady(true);
      if (!data.session) navigate({ to: "/auth" });
    });
    return () => sub.subscription.unsubscribe();
  }, [navigate]);

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="scan-pulse font-mono text-sm text-muted-foreground">Initialising secure console…</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen lg:flex">
      <aside className="border-b border-border bg-surface/60 lg:h-screen lg:w-64 lg:shrink-0 lg:border-r lg:border-b-0">
        <div className="flex items-center gap-2 px-5 py-5">
          <Radar className="size-5 text-primary" aria-hidden />
          <div>
            <p className="font-mono text-sm font-semibold tracking-tight">FileForensics AI</p>
            <p className="text-[11px] text-muted-foreground">Static analysis console</p>
          </div>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:overflow-visible">
          {NAV.map((item) => {
            const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors ${
                  active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                }`}
              >
                <item.icon className="size-4" aria-hidden />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="hidden px-4 pb-4 lg:block">
          <div className="panel p-3 text-[11px] leading-relaxed text-muted-foreground">
            <ShieldAlert className="mb-1 size-4 text-medium" aria-hidden />
            Uploads are analysed statically in your browser. Files are never executed, opened or rendered.
          </div>
        </div>
        <div className="hidden px-4 pb-6 lg:block">
          <p className="truncate font-mono text-[11px] text-muted-foreground">{email}</p>
          <Button
            variant="ghost"
            size="sm"
            className="mt-1 h-8 px-2 text-xs"
            onClick={async () => {
              await supabase.auth.signOut();
              navigate({ to: "/auth" });
            }}
          >
            <LogOut className="size-3.5" aria-hidden /> Sign out
          </Button>
        </div>
      </aside>
      <main className="grid-lines min-w-0 flex-1">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">{children}</div>
      </main>
    </div>
  );
}
