import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { RiskBadge } from "@/components/RiskBadge";
import { supabase } from "@/integrations/supabase/client";
import { CATEGORY_ICON, formatBytes } from "@/lib/risk-ui";
import { Button } from "@/components/ui/button";
import { Upload } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "FileForensics AI — File Type & Security Dashboard" },
      {
        name: "description",
        content: "Detect the real type of any file, run static security analysis, extract content and get AI summaries — all in one forensic dashboard.",
      },
      { property: "og:title", content: "FileForensics AI — File Type & Security Dashboard" },
      { property: "og:description", content: "Universal file detection, static security analysis and AI intelligence." },
    ],
  }),
  component: Dashboard,
});

function Stat({ label, value, tone = "" }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="panel p-4">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-1 font-mono text-2xl font-semibold ${tone}`}>{value}</p>
    </div>
  );
}

function Dashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => {
      const { data: files, error } = await supabase
        .from("files")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) throw error;
      return files ?? [];
    },
  });

  const files = data ?? [];
  const count = (level: string) => files.filter((file) => file.risk_level === level).length;
  const typeDistribution = Object.entries(
    files.reduce<Record<string, number>>((acc, file) => {
      acc[file.detected_type] = (acc[file.detected_type] ?? 0) + 1;
      return acc;
    }, {}),
  ).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const alerts = files.filter((file) => ["MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"].includes(file.risk_level)).slice(0, 5);

  return (
    <AppShell>
      <header className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-mono text-2xl font-semibold tracking-tight">Forensics Dashboard</h1>
          <p className="text-sm text-muted-foreground">Detection, security posture and AI intelligence across your analysed files.</p>
        </div>
        <Button asChild>
          <Link to="/upload">
            <Upload className="size-4" aria-hidden /> Analyze a file
          </Link>
        </Button>
      </header>

      {isLoading ? (
        <p className="scan-pulse font-mono text-sm text-muted-foreground">Loading analysis records…</p>
      ) : (
        <>
          <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Stat label="Files analyzed" value={files.length} />
            <Stat label="Safe" value={count("SAFE") + count("LOW")} tone="text-safe" />
            <Stat label="Suspicious" value={count("MEDIUM")} tone="text-medium" />
            <Stat label="High risk" value={count("HIGH")} tone="text-high" />
            <Stat label="Critical" value={count("CRITICAL")} tone="text-critical" />
          </section>

          <section className="mt-6 grid gap-4 lg:grid-cols-2">
            <div className="panel p-4">
              <h2 className="mb-3 font-mono text-sm font-semibold uppercase tracking-wide text-muted-foreground">Security alerts</h2>
              {alerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No suspicious files recorded yet.</p>
              ) : (
                <ul className="space-y-2">
                  {alerts.map((file) => (
                    <li key={file.id}>
                      <Link to="/files/$id" params={{ id: file.id }} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 hover:bg-secondary">
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-sm">{file.original_name}</span>
                          <span className="block truncate text-xs text-muted-foreground">{file.detected_label}</span>
                        </span>
                        <RiskBadge level={file.risk_level} score={file.risk_score} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="panel p-4">
              <h2 className="mb-3 font-mono text-sm font-semibold uppercase tracking-wide text-muted-foreground">File-type distribution</h2>
              {typeDistribution.length === 0 ? (
                <p className="text-sm text-muted-foreground">Nothing analysed yet.</p>
              ) : (
                <ul className="space-y-2">
                  {typeDistribution.map(([type, total]) => (
                    <li key={type} className="flex items-center gap-3">
                      <span className="w-20 shrink-0 font-mono text-xs uppercase">{type}</span>
                      <span className="h-2 flex-1 rounded bg-secondary">
                        <span
                          className="block h-2 rounded bg-primary"
                          style={{ width: `${Math.max(6, (total / files.length) * 100)}%` }}
                        />
                      </span>
                      <span className="w-8 text-right font-mono text-xs text-muted-foreground">{total}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section className="panel mt-4 p-4">
            <h2 className="mb-3 font-mono text-sm font-semibold uppercase tracking-wide text-muted-foreground">Recent analysis</h2>
            {files.length === 0 ? (
              <p className="text-sm text-muted-foreground">Upload a file to produce your first report.</p>
            ) : (
              <ul className="divide-y divide-border">
                {files.slice(0, 8).map((file) => (
                  <li key={file.id}>
                    <Link to="/files/$id" params={{ id: file.id }} className="flex items-center justify-between gap-3 py-2.5 hover:opacity-80">
                      <span className="flex min-w-0 items-center gap-2">
                        <span aria-hidden>{CATEGORY_ICON[file.category] ?? "❔"}</span>
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-sm">{file.original_name}</span>
                          <span className="block text-xs text-muted-foreground">
                            {file.detected_label} · {formatBytes(Number(file.size))}
                            {file.extension_match === false ? " · extension mismatch" : ""}
                          </span>
                        </span>
                      </span>
                      <RiskBadge level={file.risk_level} score={file.risk_score} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </AppShell>
  );
}
