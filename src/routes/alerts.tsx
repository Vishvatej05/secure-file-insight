import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { RiskBadge } from "@/components/RiskBadge";
import { supabase } from "@/integrations/supabase/client";
import { formatBytes } from "@/lib/risk-ui";

export const Route = createFileRoute("/alerts")({
  head: () => ({
    meta: [
      { title: "Security Alerts — FileForensics AI" },
      { name: "description", content: "Review every suspicious, high-risk, critical or incompletely scanned file detected by the static security engine." },
      { property: "og:title", content: "Security Alerts — FileForensics AI" },
      { property: "og:description", content: "Suspicious and high-risk file alerts from static analysis." },
    ],
  }),
  component: AlertsPage,
});

function AlertsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["alerts"],
    queryFn: async () => {
      const { data: files, error } = await supabase
        .from("files")
        .select("*")
        .in("risk_level", ["MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"])
        .order("risk_score", { ascending: false })
        .limit(200);
      if (error) throw error;
      return files ?? [];
    },
  });

  return (
    <AppShell>
      <h1 className="font-mono text-2xl font-semibold tracking-tight">Security Alerts</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        Files where deterministic rules produced findings. A file marked “scan incomplete” is never treated as safe.
      </p>
      <div className="panel mt-6 divide-y divide-border">
        {isLoading && <p className="scan-pulse p-4 font-mono text-sm text-muted-foreground">Loading alerts…</p>}
        {!isLoading && !data?.length && <p className="p-4 text-sm text-muted-foreground">No alerts. Nothing suspicious has been analysed yet.</p>}
        {data?.map((file) => (
          <Link key={file.id} to="/files/$id" params={{ id: file.id }} className="flex items-center justify-between gap-3 p-4 hover:bg-secondary/50">
            <span className="min-w-0">
              <span className="block truncate font-mono text-sm">{file.original_name}</span>
              <span className="block truncate text-xs text-muted-foreground">
                {file.detected_label} · {formatBytes(Number(file.size))}
                {file.extension_match === false ? ` · claims .${file.declared_extension}, actually ${file.detected_type}` : ""}
              </span>
            </span>
            <RiskBadge level={file.risk_level} score={file.risk_score} />
          </Link>
        ))}
      </div>
    </AppShell>
  );
}
