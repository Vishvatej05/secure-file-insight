import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { RiskBadge } from "@/components/RiskBadge";
import { supabase } from "@/integrations/supabase/client";
import { CATEGORY_ICON, formatBytes } from "@/lib/risk-ui";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export const Route = createFileRoute("/history")({
  head: () => ({
    meta: [
      { title: "Analysis History — FileForensics AI" },
      { name: "description", content: "Every file you have analysed, with detected type, extension verification, hashes and risk verdict." },
      { property: "og:title", content: "Analysis History — FileForensics AI" },
      { property: "og:description", content: "Complete history of analysed files and their forensic verdicts." },
    ],
  }),
  component: HistoryPage,
});

function HistoryPage() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["history"],
    queryFn: async () => {
      const { data: files, error } = await supabase.from("files").select("*").order("created_at", { ascending: false }).limit(300);
      if (error) throw error;
      return files ?? [];
    },
  });

  const remove = async (id: string) => {
    const { error } = await supabase.from("files").delete().eq("id", id);
    if (error) toast.error(error.message);
    else {
      toast.success("Record deleted (retention policy: user-controlled).");
      void queryClient.invalidateQueries();
    }
  };

  return (
    <AppShell>
      <h1 className="font-mono text-2xl font-semibold tracking-tight">History</h1>
      <p className="mt-1 text-sm text-muted-foreground">File bytes are never stored — only the analysis record, which you can delete at any time.</p>
      <div className="panel mt-6 divide-y divide-border">
        {isLoading && <p className="scan-pulse p-4 font-mono text-sm text-muted-foreground">Loading history…</p>}
        {!isLoading && !data?.length && <p className="p-4 text-sm text-muted-foreground">No files analysed yet.</p>}
        {data?.map((file) => (
          <div key={file.id} className="flex items-center gap-3 p-3">
            <span aria-hidden>{CATEGORY_ICON[file.category] ?? "❔"}</span>
            <Link to="/files/$id" params={{ id: file.id }} className="min-w-0 flex-1 hover:opacity-80">
              <span className="block truncate font-mono text-sm">{file.original_name}</span>
              <span className="block truncate text-xs text-muted-foreground">
                {file.detected_label} · {formatBytes(Number(file.size))} · {new Date(file.created_at).toLocaleString()}
              </span>
              <span className="block truncate font-mono text-[10px] text-muted-foreground">SHA-256 {file.sha256.slice(0, 32)}…</span>
            </Link>
            <RiskBadge level={file.risk_level} score={file.risk_score} />
            <Button variant="ghost" size="sm" className="text-xs" onClick={() => void remove(file.id)}>
              Delete
            </Button>
          </div>
        ))}
      </div>
    </AppShell>
  );
}
