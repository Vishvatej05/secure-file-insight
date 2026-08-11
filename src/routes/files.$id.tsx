import { createFileRoute, useParams } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { AppShell } from "@/components/AppShell";
import { RiskBadge, SeverityTag } from "@/components/RiskBadge";
import { supabase } from "@/integrations/supabase/client";
import { formatBytes } from "@/lib/risk-ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { askFileQuestion } from "@/lib/ai.functions";
import { toast } from "sonner";

export const Route = createFileRoute("/files/$id")({
  head: () => ({
    meta: [
      { title: "Analysis Report — FileForensics AI" },
      { name: "description", content: "Full forensic report: real file type, extension verification, hashes, security findings, extracted content and AI analysis." },
      { property: "og:title", content: "Analysis Report — FileForensics AI" },
      { property: "og:description", content: "Detected type, risk verdict, extracted content and AI summary for an analysed file." },
    ],
  }),
  component: ReportPage,
});

type Summary = {
  oneLiner?: string;
  detailed?: string;
  keyPoints?: string[];
  entities?: string[];
  dates?: string[];
  numbers?: string[];
  topics?: string[];
  actionItems?: string[];
  securityExplanation?: string;
};

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2 border-b border-border py-2 last:border-0">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="max-w-[70%] break-all text-right font-mono text-sm">{value}</span>
    </div>
  );
}

function List({ title, items }: { title: string; items?: string[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <p className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">{title}</p>
      <ul className="list-inside list-disc space-y-0.5 text-sm">
        {items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function ReportPage() {
  const { id } = useParams({ from: "/files/$id" });
  const queryClient = useQueryClient();
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["file", id],
    queryFn: async () => {
      const [file, findings, analysis, chat] = await Promise.all([
        supabase.from("files").select("*").eq("id", id).single(),
        supabase.from("security_findings").select("*").eq("file_id", id).order("points", { ascending: false }),
        supabase.from("analyses").select("*").eq("file_id", id).maybeSingle(),
        supabase.from("chat_messages").select("*").eq("file_id", id).order("created_at"),
      ]);
      if (file.error) throw file.error;
      return { file: file.data, findings: findings.data ?? [], analysis: analysis.data, chat: chat.data ?? [] };
    },
  });

  if (isLoading || !data) {
    return (
      <AppShell>
        <p className="scan-pulse font-mono text-sm text-muted-foreground">Loading report…</p>
      </AppShell>
    );
  }

  const { file, findings, analysis, chat } = data;
  const content = (analysis?.extracted_content ?? {}) as {
    text?: string;
    truncated?: boolean;
    tables?: Array<{ name: string; columns: string[]; rows: string[][]; truncated?: boolean }>;
    notes?: string[];
    children?: Array<{ name: string; size: number; detected: string; risk: string }>;
    unsupported?: boolean;
  };
  const meta = (analysis?.metadata ?? {}) as {
    stats?: Record<string, string | number>;
    metadata?: Record<string, string | number>;
    evidence?: string[];
    headerHex?: string;
  };
  const summary = (analysis?.summary ?? null) as Summary | null;
  const dangerous = ["HIGH", "CRITICAL"].includes(file.risk_level);

  const ask = async () => {
    if (!question.trim()) return;
    setAsking(true);
    const asked = question.trim();
    setQuestion("");
    try {
      await supabase.from("chat_messages").insert({ file_id: id, role: "user", content: asked });
      const answer = await askFileQuestion({
        data: {
          fileName: file.original_name,
          detectedType: file.detected_label,
          riskSummary: `${file.risk_level} (${file.risk_score}/100): ${findings.map((finding) => finding.description).join("; ")}`,
          content: (content.text ?? "").slice(0, 40000),
          question: asked,
          history: chat.slice(-10).map((message) => ({ role: message.role as "user" | "assistant", content: message.content })),
        },
      });
      await supabase.from("chat_messages").insert({ file_id: id, role: "assistant", content: answer });
      void queryClient.invalidateQueries({ queryKey: ["file", id] });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "AI request failed");
    } finally {
      setAsking(false);
    }
  };

  return (
    <AppShell>
      {dangerous && (
        <div className="panel mb-5 border-critical/50 bg-critical/10 p-4">
          <p className="font-mono text-sm font-semibold text-critical">⚠ SECURITY WARNING — {file.risk_level} RISK FILE DETECTED</p>
          <p className="mt-1 text-sm">
            {file.original_name} · detected as {file.detected_label} · score {file.risk_score}/100
          </p>
          <ul className="mt-2 list-inside list-disc text-sm">
            {findings.filter((finding) => ["high", "critical"].includes(finding.severity)).slice(0, 5).map((finding) => (
              <li key={finding.id}>{finding.description}</li>
            ))}
          </ul>
        </div>
      )}
      {file.status === "scan_incomplete" && (
        <div className="panel mb-5 border-unknown/50 bg-unknown/10 p-3 font-mono text-sm">SECURITY STATUS: SCAN INCOMPLETE — do not assume this file is safe.</div>
      )}

      <header className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="truncate font-mono text-xl font-semibold">{file.original_name}</h1>
          <p className="text-sm text-muted-foreground">
            {file.detected_label} · {formatBytes(Number(file.size))} · {new Date(file.created_at).toLocaleString()}
          </p>
        </div>
        <RiskBadge level={file.risk_level} score={file.risk_score} />
      </header>

      <Tabs defaultValue="overview">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="content">Content</TabsTrigger>
          <TabsTrigger value="ai">AI analysis</TabsTrigger>
          <TabsTrigger value="chat">Ask the file</TabsTrigger>
          <TabsTrigger value="technical">Technical</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="panel p-4">
            <Row label="Filename" value={file.original_name} />
            <Row label="Size" value={formatBytes(Number(file.size))} />
            <Row label="Declared extension" value={file.declared_extension ? `.${file.declared_extension}` : "none"} />
            <Row label="Actual file type" value={`${file.detected_label} (${file.detected_type})`} />
            <Row label="MIME type" value={file.mime_type ?? "unknown"} />
            <Row label="Confidence" value={`${file.confidence}%`} />
            <Row
              label="Extension match"
              value={
                file.extension_match === null ? (
                  <span className="text-low">no extension — content-based detection</span>
                ) : file.extension_match ? (
                  <span className="text-safe">✓ YES</span>
                ) : (
                  <span className="text-high">✕ NO — recommended .{file.recommended_extension}</span>
                )
              }
            />
            <Row label="SHA-256" value={file.sha256} />
            <Row label="SHA-1" value={file.sha1 ?? "-"} />
            <Row label="MD5 (reference only)" value={file.md5 ?? "-"} />
            <Row label="Entropy" value={`${file.entropy ?? "-"} bits/byte`} />
          </div>
        </TabsContent>

        <TabsContent value="security">
          <div className="panel space-y-3 p-4">
            <p className="text-sm text-muted-foreground">
              Detected facts from the deterministic rule engine. Score is the capped sum of rule weights — the AI cannot change it.
            </p>
            {findings.map((finding) => (
              <div key={finding.id} className="rounded-md border border-border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityTag severity={finding.severity} />
                  <span className="text-xs uppercase tracking-wide text-muted-foreground">{finding.category}</span>
                  <span className="ml-auto font-mono text-xs text-muted-foreground">+{finding.points}</span>
                </div>
                <p className="mt-1.5 text-sm">{finding.description}</p>
                {finding.evidence && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">Evidence: {finding.evidence}</p>}
                {finding.recommendation && <p className="mt-1 text-xs text-medium">Recommended: {finding.recommendation}</p>}
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="content">
          <div className="panel space-y-4 p-4">
            {meta.stats && Object.keys(meta.stats).length > 0 && (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {Object.entries(meta.stats).map(([key, value]) => (
                  <div key={key} className="rounded border border-border p-2">
                    <p className="text-[11px] uppercase text-muted-foreground">{key}</p>
                    <p className="font-mono text-sm">{String(value)}</p>
                  </div>
                ))}
              </div>
            )}
            {content.notes?.map((note, index) => (
              <p key={index} className="text-xs text-medium">ℹ {note}</p>
            ))}
            {content.tables?.map((table) => (
              <div key={table.name} className="overflow-x-auto rounded border border-border">
                <p className="border-b border-border px-3 py-2 font-mono text-xs uppercase text-muted-foreground">{table.name}</p>
                <table className="w-full text-left text-xs">
                  <thead className="bg-secondary/50">
                    <tr>
                      {table.columns.map((column, index) => (
                        <th key={index} className="px-3 py-1.5 font-mono">{column}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {table.rows.slice(0, 30).map((row, rowIndex) => (
                      <tr key={rowIndex} className="border-t border-border">
                        {row.map((cell, cellIndex) => (
                          <td key={cellIndex} className="px-3 py-1.5">{cell}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {content.text ? (
              <pre className="max-h-96 overflow-auto rounded border border-border bg-secondary/30 p-3 font-mono text-xs whitespace-pre-wrap">
                {content.text}
                {content.truncated ? "\n\n… truncated" : ""}
              </pre>
            ) : (
              <p className="text-sm text-muted-foreground">No readable text could be extracted from this format.</p>
            )}
          </div>
        </TabsContent>

        <TabsContent value="ai">
          <div className="panel space-y-4 p-4">
            {!summary ? (
              <p className="text-sm text-muted-foreground">AI analysis is not available for this file.</p>
            ) : (
              <>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">AI interpretation — not a detected fact</p>
                {summary.oneLiner && <p className="font-mono text-base">{summary.oneLiner}</p>}
                {summary.detailed && <p className="text-sm leading-relaxed">{summary.detailed}</p>}
                <List title="Key points" items={summary.keyPoints} />
                <List title="Entities" items={summary.entities} />
                <List title="Important dates" items={summary.dates} />
                <List title="Important numbers" items={summary.numbers} />
                <List title="Topics" items={summary.topics} />
                <List title="Action items" items={summary.actionItems} />
                {summary.securityExplanation && (
                  <div className="rounded border border-border p-3">
                    <p className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">AI explanation of the security verdict</p>
                    <p className="text-sm">{summary.securityExplanation}</p>
                  </div>
                )}
              </>
            )}
          </div>
        </TabsContent>

        <TabsContent value="chat">
          <div className="panel space-y-3 p-4">
            {chat.length === 0 && <p className="text-sm text-muted-foreground">Ask anything about this file. Answers are grounded in the extracted content only.</p>}
            {chat.map((message) => (
              <div key={message.id} className={`rounded-md border border-border p-3 text-sm ${message.role === "user" ? "bg-secondary/40" : ""}`}>
                <p className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">{message.role === "user" ? "You" : "AI"}</p>
                <p className="whitespace-pre-wrap">{message.content}</p>
              </div>
            ))}
            <div className="flex gap-2">
              <Input
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !asking) void ask();
                }}
                placeholder="What is this file about?"
                maxLength={2000}
              />
              <Button onClick={() => void ask()} disabled={asking || !question.trim()}>
                {asking ? "Thinking…" : "Ask"}
              </Button>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="technical">
          <div className="panel space-y-3 p-4">
            <div>
              <p className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">Detection evidence</p>
              <ul className="list-inside list-disc font-mono text-xs">
                {(meta.evidence ?? []).map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
            <Row label="Header bytes" value={meta.headerHex ?? "-"} />
            {meta.metadata && Object.entries(meta.metadata).map(([key, value]) => <Row key={key} label={key} value={String(value)} />)}
          </div>
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}
