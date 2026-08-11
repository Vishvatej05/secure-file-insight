import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useRef, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import { analyzeFile, MAX_UPLOAD_BYTES, STAGE_LABELS, type PipelineStage } from "@/lib/forensics/pipeline";
import { generateFileSummary } from "@/lib/ai.functions";
import { toast } from "sonner";
import { UploadCloud, ShieldCheck } from "lucide-react";

export const Route = createFileRoute("/upload")({
  head: () => ({
    meta: [
      { title: "Upload & Analyze — FileForensics AI" },
      { name: "description", content: "Drop any file to detect its real type from magic bytes, run a static security scan, extract content and generate an AI report." },
      { property: "og:title", content: "Upload & Analyze — FileForensics AI" },
      { property: "og:description", content: "Static, sandbox-safe file analysis with AI summaries." },
    ],
  }),
  component: UploadPage,
});

const STAGES: PipelineStage[] = ["upload", "detect", "security", "extract", "ai", "done"];

function UploadPage() {
  const navigate = useNavigate();
  const [stage, setStage] = useState<PipelineStage | null>(null);
  const [current, setCurrent] = useState<string>("");
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const process = useCallback(
    async (file: File) => {
      if (file.size > MAX_UPLOAD_BYTES) {
        toast.error("File exceeds the 50 MB analysis limit.");
        return;
      }
      setCurrent(file.name);
      try {
        const report = await analyzeFile(file, setStage);
        const { data: session } = await supabase.auth.getUser();
        const userId = session.user?.id;
        if (!userId) throw new Error("Session expired. Please sign in again.");

        const { data: duplicate } = await supabase
          .from("files")
          .select("id")
          .eq("sha256", report.hashes.sha256)
          .limit(1)
          .maybeSingle();
        if (duplicate) toast.info("Duplicate detected — the same SHA-256 was analysed before.");

        const { data: inserted, error } = await supabase
          .from("files")
          .insert({
            user_id: userId,
            original_name: report.fileName,
            size: report.size,
            sha256: report.hashes.sha256,
            sha1: report.hashes.sha1,
            md5: report.hashes.md5,
            declared_extension: report.declaredExtension,
            detected_type: report.detection.type,
            detected_label: report.detection.label,
            mime_type: report.detection.mime,
            category: report.detection.category,
            confidence: report.detection.confidence,
            extension_match: report.extensionMatch,
            recommended_extension: report.recommendedExtension,
            entropy: report.binary.entropy,
            risk_score: report.risk.score,
            risk_level: report.risk.level,
            status: report.risk.scanComplete ? "complete" : "scan_incomplete",
          })
          .select("id")
          .single();
        if (error) throw error;

        await supabase.from("security_findings").insert(
          report.risk.findings.map((finding) => ({
            file_id: inserted.id,
            category: finding.category,
            severity: finding.severity,
            description: finding.description,
            evidence: finding.evidence ?? null,
            recommendation: finding.recommendation ?? null,
            points: finding.points,
          })),
        );

        await supabase.from("analyses").insert({
          file_id: inserted.id,
          extracted_content: {
            text: report.extraction.text,
            truncated: report.extraction.truncated,
            tables: report.extraction.tables,
            children: report.extraction.children ?? [],
            notes: report.extraction.notes,
            unsupported: report.extraction.unsupported ?? false,
            error: report.extraction.error ?? null,
          },
          metadata: {
            stats: report.extraction.stats,
            metadata: report.extraction.metadata,
            evidence: report.detection.evidence,
            headerHex: report.binary.headerHex,
            printableRatio: report.binary.printableRatio,
          },
        });

        setStage("ai");
        try {
          const summary = await generateFileSummary({
            data: {
              fileName: report.fileName,
              detectedType: report.detection.label,
              extensionMatch: report.extensionMatch,
              riskLevel: report.risk.level,
              riskScore: report.risk.score,
              findings: report.risk.findings.map((finding) => ({ severity: finding.severity, description: finding.description })),
              stats: JSON.stringify(report.extraction.stats).slice(0, 2000),
              metadata: JSON.stringify(report.extraction.metadata).slice(0, 4000),
              content: report.extraction.text.slice(0, 40000),
              notes: report.extraction.notes.slice(0, 20),
            },
          });
          await supabase.from("analyses").update({ summary }).eq("file_id", inserted.id);
        } catch (aiError) {
          toast.warning(aiError instanceof Error ? aiError.message : "AI analysis failed — the forensic report is still available.");
        }

        setStage("done");
        navigate({ to: "/files/$id", params: { id: inserted.id } });
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "Analysis failed");
        setStage(null);
      }
    },
    [navigate],
  );

  const activeIndex = stage ? STAGES.indexOf(stage) : -1;

  return (
    <AppShell>
      <h1 className="font-mono text-2xl font-semibold tracking-tight">Upload & Analyze</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        Files are parsed statically in your browser. Nothing is executed, opened or rendered — only bytes are inspected.
      </p>

      <div
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const file = event.dataTransfer.files[0];
          if (file) void process(file);
        }}
        className={`panel mt-6 flex flex-col items-center justify-center gap-3 border-dashed p-12 text-center transition-colors ${
          dragging ? "border-primary bg-primary/5" : ""
        }`}
      >
        <UploadCloud className="size-8 text-primary" aria-hidden />
        <p className="font-mono text-sm">Drag & drop a file here</p>
        <p className="text-xs text-muted-foreground">Any format · up to 50 MB · correct, missing or wrong extension</p>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void process(file);
            event.target.value = "";
          }}
        />
        <Button variant="outline" onClick={() => inputRef.current?.click()} disabled={stage !== null && stage !== "done"}>
          Choose file
        </Button>
      </div>

      {stage && (
        <div className="panel mt-4 p-5">
          <p className="mb-3 font-mono text-sm">Analyzing <span className="text-primary">{current}</span></p>
          <ol className="space-y-2">
            {STAGES.map((item, index) => {
              const done = index < activeIndex || stage === "done";
              const active = index === activeIndex && stage !== "done";
              return (
                <li key={item} className="flex items-center gap-2 font-mono text-sm">
                  <span className={done ? "text-safe" : active ? "text-primary scan-pulse" : "text-muted-foreground"} aria-hidden>
                    {done ? "✓" : active ? "▸" : "•"}
                  </span>
                  <span className={done ? "text-foreground" : active ? "text-foreground" : "text-muted-foreground"}>
                    {STAGE_LABELS[item]}
                  </span>
                </li>
              );
            })}
          </ol>
        </div>
      )}

      <div className="panel mt-4 flex items-start gap-3 p-4 text-xs text-muted-foreground">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-safe" aria-hidden />
        <p>
          Limits enforced: 50 MB per file, 2,000 archive entries, 4 MB per decompressed entry, 40 deep-inspected entries and
          decompression-ratio checks to prevent archive bombs.
        </p>
      </div>
    </AppShell>
  );
}
