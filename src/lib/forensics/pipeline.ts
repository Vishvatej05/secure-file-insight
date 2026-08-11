// The analysis pipeline: validate -> hash -> detect -> verify extension -> scan -> extract.
import { detectFileType, evaluateExtension, sanitizeFileName } from "./detector";
import { computeBinaryStats, computeHashes } from "./hash";
import { runSecurityScan } from "./security";
import { extractContent } from "./extractors";
import type { AnalysisReport } from "./types";

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

export type PipelineStage = "upload" | "detect" | "security" | "extract" | "ai" | "done";

export const STAGE_LABELS: Record<PipelineStage, string> = {
  upload: "Reading & isolating file",
  detect: "Detecting real file type",
  security: "Static security analysis",
  extract: "Extracting content",
  ai: "AI analysis",
  done: "Complete",
};

export async function analyzeFile(
  file: File,
  onStage?: (stage: PipelineStage) => void,
): Promise<AnalysisReport> {
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new Error(`File exceeds the ${MAX_UPLOAD_BYTES / 1024 / 1024} MB upload limit.`);
  }
  onStage?.("upload");
  const fileName = sanitizeFileName(file.name);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const hashes = await computeHashes(bytes);
  const binary = computeBinaryStats(bytes);

  onStage?.("detect");
  const detection = await detectFileType(bytes, fileName);
  const extension = evaluateExtension(fileName, detection);

  onStage?.("security");
  const risk = await runSecurityScan({
    bytes,
    fileName,
    detection,
    extensionMatch: extension.match,
    binary,
  });

  onStage?.("extract");
  const extraction = await extractContent(bytes, fileName, detection);

  return {
    fileName,
    size: file.size,
    declaredExtension: extension.declared,
    hashes,
    detection,
    extensionMatch: extension.match,
    recommendedExtension: extension.recommended,
    binary,
    risk,
    extraction,
  };
}
