// Extractor base contract. New formats register an Extractor in ./index.ts.
import type { DetectionResult, ExtractionResult } from "../types";

export interface ExtractorContext {
  bytes: Uint8Array;
  fileName: string;
  detection: DetectionResult;
}

export interface Extractor {
  name: string;
  supports: (detection: DetectionResult) => boolean;
  extract: (ctx: ExtractorContext) => Promise<ExtractionResult>;
}

export const MAX_TEXT = 60_000;

export function emptyResult(partial: Partial<ExtractionResult> = {}): ExtractionResult {
  return {
    text: "",
    truncated: false,
    stats: {},
    metadata: {},
    tables: [],
    notes: [],
    ...partial,
  };
}

export function clampText(text: string): { text: string; truncated: boolean } {
  const normalized = text.replace(/\u0000/g, "").replace(/[ \t]+\n/g, "\n").trim();
  if (normalized.length <= MAX_TEXT) return { text: normalized, truncated: false };
  return { text: normalized.slice(0, MAX_TEXT), truncated: true };
}

export function stripXmlTags(xml: string): string {
  return xml
    .replace(/<w:p[ >][^>]*>|<w:p>/g, "\n")
    .replace(/<\/w:p>|<\/a:p>|<\/text:p>/g, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n");
}
