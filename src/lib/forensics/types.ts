// Shared types for the FileForensics analysis pipeline.

export type FileCategory =
  | "document"
  | "data"
  | "image"
  | "audio"
  | "video"
  | "archive"
  | "binary"
  | "text"
  | "unknown";

export type RiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface DetectionResult {
  /** canonical short type id, e.g. "pdf" */
  type: string;
  /** human friendly label, e.g. "Portable Document Format" */
  label: string;
  mime: string;
  category: FileCategory;
  /** canonical extension without dot */
  extension: string;
  confidence: number;
  /** how the type was established */
  evidence: string[];
  container?: string | undefined;
}

export interface SecurityFinding {
  category: string;
  severity: Severity;
  description: string;
  evidence?: string | undefined;
  recommendation?: string | undefined;
  points: number;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  findings: SecurityFinding[];
  scanComplete: boolean;
}

export interface ExtractedTable {
  name: string;
  columns: string[];
  rows: string[][];
  truncated?: boolean | undefined;
}

export interface ExtractionResult {
  /** plain readable text, may be truncated */
  text: string;
  truncated: boolean;
  /** counters shown in the report: pages, rows, sheets, entries... */
  stats: Record<string, string | number>;
  metadata: Record<string, string | number>;
  tables: ExtractedTable[];
  /** nested files (archives) */
  children?: Array<{
    name: string;
    size: number;
    detected: string;
    risk: string;
    note?: string | undefined;
  }> | undefined;
  notes: string[];
  /** set when the format is recognised but cannot be safely parsed */
  unsupported?: boolean | undefined;
  error?: string | undefined;
}

export interface Hashes {
  sha256: string;
  sha1: string;
  md5: string;
}

export interface BinaryStats {
  entropy: number;
  printableRatio: number;
  nullRatio: number;
  headerHex: string;
}

export interface AnalysisReport {
  fileName: string;
  size: number;
  declaredExtension: string | null;
  hashes: Hashes;
  detection: DetectionResult;
  extensionMatch: boolean | null;
  recommendedExtension: string | null;
  binary: BinaryStats;
  risk: RiskAssessment;
  extraction: ExtractionResult;
}

export const RISK_ORDER: RiskLevel[] = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"];
