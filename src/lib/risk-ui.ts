import type { RiskLevel } from "./forensics/types";

export const RISK_STYLES: Record<RiskLevel, { bg: string; text: string; border: string; icon: string; label: string }> = {
  SAFE: { bg: "bg-safe/15", text: "text-safe", border: "border-safe/40", icon: "✓", label: "No indicators" },
  LOW: { bg: "bg-low/15", text: "text-low", border: "border-low/40", icon: "•", label: "Low risk" },
  MEDIUM: { bg: "bg-medium/15", text: "text-medium", border: "border-medium/40", icon: "▲", label: "Medium risk" },
  HIGH: { bg: "bg-high/15", text: "text-high", border: "border-high/45", icon: "⚠", label: "High risk" },
  CRITICAL: { bg: "bg-critical/20", text: "text-critical", border: "border-critical/50", icon: "⛔", label: "Critical" },
  UNKNOWN: { bg: "bg-unknown/15", text: "text-unknown", border: "border-unknown/40", icon: "?", label: "Scan incomplete" },
};

export const CATEGORY_ICON: Record<string, string> = {
  document: "📄",
  data: "📊",
  image: "🖼️",
  audio: "🎵",
  video: "🎬",
  archive: "🗜️",
  binary: "⚙️",
  text: "📝",
  unknown: "❔",
};

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(2)} MB`;
}

export function riskLevel(value: string): RiskLevel {
  return (["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] as RiskLevel[]).includes(value as RiskLevel)
    ? (value as RiskLevel)
    : "UNKNOWN";
}
