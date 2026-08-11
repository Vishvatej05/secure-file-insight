import { RISK_STYLES, riskLevel } from "@/lib/risk-ui";

export function RiskBadge({ level, score, className = "" }: { level: string; score?: number; className?: string }) {
  const key = riskLevel(level);
  const style = RISK_STYLES[key];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-xs font-medium ${style.bg} ${style.text} ${style.border} ${className}`}
    >
      <span aria-hidden>{style.icon}</span>
      {key}
      {typeof score === "number" ? <span className="opacity-70">{score}/100</span> : null}
    </span>
  );
}

export function SeverityTag({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-critical/20 text-critical border-critical/50",
    high: "bg-high/15 text-high border-high/45",
    medium: "bg-medium/15 text-medium border-medium/40",
    low: "bg-low/15 text-low border-low/40",
    info: "bg-muted text-muted-foreground border-border",
  };
  return (
    <span className={`inline-flex rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${map[severity] ?? map["info"]}`}>
      {severity}
    </span>
  );
}
