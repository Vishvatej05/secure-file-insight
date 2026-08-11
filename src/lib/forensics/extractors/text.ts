// Text, delimited data and structured-text extractors.
import { clampText, emptyResult, type Extractor } from "./base";
import type { ExtractedTable } from "../types";

const decoder = new TextDecoder("utf-8", { fatal: false });

function parseDelimited(text: string, delimiter: string) {
  const lines = text.split(/\r?\n/).filter((line) => line.length);
  const rows = lines.slice(0, 5000).map((line) => {
    const cells: string[] = [];
    let current = "";
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i]!;
      if (char === '"') {
        if (quoted && line[i + 1] === '"') {
          current += '"';
          i++;
        } else quoted = !quoted;
      } else if (char === delimiter && !quoted) {
        cells.push(current);
        current = "";
      } else current += char;
    }
    cells.push(current);
    return cells;
  });
  return rows;
}

function inferType(values: string[]): string {
  const nonEmpty = values.filter((value) => value.trim().length);
  if (!nonEmpty.length) return "empty";
  if (nonEmpty.every((value) => /^-?\d+$/.test(value.trim()))) return "integer";
  if (nonEmpty.every((value) => /^-?\d*\.?\d+(e[-+]?\d+)?$/i.test(value.trim()))) return "number";
  if (nonEmpty.every((value) => /^(true|false|yes|no)$/i.test(value.trim()))) return "boolean";
  if (nonEmpty.every((value) => !Number.isNaN(Date.parse(value)) && /\d{4}|\d{1,2}[/-]\d{1,2}/.test(value))) return "date";
  return "text";
}

export const delimitedExtractor: Extractor = {
  name: "delimited",
  supports: (detection) => detection.type === "csv" || detection.type === "tsv",
  extract: async ({ bytes, detection }) => {
    const raw = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 5_000_000)));
    const delimiter = detection.type === "tsv" ? "\t" : raw.split("\n")[0]?.includes(";") ? ";" : ",";
    const rows = parseDelimited(raw, delimiter);
    const header = rows[0] ?? [];
    const body = rows.slice(1);
    const columns = header.map((name, index) => name.trim() || `column_${index + 1}`);

    const profile: string[][] = columns.map((name, index) => {
      const values = body.map((row) => row[index] ?? "");
      const missing = values.filter((value) => !value.trim().length).length;
      const numeric = values.map((value) => Number(value)).filter((value) => Number.isFinite(value));
      const stats =
        numeric.length > body.length * 0.6 && numeric.length
          ? `min ${Math.min(...numeric)} · max ${Math.max(...numeric)} · avg ${(numeric.reduce((a, b) => a + b, 0) / numeric.length).toFixed(2)}`
          : `${new Set(values).size} distinct`;
      return [name, inferType(values), String(missing), stats];
    });

    const preview: ExtractedTable = {
      name: "Data preview",
      columns,
      rows: body.slice(0, 50).map((row) => columns.map((_, index) => row[index] ?? "")),
      truncated: body.length > 50,
    };
    const profileTable: ExtractedTable = {
      name: "Column profile",
      columns: ["Column", "Inferred type", "Missing values", "Statistics"],
      rows: profile,
    };

    const textForAi = [columns.join(" | "), ...body.slice(0, 200).map((row) => row.join(" | "))].join("\n");
    const clamped = clampText(textForAi);
    return emptyResult({
      text: clamped.text,
      truncated: clamped.truncated,
      stats: { Rows: body.length, Columns: columns.length, Delimiter: delimiter === "\t" ? "tab" : delimiter },
      metadata: { Encoding: "UTF-8 (assumed)" },
      tables: [profileTable, preview],
      notes: rows.length >= 5000 ? ["Only the first 5,000 rows were parsed."] : [],
    });
  },
};

export const structuredTextExtractor: Extractor = {
  name: "structured-text",
  supports: (detection) => ["json", "jsonl", "xml", "yaml", "sql", "html", "svg", "markdown", "txt", "script", "rtf"].includes(detection.type),
  extract: async ({ bytes, detection }) => {
    const raw = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 5_000_000)));
    const stats: Record<string, string | number> = {
      Characters: raw.length,
      Lines: raw.split(/\r?\n/).length,
      Words: (raw.match(/\S+/g) ?? []).length,
    };
    const metadata: Record<string, string | number> = {};
    const notes: string[] = [];
    let text = raw;

    if (detection.type === "json" || detection.type === "jsonl") {
      try {
        const value = detection.type === "json" ? JSON.parse(raw) : raw.split(/\r?\n/).filter(Boolean).slice(0, 500).map((line) => JSON.parse(line));
        const describe = (node: unknown, depth = 0): string => {
          if (depth > 4) return "…";
          if (Array.isArray(node)) return `array[${node.length}] of ${node.length ? describe(node[0], depth + 1) : "unknown"}`;
          if (node && typeof node === "object") {
            return `{ ${Object.entries(node as Record<string, unknown>)
              .slice(0, 25)
              .map(([key, val]) => `${key}: ${describe(val, depth + 1)}`)
              .join(", ")} }`;
          }
          return typeof node;
        };
        metadata["Root type"] = Array.isArray(value) ? "array" : typeof value;
        metadata["Schema"] = describe(value);
        if (Array.isArray(value)) stats["Records"] = value.length;
        else stats["Top-level keys"] = Object.keys(value as object).length;
      } catch (error) {
        notes.push(`JSON could not be fully parsed: ${error instanceof Error ? error.message : "invalid syntax"}`);
      }
    }

    if (detection.type === "html" || detection.type === "svg" || detection.type === "xml") {
      const title = raw.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
      if (title?.[1]) metadata["Title"] = title[1].trim();
      const tags = raw.match(/<([a-z][\w:-]*)/gi) ?? [];
      stats["Elements"] = tags.length;
      stats["Links"] = (raw.match(/href\s*=\s*["'][^"']+/gi) ?? []).length;
      if (detection.type !== "svg") {
        text = raw
          .replace(/<script[\s\S]*?<\/script>/gi, " ")
          .replace(/<style[\s\S]*?<\/style>/gi, " ")
          .replace(/<[^>]+>/g, " ")
          .replace(/\s{2,}/g, " ");
      }
    }

    if (detection.type === "rtf") {
      text = raw.replace(/\\'[0-9a-f]{2}/gi, "").replace(/\\[a-z]+-?\d*\s?/gi, " ").replace(/[{}]/g, " ").replace(/\s{2,}/g, " ");
    }

    if (detection.type === "sql") {
      const statements = raw.split(";").filter((part) => part.trim().length);
      stats["Statements"] = statements.length;
      const tables = Array.from(raw.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?["'`\w.]+/gi)).map((match) => match[0]);
      if (tables.length) metadata["Tables created"] = tables.slice(0, 20).join(", ");
    }

    const clamped = clampText(text);
    return emptyResult({ text: clamped.text, truncated: clamped.truncated, stats, metadata, notes });
  },
};
