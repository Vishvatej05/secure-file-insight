// PDF extractor: static parsing only (object scan + FlateDecode inflate).
import { clampText, emptyResult, type Extractor } from "./base";
import { inflateRaw } from "../zip";

const decoder = new TextDecoder("latin1" as string, { fatal: false });

function decodePdfString(value: string): string {
  return value.replace(/\\([nrtbf()\\])/g, (_, ch: string) => ({ n: "\n", r: "\r", t: "\t", b: "", f: "" }[ch] ?? ch));
}

function extractTextOperators(content: string): string {
  let out = "";
  const showText = /\((?:\\.|[^\\()])*\)\s*Tj|\[(?:[^\[\]]|\\.)*\]\s*TJ|\((?:\\.|[^\\()])*\)\s*'/g;
  const matches = content.match(showText) ?? [];
  for (const match of matches) {
    const strings = match.match(/\((?:\\.|[^\\()])*\)/g) ?? [];
    out += strings.map((str) => decodePdfString(str.slice(1, -1))).join("");
    out += match.trim().endsWith("TJ") || match.trim().endsWith("Tj") ? "\n" : " ";
  }
  return out;
}

export const pdfExtractor: Extractor = {
  name: "pdf",
  supports: (detection) => detection.type === "pdf",
  extract: async ({ bytes }) => {
    const raw = decoder.decode(bytes);
    const notes: string[] = [];
    const metadata: Record<string, string | number> = {};

    const version = raw.match(/^%PDF-(\d\.\d)/)?.[1];
    if (version) metadata["PDF version"] = version;
    for (const key of ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]) {
      const match = raw.match(new RegExp(`/${key}\\s*\\(((?:\\\\.|[^\\\\()])*)\\)`));
      if (match?.[1]) metadata[key] = decodePdfString(match[1]).slice(0, 300);
    }

    const pageCount = (raw.match(/\/Type\s*\/Page[^s]/g) ?? []).length || (raw.match(/\/Count\s+(\d+)/)?.[1] ? Number(raw.match(/\/Count\s+(\d+)/)![1]) : 0);
    const links = Array.from(raw.matchAll(/\/URI\s*\(([^)]{1,300})\)/g)).map((match) => match[1] ?? "");
    const images = (raw.match(/\/Subtype\s*\/Image/g) ?? []).length;
    const encrypted = /\/Encrypt[\s/<]/.test(raw);

    let text = "";
    if (!encrypted) {
      // Uncompressed content streams
      text += extractTextOperators(raw);
      // FlateDecode streams
      const streamPattern = /\/Filter\s*\/FlateDecode[^>]*>>\s*stream\r?\n/g;
      let match: RegExpExecArray | null;
      let inflatedCount = 0;
      while ((match = streamPattern.exec(raw)) !== null && inflatedCount < 60 && text.length < 200_000) {
        const start = match.index + match[0].length;
        const end = raw.indexOf("endstream", start);
        if (end < 0) break;
        const slice = bytes.subarray(start, end);
        const inflated = (await inflateRaw(slice, "deflate")) ?? (await inflateRaw(slice, "deflate-raw"));
        if (inflated) {
          inflatedCount++;
          text += extractTextOperators(new TextDecoder("latin1" as string).decode(inflated));
        }
      }
      if (!inflatedCount && !text.trim()) {
        notes.push("No text could be recovered — the PDF may be a scan. OCR is not available for PDFs in this build.");
      }
    } else {
      notes.push("PDF is encrypted; text extraction was skipped.");
    }

    const clamped = clampText(text);
    return emptyResult({
      text: clamped.text,
      truncated: clamped.truncated,
      stats: {
        Pages: pageCount || "unknown",
        "Embedded images": images,
        Links: links.length,
        Encrypted: encrypted ? "yes" : "no",
      },
      metadata,
      tables: links.length
        ? [{ name: "Links", columns: ["URL"], rows: links.slice(0, 40).map((url) => [url]), truncated: links.length > 40 }]
        : [],
      notes,
      unsupported: encrypted,
    });
  },
};
