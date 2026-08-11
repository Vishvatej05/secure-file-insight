// Multi-layer file type detection: extension -> magic bytes -> structure -> container refinement.
import { EXTENSION_MAP, matchSignatures } from "./signatures";
import type { DetectionResult, FileCategory } from "./types";
import { readZipDirectory, type ZipEntry } from "./zip";

const decoder = new TextDecoder("utf-8", { fatal: false });

export function getExtension(name: string): string | null {
  const clean = name.trim().replace(/\\/g, "/").split("/").pop() ?? name;
  const idx = clean.lastIndexOf(".");
  if (idx <= 0 || idx === clean.length - 1) return null;
  return clean.slice(idx + 1).toLowerCase();
}

export function sanitizeFileName(name: string): string {
  return (name.replace(/\\/g, "/").split("/").pop() ?? "file")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 255) || "file";
}

function makeResult(
  type: string,
  label: string,
  mime: string,
  category: FileCategory,
  extension: string,
  confidence: number,
  evidence: string[],
  container?: string,
): DetectionResult {
  return { type, label, mime, category, extension, confidence, evidence, container };
}

const TEXT_PROBES: Array<{
  test: (text: string) => boolean;
  result: [string, string, string, FileCategory, string];
  confidence: number;
}> = [
  {
    test: (t) => /^\s*<\?xml/i.test(t) && /<svg[\s>]/i.test(t),
    result: ["svg", "Scalable Vector Graphics", "image/svg+xml", "image", "svg"],
    confidence: 96,
  },
  { test: (t) => /^\s*<svg[\s>]/i.test(t), result: ["svg", "Scalable Vector Graphics", "image/svg+xml", "image", "svg"], confidence: 95 },
  { test: (t) => /^\s*<!doctype html|^\s*<html[\s>]/i.test(t), result: ["html", "HTML Document", "text/html", "document", "html"], confidence: 94 },
  { test: (t) => /^\s*<\?xml/i.test(t), result: ["xml", "XML Document", "application/xml", "data", "xml"], confidence: 93 },
  {
    test: (t) => {
      const trimmed = t.trim();
      if (!/^[[{]/.test(trimmed)) return false;
      try {
        JSON.parse(trimmed);
        return true;
      } catch {
        return false;
      }
    },
    result: ["json", "JSON Document", "application/json", "data", "json"],
    confidence: 98,
  },
  {
    test: (t) => {
      const lines = t.trim().split(/\r?\n/).filter(Boolean).slice(0, 5);
      if (lines.length < 2) return false;
      return lines.every((line) => {
        try {
          JSON.parse(line);
          return true;
        } catch {
          return false;
        }
      });
    },
    result: ["jsonl", "JSON Lines", "application/x-ndjson", "data", "jsonl"],
    confidence: 90,
  },
  {
    test: (t) => /^\s*(--|\/\*)?\s*(select|insert|update|delete|create\s+table|drop\s+table|alter\s+table)\b/i.test(t),
    result: ["sql", "SQL Script", "application/sql", "data", "sql"],
    confidence: 80,
  },
  {
    test: (t) => /^(#!\/|#!\s*\/)/.test(t) || /^\s*(import |from |def |function |const |package |#include)/m.test(t),
    result: ["script", "Source Code / Script", "text/plain", "text", "txt"],
    confidence: 70,
  },
  {
    test: (t) => /^\s*(#|---)/.test(t) && /^[\w."'-]+\s*:\s*\S/m.test(t),
    result: ["yaml", "YAML Document", "application/yaml", "data", "yaml"],
    confidence: 72,
  },
  { test: (t) => /^\s{0,3}#{1,6}\s|\n\s{0,3}#{1,6}\s|\[[^\]]+\]\([^)]+\)/.test(t), result: ["markdown", "Markdown Document", "text/markdown", "document", "md"], confidence: 70 },
];

function detectDelimited(text: string): DetectionResult | null {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length).slice(0, 20);
  if (lines.length < 2) return null;
  for (const [delimiter, type, label, ext, mime] of [
    [",", "csv", "Comma-Separated Values", "csv", "text/csv"],
    ["\t", "tsv", "Tab-Separated Values", "tsv", "text/tab-separated-values"],
    [";", "csv", "Semicolon-Separated Values", "csv", "text/csv"],
  ] as const) {
    const counts = lines.map((line) => line.split(delimiter).length - 1);
    const first = counts[0] ?? 0;
    if (first >= 1 && counts.every((c) => c === first)) {
      return makeResult(type, label, mime, "data", ext, 88, [
        `Consistent ${first + 1}-column delimited structure across ${lines.length} sampled lines`,
      ]);
    }
  }
  return null;
}

const OOXML_MARKERS: Array<[RegExp, string, string, string, FileCategory, string]> = [
  [/^word\//, "docx", "Microsoft Word Document (OOXML)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document", "docx"],
  [/^xl\//, "xlsx", "Microsoft Excel Workbook (OOXML)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "data", "xlsx"],
  [/^ppt\//, "pptx", "Microsoft PowerPoint Presentation (OOXML)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document", "pptx"],
];

async function refineZip(bytes: Uint8Array, entries: ZipEntry[] | null): Promise<DetectionResult> {
  const names = (entries ?? []).map((entry) => entry.name);
  const evidence = [`ZIP container with ${names.length} entries`];

  const mimetypeEntry = entries?.find((entry) => entry.name === "mimetype");
  if (mimetypeEntry && mimetypeEntry.compressedSize < 200) {
    const raw = decoder.decode(bytes.subarray(mimetypeEntry.dataStart, mimetypeEntry.dataStart + mimetypeEntry.compressedSize));
    if (raw.includes("opendocument.text")) return makeResult("odt", "OpenDocument Text", "application/vnd.oasis.opendocument.text", "document", "odt", 99, [...evidence, "OpenDocument mimetype entry"], "zip");
    if (raw.includes("opendocument.spreadsheet")) return makeResult("ods", "OpenDocument Spreadsheet", "application/vnd.oasis.opendocument.spreadsheet", "data", "ods", 99, [...evidence, "OpenDocument mimetype entry"], "zip");
    if (raw.includes("opendocument.presentation")) return makeResult("odp", "OpenDocument Presentation", "application/vnd.oasis.opendocument.presentation", "document", "odp", 99, [...evidence, "OpenDocument mimetype entry"], "zip");
    if (raw.includes("epub")) return makeResult("epub", "EPUB eBook", "application/epub+zip", "document", "epub", 99, [...evidence, "EPUB mimetype entry"], "zip");
  }

  for (const [pattern, type, label, mime, category, ext] of OOXML_MARKERS) {
    if (names.some((name) => pattern.test(name))) {
      return makeResult(type, label, mime, category, ext, 99, [...evidence, `OOXML part matching ${pattern.source}`], "zip");
    }
  }
  if (names.includes("AndroidManifest.xml") && names.some((n) => n.endsWith(".dex"))) {
    return makeResult("apk", "Android Application Package", "application/vnd.android.package-archive", "binary", "apk", 98, [...evidence, "AndroidManifest.xml + classes.dex"], "zip");
  }
  if (names.some((name) => name.startsWith("META-INF/")) && names.some((name) => name.endsWith(".class"))) {
    return makeResult("jar", "Java Archive", "application/java-archive", "binary", "jar", 96, [...evidence, "META-INF manifest + compiled classes"], "zip");
  }
  return makeResult("zip", "ZIP Archive", "application/zip", "archive", "zip", 97, evidence, "zip");
}

function refineOle(bytes: Uint8Array): DetectionResult {
  const window = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 65536)));
  const asUtf16 = window.replace(/\u0000/g, "");
  const evidence = ["OLE2 compound-file header (D0 CF 11 E0)"];
  if (/Workbook|Microsoft Excel/i.test(asUtf16)) return makeResult("xls", "Microsoft Excel 97-2003 Workbook", "application/vnd.ms-excel", "data", "xls", 92, [...evidence, "Workbook stream found"], "ole2");
  if (/PowerPoint Document/i.test(asUtf16)) return makeResult("ppt", "Microsoft PowerPoint 97-2003", "application/vnd.ms-powerpoint", "document", "ppt", 92, [...evidence, "PowerPoint Document stream"], "ole2");
  if (/WordDocument/i.test(asUtf16)) return makeResult("doc", "Microsoft Word 97-2003 Document", "application/msword", "document", "doc", 92, [...evidence, "WordDocument stream"], "ole2");
  return makeResult("ole", "Legacy Microsoft Office / OLE2 Compound File", "application/x-ole-storage", "document", "doc", 80, [...evidence, "Specific stream not identified"], "ole2");
}

function looksTextual(bytes: Uint8Array): boolean {
  const sample = bytes.subarray(0, Math.min(bytes.length, 8192));
  if (!sample.length) return false;
  let printable = 0;
  for (let i = 0; i < sample.length; i++) {
    const byte = sample[i]!;
    if (byte === 0) return false;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) || byte >= 128) printable++;
  }
  return printable / sample.length > 0.9;
}

export async function detectFileType(bytes: Uint8Array, fileName: string): Promise<DetectionResult> {
  const extension = getExtension(fileName);
  const hits = matchSignatures(bytes);
  const primary = hits[0];

  if (primary) {
    const evidence = [
      `Magic bytes matched at offset ${primary.offset}: ${primary.bytes
        .map((byte) => (byte === null ? "??" : byte.toString(16).padStart(2, "0").toUpperCase()))
        .join(" ")}`,
    ];

    if (primary.type === "zip") {
      const entries = await readZipDirectory(bytes).catch(() => null);
      const refined = await refineZip(bytes, entries);
      refined.evidence = [...evidence, ...refined.evidence];
      return refined;
    }
    if (primary.type === "ole") {
      const refined = refineOle(bytes);
      refined.evidence = [...evidence, ...refined.evidence];
      return refined;
    }
    if (primary.type === "mp4") {
      const brand = decoder.decode(bytes.subarray(8, 12));
      if (/^M4A/.test(brand)) return makeResult("m4a", "MPEG-4 Audio", "audio/mp4", "audio", "m4a", 96, [...evidence, `ftyp brand: ${brand}`], "iso-bmff");
      if (/^qt/.test(brand)) return makeResult("mov", "QuickTime Movie", "video/quicktime", "video", "mov", 96, [...evidence, `ftyp brand: ${brand}`], "iso-bmff");
      if (/heic|heif|mif1/.test(brand)) return makeResult("heic", "HEIC Image", "image/heic", "image", "heic", 96, [...evidence, `ftyp brand: ${brand}`], "iso-bmff");
      return makeResult("mp4", "MPEG-4 Video", "video/mp4", "video", "mp4", 96, [...evidence, `ftyp brand: ${brand}`], "iso-bmff");
    }
    if (primary.type === "pe") {
      const peOffset = bytes.length > 0x40 ? new DataView(bytes.buffer, bytes.byteOffset).getUint32(0x3c, true) : 0;
      const isPe =
        peOffset + 4 < bytes.length &&
        bytes[peOffset] === 0x50 &&
        bytes[peOffset + 1] === 0x45;
      return makeResult(
        "pe",
        isPe ? "Windows Executable / Library (PE)" : "DOS MZ Executable",
        "application/vnd.microsoft.portable-executable",
        "binary",
        "exe",
        isPe ? 99 : 75,
        [...evidence, isPe ? `PE signature located at 0x${peOffset.toString(16)}` : "PE header not found after MZ stub"],
      );
    }

    let confidence = 90 + Math.min(9, primary.bytes.length);
    if (primary.type === "bmp" || primary.type === "aac" || primary.type === "mp3") confidence = 82;
    return makeResult(primary.type, primary.label, primary.mime, primary.category, primary.extension, Math.min(confidence, 99.9), evidence);
  }

  // No binary signature: try structured text detection.
  if (looksTextual(bytes)) {
    const text = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 262_144)));
    for (const probe of TEXT_PROBES) {
      if (probe.test(text)) {
        const [type, label, mime, category, ext] = probe.result;
        return makeResult(type, label, mime, category, ext, probe.confidence, ["Textual content matched a structural pattern"]);
      }
    }
    const delimited = detectDelimited(text);
    if (delimited) return delimited;
    return makeResult("txt", "Plain Text", "text/plain", "text", "txt", 70, [
      "No binary signature; content is predominantly printable text",
    ]);
  }

  const guessed = extension ? EXTENSION_MAP[extension] : undefined;
  return makeResult("unknown", "Unknown / Unrecognised Binary", "application/octet-stream", "unknown", extension ?? "", guessed ? 15 : 5, [
    "No magic-byte signature matched",
    "Content is not valid printable text",
    guessed ? `Filename extension suggests "${guessed}" but content does not confirm it` : "No usable filename extension",
  ]);
}

export function evaluateExtension(fileName: string, detection: DetectionResult) {
  const declared = getExtension(fileName);
  if (!declared) {
    return { declared: null, match: null as boolean | null, recommended: detection.extension || null };
  }
  const expected = EXTENSION_MAP[declared];
  const aliases: Record<string, string[]> = {
    jpeg: ["jpg", "jpeg"],
    tiff: ["tif", "tiff"],
    mpeg: ["mpg", "mpeg"],
    yaml: ["yml", "yaml"],
    markdown: ["md", "markdown"],
    mkv: ["mkv", "webm"],
    pe: ["exe", "dll", "sys", "scr", "com"],
    elf: ["elf", "so", "bin", "out"],
    txt: ["txt", "log", "text", "conf", "ini", "cfg"],
    script: ["js", "ts", "py", "sh", "ps1", "bat", "cmd", "vbs", "rb", "go", "java", "c", "cpp"],
    sqlite: ["sqlite", "sqlite3", "db"],
    gz: ["gz", "tgz"],
    zip: ["zip"],
    ole: ["doc", "xls", "ppt", "msg"],
    doc: ["doc"],
    xls: ["xls"],
    ppt: ["ppt"],
  };
  const accepted = aliases[detection.type] ?? [detection.extension];
  const match = expected === detection.type || accepted.includes(declared);
  return {
    declared,
    match,
    recommended: match ? null : detection.extension || null,
  };
}
