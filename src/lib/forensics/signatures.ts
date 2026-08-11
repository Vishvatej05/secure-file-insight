// Magic-byte signature registry. Adding a format = adding an entry here.
import type { FileCategory } from "./types";

export interface Signature {
  type: string;
  label: string;
  mime: string;
  category: FileCategory;
  extension: string;
  offset: number;
  /** byte pattern; null entries are wildcards */
  bytes: Array<number | null>;
  /** higher wins when several signatures match */
  weight?: number;
}

const b = (s: string): Array<number | null> => Array.from(s).map((c) => c.charCodeAt(0));

export const SIGNATURES: Signature[] = [
  // Documents
  { type: "pdf", label: "Portable Document Format", mime: "application/pdf", category: "document", extension: "pdf", offset: 0, bytes: b("%PDF-"), weight: 10 },
  { type: "rtf", label: "Rich Text Format", mime: "application/rtf", category: "document", extension: "rtf", offset: 0, bytes: b("{\\rtf") },
  { type: "ole", label: "Legacy Microsoft Office / OLE2 Compound File", mime: "application/x-ole-storage", category: "document", extension: "doc", offset: 0, bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },
  // Containers (refined later by structural inspection)
  { type: "zip", label: "ZIP Archive", mime: "application/zip", category: "archive", extension: "zip", offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: "zip", label: "ZIP Archive (empty)", mime: "application/zip", category: "archive", extension: "zip", offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
  { type: "zip", label: "ZIP Archive (spanned)", mime: "application/zip", category: "archive", extension: "zip", offset: 0, bytes: [0x50, 0x4b, 0x07, 0x08] },
  { type: "rar", label: "RAR Archive", mime: "application/vnd.rar", category: "archive", extension: "rar", offset: 0, bytes: b("Rar!") },
  { type: "7z", label: "7-Zip Archive", mime: "application/x-7z-compressed", category: "archive", extension: "7z", offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: "gz", label: "GZIP Compressed Data", mime: "application/gzip", category: "archive", extension: "gz", offset: 0, bytes: [0x1f, 0x8b] },
  { type: "bz2", label: "BZIP2 Compressed Data", mime: "application/x-bzip2", category: "archive", extension: "bz2", offset: 0, bytes: b("BZh") },
  { type: "xz", label: "XZ Compressed Data", mime: "application/x-xz", category: "archive", extension: "xz", offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { type: "tar", label: "TAR Archive", mime: "application/x-tar", category: "archive", extension: "tar", offset: 257, bytes: b("ustar") },
  { type: "zstd", label: "Zstandard Compressed Data", mime: "application/zstd", category: "archive", extension: "zst", offset: 0, bytes: [0x28, 0xb5, 0x2f, 0xfd] },

  // Images
  { type: "jpeg", label: "JPEG Image", mime: "image/jpeg", category: "image", extension: "jpg", offset: 0, bytes: [0xff, 0xd8, 0xff] },
  { type: "png", label: "PNG Image", mime: "image/png", category: "image", extension: "png", offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], weight: 10 },
  { type: "gif", label: "GIF Image", mime: "image/gif", category: "image", extension: "gif", offset: 0, bytes: b("GIF8") },
  { type: "bmp", label: "Bitmap Image", mime: "image/bmp", category: "image", extension: "bmp", offset: 0, bytes: b("BM") },
  { type: "tiff", label: "TIFF Image", mime: "image/tiff", category: "image", extension: "tiff", offset: 0, bytes: [0x49, 0x49, 0x2a, 0x00] },
  { type: "tiff", label: "TIFF Image (big endian)", mime: "image/tiff", category: "image", extension: "tiff", offset: 0, bytes: [0x4d, 0x4d, 0x00, 0x2a] },
  { type: "webp", label: "WebP Image", mime: "image/webp", category: "image", extension: "webp", offset: 8, bytes: b("WEBP"), weight: 10 },
  { type: "ico", label: "Windows Icon", mime: "image/x-icon", category: "image", extension: "ico", offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },
  { type: "heic", label: "HEIC Image", mime: "image/heic", category: "image", extension: "heic", offset: 4, bytes: b("ftypheic"), weight: 10 },
  { type: "psd", label: "Photoshop Document", mime: "image/vnd.adobe.photoshop", category: "image", extension: "psd", offset: 0, bytes: b("8BPS") },

  // Audio / video
  { type: "mp3", label: "MP3 Audio", mime: "audio/mpeg", category: "audio", extension: "mp3", offset: 0, bytes: b("ID3") },
  { type: "mp3", label: "MP3 Audio (frame sync)", mime: "audio/mpeg", category: "audio", extension: "mp3", offset: 0, bytes: [0xff, 0xfb] },
  { type: "wav", label: "WAV Audio", mime: "audio/wav", category: "audio", extension: "wav", offset: 8, bytes: b("WAVE"), weight: 10 },
  { type: "flac", label: "FLAC Audio", mime: "audio/flac", category: "audio", extension: "flac", offset: 0, bytes: b("fLaC") },
  { type: "ogg", label: "OGG Container", mime: "audio/ogg", category: "audio", extension: "ogg", offset: 0, bytes: b("OggS") },
  { type: "m4a", label: "MPEG-4 Audio", mime: "audio/mp4", category: "audio", extension: "m4a", offset: 4, bytes: b("ftypM4A"), weight: 12 },
  { type: "aac", label: "AAC Audio (ADTS)", mime: "audio/aac", category: "audio", extension: "aac", offset: 0, bytes: [0xff, 0xf1] },
  { type: "wma", label: "Windows Media (ASF)", mime: "audio/x-ms-wma", category: "audio", extension: "wma", offset: 0, bytes: [0x30, 0x26, 0xb2, 0x75] },
  { type: "mp4", label: "MPEG-4 Video", mime: "video/mp4", category: "video", extension: "mp4", offset: 4, bytes: b("ftyp"), weight: 5 },
  { type: "mkv", label: "Matroska / WebM Container", mime: "video/x-matroska", category: "video", extension: "mkv", offset: 0, bytes: [0x1a, 0x45, 0xdf, 0xa3] },
  { type: "avi", label: "AVI Video", mime: "video/x-msvideo", category: "video", extension: "avi", offset: 8, bytes: b("AVI "), weight: 10 },
  { type: "mov", label: "QuickTime Movie", mime: "video/quicktime", category: "video", extension: "mov", offset: 4, bytes: b("ftypqt"), weight: 12 },
  { type: "flv", label: "Flash Video", mime: "video/x-flv", category: "video", extension: "flv", offset: 0, bytes: b("FLV") },
  { type: "mpeg", label: "MPEG Program Stream", mime: "video/mpeg", category: "video", extension: "mpeg", offset: 0, bytes: [0x00, 0x00, 0x01, 0xba] },

  // Executables / technical
  { type: "pe", label: "Windows Executable (PE)", mime: "application/vnd.microsoft.portable-executable", category: "binary", extension: "exe", offset: 0, bytes: b("MZ") },
  { type: "elf", label: "ELF Executable / Shared Object", mime: "application/x-elf", category: "binary", extension: "elf", offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { type: "macho", label: "Mach-O Executable", mime: "application/x-mach-binary", category: "binary", extension: "macho", offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { type: "class", label: "Java Class File", mime: "application/java-vm", category: "binary", extension: "class", offset: 0, bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { type: "wasm", label: "WebAssembly Module", mime: "application/wasm", category: "binary", extension: "wasm", offset: 0, bytes: [0x00, 0x61, 0x73, 0x6d] },
  { type: "sqlite", label: "SQLite Database", mime: "application/vnd.sqlite3", category: "data", extension: "sqlite", offset: 0, bytes: b("SQLite format 3") },
  { type: "parquet", label: "Apache Parquet", mime: "application/vnd.apache.parquet", category: "data", extension: "parquet", offset: 0, bytes: b("PAR1") },
  { type: "avro", label: "Apache Avro", mime: "application/avro", category: "data", extension: "avro", offset: 0, bytes: [0x4f, 0x62, 0x6a, 0x01] },
  { type: "feather", label: "Arrow / Feather", mime: "application/vnd.apache.arrow.file", category: "data", extension: "feather", offset: 0, bytes: b("ARROW1") },
  { type: "dex", label: "Android DEX", mime: "application/x-dex", category: "binary", extension: "dex", offset: 0, bytes: b("dex\n") },
];

export function matchSignatures(bytes: Uint8Array): Signature[] {
  const hits: Signature[] = [];
  for (const sig of SIGNATURES) {
    const end = sig.offset + sig.bytes.length;
    if (end > bytes.length) continue;
    let ok = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      const expected = sig.bytes[i];
      if (expected === null) continue;
      if (bytes[sig.offset + i] !== expected) {
        ok = false;
        break;
      }
    }
    if (ok) hits.push(sig);
  }
  return hits.sort((a, b2) => (b2.weight ?? 1) - (a.weight ?? 1));
}

/** Extension -> expected canonical type, used for mismatch detection. */
export const EXTENSION_MAP: Record<string, string> = {
  pdf: "pdf", rtf: "rtf", doc: "ole", xls: "ole", ppt: "ole", msg: "ole",
  docx: "docx", xlsx: "xlsx", pptx: "pptx", odt: "odt", ods: "ods", odp: "odp", epub: "epub", jar: "jar", apk: "apk",
  zip: "zip", rar: "rar", "7z": "7z", gz: "gz", tgz: "gz", bz2: "bz2", xz: "xz", tar: "tar", zst: "zstd",
  jpg: "jpeg", jpeg: "jpeg", png: "png", gif: "gif", bmp: "bmp", tif: "tiff", tiff: "tiff", webp: "webp",
  ico: "ico", heic: "heic", svg: "svg", psd: "psd",
  mp3: "mp3", wav: "wav", flac: "flac", ogg: "ogg", m4a: "m4a", aac: "aac", wma: "wma",
  mp4: "mp4", mkv: "mkv", webm: "mkv", avi: "avi", mov: "mov", flv: "flv", mpeg: "mpeg", mpg: "mpeg",
  exe: "pe", dll: "pe", sys: "pe", elf: "elf", so: "elf", class: "class", wasm: "wasm", dex: "dex",
  sqlite: "sqlite", db: "sqlite", parquet: "parquet", avro: "avro", feather: "feather",
  txt: "txt", md: "markdown", csv: "csv", tsv: "tsv", json: "json", jsonl: "jsonl",
  xml: "xml", yaml: "yaml", yml: "yaml", sql: "sql", html: "html", htm: "html",
  js: "script", ts: "script", py: "script", sh: "script", ps1: "script", bat: "script", cmd: "script", vbs: "script",
};

export const EXECUTABLE_EXTENSIONS = [
  "exe", "dll", "scr", "com", "pif", "bat", "cmd", "msi", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "ps1", "psm1", "jar", "apk", "app", "sh", "run", "elf", "so", "dylib", "hta", "cpl",
];
