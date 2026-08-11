// Archive extractor: safe listing + recursive type detection with hard limits.
import { emptyResult, type Extractor } from "./base";
import { readZipDirectory } from "../zip";
import { matchSignatures } from "../signatures";
import { readZipEntry } from "../zip";

const MAX_LISTED = 300;
const MAX_INSPECTED = 40;

export const archiveExtractor: Extractor = {
  name: "archive",
  supports: (detection) => ["zip", "jar", "apk"].includes(detection.type),
  extract: async ({ bytes }) => {
    const entries = await readZipDirectory(bytes);
    const total = entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0);
    const children: NonNullable<ReturnType<typeof emptyResult>["children"]> = [];
    const notes: string[] = [];

    let inspected = 0;
    for (const entry of entries.slice(0, MAX_LISTED)) {
      if (entry.name.endsWith("/")) continue;
      let detectedLabel = "not inspected";
      let risk = "not scanned";
      if (inspected < MAX_INSPECTED && !entry.encrypted) {
        const head = await readZipEntry(bytes, entry, 65_536);
        if (head) {
          inspected++;
          const hit = matchSignatures(head)[0];
          detectedLabel = hit ? hit.label : "text or unrecognised";
          risk = hit && hit.category === "binary" ? "executable content" : "no signature-level threat";
        }
      }
      if (entry.encrypted) {
        detectedLabel = "encrypted";
        risk = "cannot inspect";
      }
      children.push({
        name: entry.name,
        size: entry.uncompressedSize,
        detected: detectedLabel,
        risk,
        note: /\.(exe|dll|js|vbs|ps1|bat|cmd|jar|scr|hta)$/i.test(entry.name) ? "high-risk extension" : undefined,
      });
    }

    if (entries.length > MAX_LISTED) notes.push(`Only the first ${MAX_LISTED} of ${entries.length} entries are listed (recursion/limit policy).`);
    notes.push(`Deep inspection was limited to ${MAX_INSPECTED} entries and 64 KB per entry to prevent resource exhaustion.`);

    const text = children.slice(0, 200).map((child) => `${child.name} (${child.size} bytes, ${child.detected})`).join("\n");
    return emptyResult({
      text,
      truncated: children.length > 200,
      stats: {
        Entries: entries.length,
        "Uncompressed size": `${(total / 1024).toFixed(1)} KB`,
        "Compression ratio": bytes.length ? `${(total / bytes.length).toFixed(1)}:1` : "n/a",
        Encrypted: entries.filter((entry) => entry.encrypted).length,
      },
      metadata: {},
      tables: [
        {
          name: "Archive contents",
          columns: ["Path", "Size (bytes)", "Detected type", "Static assessment"],
          rows: children.map((child) => [child.name, String(child.size), child.detected, child.risk]),
          truncated: entries.length > MAX_LISTED,
        },
      ],
      children,
      notes,
    });
  },
};

export const opaqueArchiveExtractor: Extractor = {
  name: "opaque-archive",
  supports: (detection) => ["rar", "7z", "gz", "bz2", "xz", "tar", "zstd"].includes(detection.type),
  extract: async ({ bytes, detection }) => {
    return emptyResult({
      stats: { "Compressed size": `${(bytes.length / 1024).toFixed(1)} KB` },
      metadata: { Format: detection.label },
      notes: [
        `${detection.label} cannot be decompressed safely in this environment, so its contents were not listed.`,
        "Type identification, hashing and filename/structure security rules were still applied.",
      ],
      unsupported: true,
    });
  },
};
