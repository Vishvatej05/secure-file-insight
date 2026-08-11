// Static executable/binary analysis. Nothing is loaded, linked or executed.
import { emptyResult, type Extractor } from "./base";
import type { ExtractedTable } from "../types";

const decoder = new TextDecoder("latin1" as string, { fatal: false });

const MACHINE_TYPES: Record<number, string> = {
  0x014c: "x86 (32-bit)",
  0x8664: "x86-64",
  0x01c0: "ARM",
  0xaa64: "ARM64",
  0x0200: "Itanium",
};

const ELF_MACHINES: Record<number, string> = {
  0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0xf3: "RISC-V", 0x08: "MIPS",
};

function extractStrings(bytes: Uint8Array, min = 6, limit = 400): string[] {
  const out: string[] = [];
  let current = "";
  const cap = Math.min(bytes.length, 2_000_000);
  for (let i = 0; i < cap && out.length < limit; i++) {
    const byte = bytes[i]!;
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= min) out.push(current);
      current = "";
    }
  }
  if (current.length >= min && out.length < limit) out.push(current);
  return out;
}

export const binaryExtractor: Extractor = {
  name: "binary",
  supports: (detection) => ["pe", "elf", "macho", "class", "wasm", "dex", "sqlite", "parquet", "avro", "feather"].includes(detection.type),
  extract: async ({ bytes, detection }) => {
    const metadata: Record<string, string | number> = { Format: detection.label };
    const stats: Record<string, string | number> = { "File size": `${(bytes.length / 1024).toFixed(1)} KB` };
    const tables: ExtractedTable[] = [];
    const notes: string[] = [
      "This file was analysed statically. It was never executed, loaded or linked.",
    ];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    try {
      if (detection.type === "pe" && bytes.length > 0x40) {
        const peOffset = view.getUint32(0x3c, true);
        if (peOffset + 24 < bytes.length) {
          const machine = view.getUint16(peOffset + 4, true);
          const sectionCount = view.getUint16(peOffset + 6, true);
          const timestamp = view.getUint32(peOffset + 8, true);
          const characteristics = view.getUint16(peOffset + 22, true);
          metadata["Architecture"] = MACHINE_TYPES[machine] ?? `0x${machine.toString(16)}`;
          metadata["Compiled"] = timestamp ? new Date(timestamp * 1000).toISOString() : "unknown";
          metadata["Subsystem type"] = characteristics & 0x2000 ? "DLL (library)" : "EXE (application)";
          stats["Sections"] = sectionCount;

          const optionalSize = view.getUint16(peOffset + 20, true);
          const sectionStart = peOffset + 24 + optionalSize;
          const rows: string[][] = [];
          for (let i = 0; i < Math.min(sectionCount, 24); i++) {
            const base = sectionStart + i * 40;
            if (base + 40 > bytes.length) break;
            const name = decoder.decode(bytes.subarray(base, base + 8)).replace(/\u0000+$/, "");
            const virtualSize = view.getUint32(base + 8, true);
            const rawSize = view.getUint32(base + 16, true);
            const flags = view.getUint32(base + 36, true);
            const perms = [flags & 0x20000000 ? "execute" : "", flags & 0x80000000 ? "write" : "", flags & 0x40000000 ? "read" : ""]
              .filter(Boolean)
              .join("/");
            rows.push([name, String(virtualSize), String(rawSize), perms || "none"]);
          }
          if (rows.length) tables.push({ name: "PE sections", columns: ["Name", "Virtual size", "Raw size", "Permissions"], rows });
        }
      }

      if (detection.type === "elf") {
        metadata["Class"] = bytes[4] === 2 ? "64-bit" : "32-bit";
        metadata["Endianness"] = bytes[5] === 1 ? "little" : "big";
        const typeValue = view.getUint16(16, true);
        metadata["Object type"] = { 1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump" }[typeValue] ?? String(typeValue);
        metadata["Architecture"] = ELF_MACHINES[view.getUint16(18, true)] ?? `0x${view.getUint16(18, true).toString(16)}`;
      }

      if (detection.type === "sqlite") {
        metadata["Page size"] = view.getUint16(16) || 65536;
        const strings = extractStrings(bytes, 8, 800);
        const tableNames = strings
          .filter((value) => /CREATE TABLE/i.test(value))
          .map((value) => value.replace(/\s+/g, " ").slice(0, 160));
        if (tableNames.length) {
          tables.push({ name: "Schema statements", columns: ["DDL"], rows: tableNames.slice(0, 30).map((value) => [value]) });
          stats["Tables"] = tableNames.length;
        }
        notes.push("Only the SQLite header and schema strings were read; no queries were executed.");
      }

      if (detection.type === "class") {
        metadata["Class file version"] = `${view.getUint16(6)}.${view.getUint16(4)}`;
      }
      if (detection.type === "wasm") {
        metadata["WASM version"] = view.getUint32(4, true);
      }
    } catch {
      notes.push("Header parsing was incomplete — the binary may be truncated or malformed.");
    }

    const strings = extractStrings(bytes);
    const interesting = strings.filter((value) =>
      /https?:\/\/|\.dll$|\.exe$|Advapi|kernel32|CreateProcess|VirtualAlloc|RegSet|cmd\.exe|powershell|\/bin\/sh|socket|GetProcAddress/i.test(value),
    );
    if (interesting.length) {
      tables.push({
        name: "Notable strings",
        columns: ["String"],
        rows: interesting.slice(0, 60).map((value) => [value.slice(0, 200)]),
        truncated: interesting.length > 60,
      });
    }
    stats["Extracted strings"] = strings.length;

    return emptyResult({
      text: strings.slice(0, 200).join("\n").slice(0, 20_000),
      truncated: strings.length > 200,
      stats,
      metadata,
      tables,
      notes,
    });
  },
};

export const unknownExtractor: Extractor = {
  name: "unknown",
  supports: () => true,
  extract: async ({ bytes, detection }) => {
    const strings = extractStrings(bytes, 8, 120);
    return emptyResult({
      text: strings.join("\n").slice(0, 8000),
      stats: { "File size": `${(bytes.length / 1024).toFixed(1)} KB`, "Readable strings": strings.length },
      metadata: { Format: detection.label },
      notes: [
        "The format could not be parsed, so only generic binary information is available.",
        "Possible reasons: unsupported format, corrupted file, encrypted content, custom binary format, or insufficient signature information.",
        "No threat indicator found does not mean the file is safe.",
      ],
      unsupported: true,
    });
  },
};
