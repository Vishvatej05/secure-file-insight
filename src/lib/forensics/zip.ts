// Minimal, allocation-bounded ZIP central-directory reader with safe inflate.
// Never executes archive content; used for archives and OOXML/ODF containers.

export interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: number;
  encrypted: boolean;
  /** offset of the file data inside the buffer */
  dataStart: number;
  crc32: number;
}

const MAX_ENTRIES = 2000;
const decoder = new TextDecoder();

export async function readZipDirectory(bytes: Uint8Array): Promise<ZipEntry[]> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Locate End Of Central Directory record.
  let eocd = -1;
  const start = Math.max(0, bytes.length - 66_000);
  for (let i = bytes.length - 22; i >= start; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("ZIP end-of-central-directory record not found");

  let count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  if (offset === 0xffffffff) throw new Error("ZIP64 archives are not parsed in-browser");
  if (count > MAX_ENTRIES) count = MAX_ENTRIES;

  const entries: ZipEntry[] = [];
  for (let i = 0; i < count; i++) {
    if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) break;
    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const crc32 = view.getUint32(offset + 16, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localHeader = view.getUint32(offset + 42, true);
    const name = decoder.decode(bytes.subarray(offset + 46, offset + 46 + nameLength));

    let dataStart = 0;
    if (localHeader + 30 <= bytes.length && view.getUint32(localHeader, true) === 0x04034b50) {
      const localNameLength = view.getUint16(localHeader + 26, true);
      const localExtraLength = view.getUint16(localHeader + 28, true);
      dataStart = localHeader + 30 + localNameLength + localExtraLength;
    }

    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      method,
      encrypted: (flags & 0x1) === 1,
      dataStart,
      crc32,
    });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** Inflate a single entry with a hard output cap (decompression-bomb guard). */
export async function readZipEntry(
  bytes: Uint8Array,
  entry: ZipEntry,
  maxBytes = 4_000_000,
): Promise<Uint8Array | null> {
  if (entry.encrypted || !entry.dataStart) return null;
  if (entry.uncompressedSize > maxBytes) return null;
  const slice = bytes.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
  if (entry.method === 0) return slice;
  if (entry.method !== 8) return null;
  if (typeof DecompressionStream === "undefined") return null;
  try {
    const stream = new Blob([slice as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    const buffer = await new Response(stream).arrayBuffer();
    if (buffer.byteLength > maxBytes) return new Uint8Array(buffer.slice(0, maxBytes));
    return new Uint8Array(buffer);
  } catch {
    return null;
  }
}

export async function inflateRaw(slice: Uint8Array, format: "deflate" | "deflate-raw" | "gzip" = "deflate"): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === "undefined") return null;
  try {
    const stream = new Blob([slice as BlobPart]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}
