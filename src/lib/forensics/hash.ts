// Hashing + basic binary statistics. Pure static computation, never executes input.
import type { BinaryStats, Hashes } from "./types";

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/* ---------- MD5 (identification only, not for security decisions) ---------- */

const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const K = new Uint32Array(
  Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)),
);

function rotl(x: number, c: number): number {
  return (x << c) | (x >>> (32 - c));
}

export function md5(input: Uint8Array): string {
  const originalBits = input.length * 8;
  const paddedLength = (((input.length + 8) >> 6) + 1) << 6;
  const data = new Uint8Array(paddedLength);
  data.set(input);
  data[input.length] = 0x80;
  const view = new DataView(data.buffer);
  view.setUint32(paddedLength - 8, originalBits >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(originalBits / 4294967296), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let chunk = 0; chunk < paddedLength; chunk += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(chunk + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number;
      let g: number;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i]! + M[g]!) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl(F, S[i]!)) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a0, true);
  out.setUint32(4, b0, true);
  out.setUint32(8, c0, true);
  out.setUint32(12, d0, true);
  return toHex(out.buffer);
}

export async function computeHashes(bytes: Uint8Array): Promise<Hashes> {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const [sha256, sha1] = await Promise.all([
    crypto.subtle.digest("SHA-256", buffer),
    crypto.subtle.digest("SHA-1", buffer),
  ]);
  return { sha256: toHex(sha256), sha1: toHex(sha1), md5: md5(bytes) };
}

export function computeBinaryStats(bytes: Uint8Array): BinaryStats {
  const sample = bytes.length > 1_000_000 ? bytes.subarray(0, 1_000_000) : bytes;
  const counts = new Uint32Array(256);
  let printable = 0;
  let nulls = 0;
  for (let i = 0; i < sample.length; i++) {
    const byte = sample[i]!;
    counts[byte] = (counts[byte] ?? 0) + 1;
    if (byte === 0) nulls++;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i]! / sample.length;
    entropy -= p * Math.log2(p);
  }
  const headerHex = Array.from(bytes.subarray(0, 16))
    .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
    .join(" ");
  return {
    entropy: sample.length ? Number(entropy.toFixed(3)) : 0,
    printableRatio: sample.length ? printable / sample.length : 0,
    nullRatio: sample.length ? nulls / sample.length : 0,
    headerHex,
  };
}
