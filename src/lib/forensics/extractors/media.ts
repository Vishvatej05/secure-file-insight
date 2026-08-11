// Image, audio and video extractors: header/metadata parsing only.
import { clampText, emptyResult, type Extractor } from "./base";

const decoder = new TextDecoder("latin1" as string, { fatal: false });

function pngInfo(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    Width: view.getUint32(16),
    Height: view.getUint32(20),
    "Bit depth": bytes[24] ?? 0,
    "Colour type": bytes[25] ?? 0,
  };
}

function jpegInfo(bytes: Uint8Array) {
  let offset = 2;
  const info: Record<string, string | number> = {};
  while (offset + 9 < bytes.length) {
    if (bytes[offset] !== 0xff) break;
    const marker = bytes[offset + 1]!;
    const length = ((bytes[offset + 2] ?? 0) << 8) | (bytes[offset + 3] ?? 0);
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      info["Height"] = ((bytes[offset + 5] ?? 0) << 8) | (bytes[offset + 6] ?? 0);
      info["Width"] = ((bytes[offset + 7] ?? 0) << 8) | (bytes[offset + 8] ?? 0);
      info["Components"] = bytes[offset + 9] ?? 0;
      break;
    }
    offset += 2 + length;
  }
  return info;
}

function gifInfo(bytes: Uint8Array) {
  return {
    Width: ((bytes[7] ?? 0) << 8) | (bytes[6] ?? 0),
    Height: ((bytes[9] ?? 0) << 8) | (bytes[8] ?? 0),
    Version: decoder.decode(bytes.subarray(0, 6)),
  };
}

export const imageExtractor: Extractor = {
  name: "image",
  supports: (detection) => detection.category === "image",
  extract: async ({ bytes, detection }) => {
    const metadata: Record<string, string | number> = { Format: detection.label };
    const notes: string[] = [];
    let text = "";

    try {
      if (detection.type === "png") Object.assign(metadata, pngInfo(bytes));
      if (detection.type === "jpeg") Object.assign(metadata, jpegInfo(bytes));
      if (detection.type === "gif") Object.assign(metadata, gifInfo(bytes));
      if (detection.type === "svg") {
        const raw = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 1_000_000)));
        metadata["Width"] = raw.match(/width="([^"]+)"/)?.[1] ?? "unknown";
        metadata["Height"] = raw.match(/height="([^"]+)"/)?.[1] ?? "unknown";
        const labels = Array.from(raw.matchAll(/<(?:title|desc|text)[^>]*>([^<]{1,200})</g)).map((match) => match[1] ?? "");
        text = labels.join("\n");
        if (/<script|on\w+\s*=/.test(raw)) notes.push("SVG contains active content — it is treated as a script-bearing document.");
      }
    } catch {
      notes.push("Image header parsing failed; the file may be malformed.");
    }

    const raw = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 200_000)));
    const exifStrings = Array.from(raw.matchAll(/(GPS|Make|Model|Software|DateTime|Artist|Copyright)[\x00-\x20]{0,4}([\x20-\x7e]{3,60})/g))
      .map((match) => `${match[1]}: ${match[2]}`)
      .slice(0, 12);
    if (exifStrings.length) metadata["Embedded strings"] = exifStrings.join(" · ");
    notes.push("Optical character recognition is not available in this build; only header metadata and embedded text were extracted.");

    const clamped = clampText(text);
    return emptyResult({
      text: clamped.text,
      truncated: clamped.truncated,
      stats: { "File size": `${(bytes.length / 1024).toFixed(1)} KB` },
      metadata,
      notes,
    });
  },
};

export const mediaExtractor: Extractor = {
  name: "media",
  supports: (detection) => detection.category === "audio" || detection.category === "video",
  extract: async ({ bytes, detection }) => {
    const metadata: Record<string, string | number> = { Format: detection.label, Container: detection.container ?? detection.type };
    const raw = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 300_000)));
    const notes: string[] = [];

    if (detection.type === "mp3" && raw.startsWith("ID3")) {
      for (const [tag, label] of [["TIT2", "Title"], ["TPE1", "Artist"], ["TALB", "Album"], ["TYER", "Year"], ["TCON", "Genre"]] as const) {
        const index = raw.indexOf(tag);
        if (index > 0) {
          const value = raw.slice(index + 11, index + 80).split("\u0000").filter(Boolean)[0];
          if (value) metadata[label] = value.replace(/[^\x20-\x7e]/g, "").trim();
        }
      }
    }
    if (detection.type === "wav") {
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (bytes.length > 44) {
        metadata["Channels"] = view.getUint16(22, true);
        metadata["Sample rate"] = `${view.getUint32(24, true)} Hz`;
        metadata["Bit depth"] = view.getUint16(34, true);
        const byteRate = view.getUint32(28, true);
        if (byteRate) metadata["Approx. duration"] = `${((bytes.length - 44) / byteRate).toFixed(1)} s`;
      }
    }
    if (["mp4", "mov", "m4a", "heic"].includes(detection.type)) {
      metadata["Brand"] = decoder.decode(bytes.subarray(8, 12));
      const handlers = Array.from(raw.matchAll(/hdlr[\s\S]{8}(\w{4})/g)).map((match) => match[1] ?? "");
      if (handlers.length) metadata["Tracks"] = Array.from(new Set(handlers)).join(", ");
    }

    notes.push(
      detection.category === "audio"
        ? "Speech-to-text transcription is not enabled in this build; only container metadata was read."
        : "Video frame analysis and transcription are not enabled in this build; only container metadata was read.",
    );

    return emptyResult({
      stats: { "File size": `${(bytes.length / 1_048_576).toFixed(2)} MB` },
      metadata,
      notes,
      unsupported: true,
    });
  },
};
