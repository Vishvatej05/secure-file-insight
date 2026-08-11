// Extractor registry — order matters, first match wins.
import type { Extractor } from "./base";
import { pdfExtractor } from "./pdf";
import { officeExtractor } from "./office";
import { delimitedExtractor, structuredTextExtractor } from "./text";
import { archiveExtractor, opaqueArchiveExtractor } from "./archive";
import { imageExtractor, mediaExtractor } from "./media";
import { binaryExtractor, unknownExtractor } from "./binary";
import type { DetectionResult, ExtractionResult } from "../types";
import { emptyResult } from "./base";

export const EXTRACTORS: Extractor[] = [
  pdfExtractor,
  officeExtractor,
  delimitedExtractor,
  structuredTextExtractor,
  archiveExtractor,
  opaqueArchiveExtractor,
  imageExtractor,
  mediaExtractor,
  binaryExtractor,
  unknownExtractor,
];

export async function extractContent(
  bytes: Uint8Array,
  fileName: string,
  detection: DetectionResult,
): Promise<ExtractionResult> {
  const extractor = EXTRACTORS.find((candidate) => candidate.supports(detection)) ?? unknownExtractor;
  try {
    return await extractor.extract({ bytes, fileName, detection });
  } catch (error) {
    return emptyResult({
      notes: ["Content extraction failed; the file may be corrupted, encrypted or malformed."],
      error: error instanceof Error ? error.message : String(error),
      unsupported: true,
      metadata: { Format: detection.label },
    });
  }
}

export type { Extractor } from "./base";
