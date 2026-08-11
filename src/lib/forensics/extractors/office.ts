// OOXML / OpenDocument extractors (docx, xlsx, pptx, odt, ods, odp, epub).
import { clampText, emptyResult, stripXmlTags, type Extractor } from "./base";
import { readZipDirectory, readZipEntry } from "../zip";
import type { ExtractedTable } from "../types";

const decoder = new TextDecoder();

async function readEntryText(bytes: Uint8Array, entries: Awaited<ReturnType<typeof readZipDirectory>>, name: string) {
  const entry = entries.find((item) => item.name === name);
  if (!entry) return null;
  const data = await readZipEntry(bytes, entry);
  return data ? decoder.decode(data) : null;
}

function colLetterToIndex(ref: string): number {
  const letters = ref.replace(/\d+/g, "");
  let index = 0;
  for (const char of letters) index = index * 26 + (char.charCodeAt(0) - 64);
  return index - 1;
}

export const officeExtractor: Extractor = {
  name: "ooxml-odf",
  supports: (detection) => ["docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"].includes(detection.type),
  extract: async ({ bytes, detection }) => {
    const notes: string[] = [];
    const metadata: Record<string, string | number> = {};
    const stats: Record<string, string | number> = {};
    const tables: ExtractedTable[] = [];
    let text = "";

    const entries = await readZipDirectory(bytes);
    stats["Container entries"] = entries.length;

    const core = (await readEntryText(bytes, entries, "docProps/core.xml")) ?? (await readEntryText(bytes, entries, "meta.xml"));
    if (core) {
      for (const key of ["dc:title", "dc:creator", "dc:subject", "cp:lastModifiedBy", "dcterms:created", "dcterms:modified", "meta:generator"]) {
        const match = core.match(new RegExp(`<${key}[^>]*>([^<]{1,200})</${key}>`));
        if (match?.[1]) metadata[key.split(":")[1] ?? key] = match[1];
      }
    }
    const app = await readEntryText(bytes, entries, "docProps/app.xml");
    if (app) {
      for (const key of ["Pages", "Words", "Slides", "Company", "Application"]) {
        const match = app.match(new RegExp(`<${key}>([^<]{1,120})</${key}>`));
        if (match?.[1]) metadata[key] = match[1];
      }
    }
    if (entries.some((entry) => /vbaProject/i.test(entry.name))) {
      notes.push("Document contains a VBA macro project (reported by the security engine).");
    }

    if (detection.type === "docx" || detection.type === "odt" || detection.type === "epub") {
      const parts = entries.filter((entry) =>
        detection.type === "docx"
          ? entry.name === "word/document.xml" || /^word\/(header|footer)\d*\.xml$/.test(entry.name)
          : detection.type === "odt"
            ? entry.name === "content.xml"
            : /\.x?html?$/.test(entry.name),
      );
      for (const part of parts.slice(0, 40)) {
        const data = await readZipEntry(bytes, part);
        if (data) text += stripXmlTags(decoder.decode(data)) + "\n";
      }
      const paragraphs = text.split(/\n+/).filter((line) => line.trim().length);
      stats["Paragraphs"] = paragraphs.length;
      stats["Words"] = (text.match(/\S+/g) ?? []).length;

      const doc = await readEntryText(bytes, entries, detection.type === "docx" ? "word/document.xml" : "content.xml");
      if (doc) {
        const headings = Array.from(doc.matchAll(/w:val="Heading\d"[\s\S]{0,400}?<w:t[^>]*>([^<]{1,120})</g)).map((match) => match[1] ?? "");
        if (headings.length) tables.push({ name: "Headings", columns: ["Heading"], rows: headings.slice(0, 30).map((h) => [h]) });
      }
      const rels = await readEntryText(bytes, entries, "word/_rels/document.xml.rels");
      if (rels) {
        const links = Array.from(rels.matchAll(/Target="(https?:\/\/[^"]+)"/g)).map((match) => match[1] ?? "");
        if (links.length) tables.push({ name: "Hyperlinks", columns: ["URL"], rows: links.slice(0, 30).map((url) => [url]) });
        stats["Hyperlinks"] = links.length;
      }
    }

    if (detection.type === "xlsx" || detection.type === "ods") {
      if (detection.type === "xlsx") {
        const workbook = await readEntryText(bytes, entries, "xl/workbook.xml");
        const sheetNames = workbook ? Array.from(workbook.matchAll(/<sheet[^>]*name="([^"]+)"/g)).map((match) => match[1] ?? "") : [];
        stats["Sheets"] = sheetNames.length;
        metadata["Sheet names"] = sheetNames.join(", ");

        const sharedRaw = await readEntryText(bytes, entries, "xl/sharedStrings.xml");
        const shared = sharedRaw
          ? Array.from(sharedRaw.matchAll(/<si>([\s\S]*?)<\/si>/g)).map((match) => stripXmlTags(match[1] ?? "").trim())
          : [];

        const sheetEntries = entries.filter((entry) => /^xl\/worksheets\/sheet\d+\.xml$/.test(entry.name)).slice(0, 5);
        let totalRows = 0;
        let formulas = 0;
        for (let s = 0; s < sheetEntries.length; s++) {
          const data = await readZipEntry(bytes, sheetEntries[s]!);
          if (!data) continue;
          const xml = decoder.decode(data);
          formulas += (xml.match(/<f[\s>]/g) ?? []).length;
          const rows = Array.from(xml.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g));
          totalRows += rows.length;
          const parsed: string[][] = [];
          for (const row of rows.slice(0, 40)) {
            const cells = Array.from((row[1] ?? "").matchAll(/<c([^>]*)>([\s\S]*?)<\/c>|<c([^>]*)\/>/g));
            const values: string[] = [];
            for (const cell of cells) {
              const attrs = cell[1] ?? cell[3] ?? "";
              const body = cell[2] ?? "";
              const ref = attrs.match(/r="([A-Z]+\d+)"/)?.[1];
              const index = ref ? colLetterToIndex(ref) : values.length;
              const isShared = /t="s"/.test(attrs);
              const rawValue = body.match(/<v>([\s\S]*?)<\/v>/)?.[1] ?? stripXmlTags(body).trim();
              const value = isShared ? (shared[Number(rawValue)] ?? "") : rawValue;
              while (values.length < index) values.push("");
              values[index] = value;
            }
            parsed.push(values);
          }
          if (parsed.length) {
            const header = parsed[0] ?? [];
            tables.push({
              name: sheetNames[s] ?? `Sheet ${s + 1}`,
              columns: header.map((name, index) => name || `col_${index + 1}`),
              rows: parsed.slice(1),
              truncated: rows.length > 40,
            });
            text += `[${sheetNames[s] ?? `Sheet ${s + 1}`}]\n` + parsed.map((row) => row.join(" | ")).join("\n") + "\n\n";
          }
        }
        stats["Rows (sampled sheets)"] = totalRows;
        stats["Formulas"] = formulas;
      } else {
        const content = await readEntryText(bytes, entries, "content.xml");
        if (content) {
          text = stripXmlTags(content);
          stats["Tables"] = (content.match(/<table:table[\s>]/g) ?? []).length;
        }
      }
    }

    if (detection.type === "pptx" || detection.type === "odp") {
      const slides = entries.filter((entry) => /^ppt\/slides\/slide\d+\.xml$/.test(entry.name));
      stats["Slides"] = detection.type === "pptx" ? slides.length : stats["Slides"] ?? "unknown";
      const notesEntries = entries.filter((entry) => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(entry.name));
      for (let i = 0; i < Math.min(slides.length, 60); i++) {
        const data = await readZipEntry(bytes, slides[i]!);
        if (data) text += `\n[Slide ${i + 1}]\n` + stripXmlTags(decoder.decode(data)).trim() + "\n";
      }
      for (let i = 0; i < Math.min(notesEntries.length, 30); i++) {
        const data = await readZipEntry(bytes, notesEntries[i]!);
        if (data) {
          const noteText = stripXmlTags(decoder.decode(data)).trim();
          if (noteText) text += `\n[Speaker notes ${i + 1}]\n${noteText}\n`;
        }
      }
      if (detection.type === "odp") {
        const content = await readEntryText(bytes, entries, "content.xml");
        if (content) text += stripXmlTags(content);
      }
      stats["Embedded media"] = entries.filter((entry) => entry.name.startsWith("ppt/media/")).length;
    }

    const clamped = clampText(text);
    return emptyResult({ text: clamped.text, truncated: clamped.truncated, stats, metadata, tables, notes });
  },
};
