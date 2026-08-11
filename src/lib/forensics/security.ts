// Deterministic security rule engine. AI never changes these results.
import { EXECUTABLE_EXTENSIONS, getExtension } from "./signatures-helpers";
import type { BinaryStats, DetectionResult, RiskAssessment, RiskLevel, SecurityFinding } from "./types";
import { readZipDirectory, readZipEntry } from "./zip";

const decoder = new TextDecoder("utf-8", { fatal: false });

const SUSPICIOUS_NAME_PATTERNS: Array<[RegExp, string]> = [
  [/\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)\.(exe|scr|com|bat|cmd|js|vbs|ps1|jar|msi|hta)$/i, "Double extension disguising an executable"],
  [/(invoice|receipt|payment|statement|resume|cv|urgent|payroll|refund)[-_ ]?\d*\.(exe|scr|js|vbs|jar|hta|msi)$/i, "Social-engineering filename on an executable"],
  [/\u202e/, "Right-to-left override character in filename (extension spoofing)"],
  [/(crack|keygen|patch|activator|loader)/i, "Filename associated with cracked software bundles"],
];

const PDF_RULES: Array<[RegExp, string, SecurityFinding["severity"], number, string]> = [
  [/\/JavaScript|\/JS[\s/<]/, "PDF contains JavaScript", "high", 28, "Do not open with a viewer that allows scripting."],
  [/\/OpenAction/, "PDF defines an automatic action on open", "high", 22, "Inspect the action target before opening."],
  [/\/AA[\s/<]/, "PDF defines additional automatic actions", "medium", 14, "Treat auto-triggered behaviour as untrusted."],
  [/\/Launch/, "PDF contains a Launch action (can start external programs)", "critical", 34, "Do not open. Launch actions are commonly abused."],
  [/\/EmbeddedFile/, "PDF embeds one or more files", "medium", 16, "Extract embedded files only in an isolated environment."],
  [/\/RichMedia|\/Flash/, "PDF embeds rich media / Flash content", "medium", 12, "Disable multimedia in your PDF reader."],
  [/\/URI\s*\(/, "PDF contains external URI links", "low", 4, "Verify link targets before clicking."],
  [/\/AcroForm/, "PDF contains interactive form fields", "info", 0, "Informational only."],
];

const SCRIPT_RULES: Array<[RegExp, string, SecurityFinding["severity"], number]> = [
  [/eval\s*\(|new\s+Function\s*\(/, "Dynamic code evaluation (eval / Function constructor)", "high", 20],
  [/FromBase64String|atob\s*\(|base64\s+-d/i, "Base64 decoding of embedded payload", "medium", 12],
  [/Invoke-Expression|IEX\s|powershell\s+-e(nc)?\b/i, "Encoded PowerShell execution", "critical", 30],
  [/WScript\.Shell|Shell\.Application|cmd\.exe\s*\/c/i, "Shell command execution primitives", "high", 22],
  [/curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh/i, "Download-and-execute pipeline", "critical", 30],
  [/urllib|requests\.get|XMLHttpRequest|fetch\s*\(/, "Outbound network request in script", "low", 6],
  [/document\.write|innerHTML\s*=/, "DOM injection primitives", "low", 5],
  [/<script[\s>]/i, "Embedded script tag", "medium", 12],
  [/on(load|error|click)\s*=\s*["']/i, "Inline event handler attribute", "medium", 10],
];

function levelFromScore(score: number, scanComplete: boolean): RiskLevel {
  if (!scanComplete) return "UNKNOWN";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  if (score >= 12) return "LOW";
  return "SAFE";
}

export async function runSecurityScan(params: {
  bytes: Uint8Array;
  fileName: string;
  detection: DetectionResult;
  extensionMatch: boolean | null;
  binary: BinaryStats;
}): Promise<RiskAssessment> {
  const { bytes, fileName, detection, extensionMatch, binary } = params;
  const findings: SecurityFinding[] = [];
  let scanComplete = true;

  const push = (finding: SecurityFinding) => findings.push(finding);

  // --- Filename rules -------------------------------------------------
  for (const [pattern, description] of SUSPICIOUS_NAME_PATTERNS) {
    if (pattern.test(fileName)) {
      push({
        category: "Filename",
        severity: "high",
        description,
        evidence: fileName,
        recommendation: "Treat this file as untrusted; verify the sender through another channel.",
        points: 25,
      });
    }
  }

  // --- Extension / content mismatch ----------------------------------
  if (extensionMatch === false) {
    const declared = getExtension(fileName);
    const dangerous = detection.category === "binary";
    push({
      category: "Extension mismatch",
      severity: dangerous ? "critical" : "medium",
      description: `The filename claims ".${declared}" but the content is ${detection.label}`,
      evidence: `Declared .${declared} · Detected ${detection.type} (${detection.confidence}% confidence)`,
      recommendation: dangerous
        ? "Executable content hidden behind a harmless extension is a strong malware indicator. Do not open."
        : `Rename to .${detection.extension} and open with the matching application.`,
      points: dangerous ? 45 : 18,
    });
  } else if (extensionMatch === null) {
    push({
      category: "Extension",
      severity: "low",
      description: "File has no extension; type was established from content only",
      evidence: fileName,
      recommendation: `Add the extension .${detection.extension} if the detection looks correct.`,
      points: 5,
    });
  }

  // --- Executable / high-risk types ----------------------------------
  const declaredExt = getExtension(fileName);
  if (detection.category === "binary" || (declaredExt && EXECUTABLE_EXTENSIONS.includes(declaredExt))) {
    const isRunnable = ["pe", "elf", "macho", "apk", "jar", "class", "dex", "wasm"].includes(detection.type);
    push({
      category: "Executable content",
      severity: isRunnable ? "high" : "medium",
      description: `${detection.label} contains machine-executable or bytecode content`,
      evidence: `Detected type: ${detection.type}`,
      recommendation: "Only run software from sources you trust. This platform never executes uploads.",
      points: isRunnable ? 40 : 20,
    });
  }

  // --- Entropy --------------------------------------------------------
  const compressedTypes = ["zip", "7z", "rar", "gz", "bz2", "xz", "zstd", "jpeg", "png", "webp", "mp3", "mp4", "mkv", "docx", "xlsx", "pptx", "heic", "flac"];
  if (binary.entropy >= 7.5 && !compressedTypes.includes(detection.type)) {
    push({
      category: "Entropy",
      severity: "medium",
      description: "Very high entropy for this file type — data may be packed, encrypted or obfuscated",
      evidence: `Shannon entropy ${binary.entropy} bits/byte`,
      recommendation: "High entropy alone is not proof of malice, but combined with executable content it is a packing indicator.",
      points: 14,
    });
  }

  if (detection.type === "unknown") {
    push({
      category: "Unrecognised format",
      severity: "medium",
      description: "The file format could not be identified from its content",
      evidence: `Header bytes: ${binary.headerHex}`,
      recommendation: "Unknown does not mean safe. Handle in an isolated environment.",
      points: 15,
    });
    scanComplete = false;
  }

  // --- Format specific -------------------------------------------------
  try {
    if (detection.type === "pdf") {
      const text = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 5_000_000)));
      for (const [pattern, description, severity, points, recommendation] of PDF_RULES) {
        if (pattern.test(text)) {
          push({ category: "PDF active content", severity, description, evidence: pattern.source, recommendation, points });
        }
      }
      if (/\/Encrypt[\s/<]/.test(text)) {
        push({
          category: "Encryption",
          severity: "low",
          description: "PDF is encrypted or password protected",
          evidence: "/Encrypt dictionary present",
          recommendation: "Content extraction may be limited.",
          points: 6,
        });
      }
    }

    if (["docx", "xlsx", "pptx", "odt", "ods", "odp", "zip", "epub", "jar", "apk"].includes(detection.type)) {
      const entries = await readZipDirectory(bytes);
      const names = entries.map((entry) => entry.name);

      if (names.some((name) => /vbaProject\.bin$|\.bin$/i.test(name) && /vbaProject/i.test(name))) {
        push({
          category: "Office macros",
          severity: "high",
          description: "Document contains a VBA macro project",
          evidence: "vbaProject.bin present in the container",
          recommendation: "Do not enable macros unless you fully trust the origin.",
          points: 35,
        });
      }
      if (names.some((name) => /\.(exe|dll|scr|bat|cmd|js|vbs|ps1|jar|msi|hta|com)$/i.test(name))) {
        push({
          category: "Embedded executable",
          severity: "critical",
          description: "Container includes executable or script files",
          evidence: names.filter((name) => /\.(exe|dll|scr|bat|cmd|js|vbs|ps1|jar|msi|hta|com)$/i.test(name)).slice(0, 5).join(", "),
          recommendation: "Do not extract and run the contained files.",
          points: 40,
        });
      }
      if (names.some((name) => /\.(zip|rar|7z|gz|bz2|xz)$/i.test(name))) {
        push({
          category: "Nested archive",
          severity: "medium",
          description: "Archive contains further archives (nesting is used to evade scanners)",
          evidence: names.filter((name) => /\.(zip|rar|7z|gz|bz2|xz)$/i.test(name)).slice(0, 5).join(", "),
          recommendation: "Inspect nested archives separately with recursion limits.",
          points: 15,
        });
      }
      if (entries.some((entry) => entry.encrypted)) {
        push({
          category: "Password protected",
          severity: "medium",
          description: "Archive entries are encrypted; contents cannot be inspected",
          evidence: `${entries.filter((entry) => entry.encrypted).length} encrypted entries`,
          recommendation: "Encrypted archives are a common way to bypass scanning. Verify the sender.",
          points: 20,
        });
        scanComplete = false;
      }
      if (names.some((name) => name.includes("../") || name.startsWith("/") || /^[a-z]:\\/i.test(name))) {
        push({
          category: "Path traversal",
          severity: "critical",
          description: "Archive entry names attempt to escape the extraction directory",
          evidence: names.find((name) => name.includes("../")) ?? "absolute path entry",
          recommendation: "Do not extract with a tool that honours absolute or relative paths.",
          points: 45,
        });
      }
      const totalUncompressed = entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0);
      const ratio = bytes.length ? totalUncompressed / bytes.length : 0;
      if (ratio > 100 && totalUncompressed > 50_000_000) {
        push({
          category: "Decompression bomb",
          severity: "critical",
          description: "Extreme compression ratio — likely a decompression bomb",
          evidence: `Ratio ≈ ${Math.round(ratio)}:1 (${Math.round(totalUncompressed / 1_000_000)} MB expanded)`,
          recommendation: "Do not extract this archive.",
          points: 45,
        });
      }
      if (entries.length > 1000) {
        push({
          category: "Archive structure",
          severity: "low",
          description: `Archive holds a very large number of entries (${entries.length})`,
          evidence: `${entries.length} entries`,
          recommendation: "Large archives can exhaust resources during extraction.",
          points: 6,
        });
      }

      // Scan OOXML relationship targets for remote template injection.
      const relEntry = entries.find((entry) => /_rels\/.+\.rels$/.test(entry.name) || entry.name.endsWith(".rels"));
      if (relEntry) {
        const relBytes = await readZipEntry(bytes, relEntry, 1_000_000);
        if (relBytes) {
          const rels = decoder.decode(relBytes);
          if (/attachedTemplate|oleObject|frame/i.test(rels) && /Target="https?:/i.test(rels)) {
            push({
              category: "Remote content",
              severity: "high",
              description: "Document references a remote template or embedded object over the network",
              evidence: (rels.match(/Target="https?:\/\/[^"]+"/i) ?? ["remote target"])[0],
              recommendation: "Remote template injection is a known malware delivery technique.",
              points: 30,
            });
          }
        }
      }
    }

    if (["txt", "script", "html", "svg", "xml", "json", "yaml", "sql", "markdown", "csv"].includes(detection.type)) {
      const text = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 2_000_000)));
      for (const [pattern, description, severity, points] of SCRIPT_RULES) {
        if (pattern.test(text)) {
          const hit = text.match(pattern);
          push({
            category: "Script analysis",
            severity,
            description,
            evidence: hit ? hit[0].slice(0, 120) : pattern.source,
            recommendation: "Review the script statically before running it anywhere.",
            points,
          });
        }
      }
      if (detection.type === "csv" && /^[=+\-@]/m.test(text)) {
        push({
          category: "CSV injection",
          severity: "medium",
          description: "Cells begin with formula characters (=, +, -, @) — spreadsheet formula injection risk",
          evidence: (text.match(/^[=+\-@].{0,60}/m) ?? [""])[0],
          recommendation: "Open with formula evaluation disabled.",
          points: 14,
        });
      }
      const urls = text.match(/https?:\/\/[^\s"'<>)]+/g) ?? [];
      const suspiciousUrls = urls.filter((url) => /\d{1,3}(\.\d{1,3}){3}|\.(ru|tk|xyz|top|gq|cf)\b|bit\.ly|tinyurl/i.test(url));
      if (suspiciousUrls.length) {
        push({
          category: "Suspicious URL",
          severity: "medium",
          description: `${suspiciousUrls.length} suspicious URL(s) found (raw IP, shortener or high-abuse TLD)`,
          evidence: suspiciousUrls.slice(0, 3).join(", ").slice(0, 200),
          recommendation: "Do not visit these links.",
          points: 12,
        });
      }
    }

    if (detection.type === "pe" || detection.type === "elf") {
      const text = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 3_000_000)));
      const apis = [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx",
        "URLDownloadToFile", "WinExec", "ShellExecute", "RegSetValue", "CryptEncrypt", "IsDebuggerPresent",
      ].filter((api) => text.includes(api));
      if (apis.length >= 2) {
        push({
          category: "Static imports",
          severity: "high",
          description: "Executable references APIs commonly used for injection, persistence or download-and-run",
          evidence: apis.slice(0, 6).join(", "),
          recommendation: "Analyse in a dedicated malware sandbox, never on a workstation.",
          points: 25,
        });
      }
    }

    // Polyglot indicator: another strong signature deep inside the file.
    const tail = bytes.subarray(0, Math.min(bytes.length, 2_000_000));
    const asText = decoder.decode(tail);
    if (detection.type !== "zip" && detection.category === "image" && asText.includes("PK\u0003\u0004")) {
      push({
        category: "Polyglot file",
        severity: "high",
        description: "Image file also contains a complete ZIP archive structure (polyglot)",
        evidence: "ZIP local file header found inside image data",
        recommendation: "Polyglot files are used to smuggle payloads past filters.",
        points: 30,
      });
    }
  } catch (error) {
    scanComplete = false;
    push({
      category: "Scan error",
      severity: "medium",
      description: "Part of the security scan could not complete",
      evidence: error instanceof Error ? error.message : String(error),
      recommendation: "Do not treat this file as safe — the scan is incomplete.",
      points: 10,
    });
  }

  if (!findings.length) {
    findings.push({
      category: "Baseline",
      severity: "info",
      description: "No security rule triggered during static analysis",
      evidence: `${detection.label} · entropy ${binary.entropy}`,
      recommendation: "Static analysis cannot prove a file is safe, only that no known indicator was found.",
      points: 0,
    });
  }

  const raw = findings.reduce((sum, finding) => sum + finding.points, 0);
  const score = Math.min(100, raw);
  return { score, level: levelFromScore(score, scanComplete), findings, scanComplete };
}
