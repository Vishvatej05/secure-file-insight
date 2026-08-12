# FileGuard AI

Build: FileForensics AI — Universal File Detection, Security Analysis & AI Intelligence Platform

Build a complete full-stack application called FileForensics AI. It is an AI-powered universal file analysis platform where users can upload files with correct, missing, or incorrect extensions, and the system determines the actual file type, safely analyzes it, detects potentially harmful/suspicious characteristics, extracts readable content, and generates an AI-powered summary.

1. Core Objective

The application must follow this pipeline:

Upload File → File Validation → Safe Isolation → Real File-Type Detection → Extension Verification → Security Analysis → Content Extraction → AI Analysis → Dashboard Report

Never trust the filename or extension. Determine the actual format using file signatures/magic bytes, MIME detection, structural inspection, and format-specific validation.

Never execute, open, or dynamically load uploaded executable or potentially malicious files. All analysis must be static and sandbox-safe.

2. Supported File Categories

Design the architecture using a modular detector/extractor system so new formats can be added easily.

Support as many common formats as practically possible.

Documents

PDF, DOC, DOCX, ODT, RTF, TXT, MD, HTML, EPUB, PPT, PPTX

Data

CSV, TSV, XLS, XLSX, ODS, JSON, JSONL, XML, YAML, SQL, Parquet, Avro, Feather

Images

JPG, JPEG, PNG, GIF, BMP, TIFF, WEBP, SVG, ICO, HEIC

Audio

MP3, WAV, AAC, FLAC, OGG, M4A, WMA

Video

MP4, MKV, AVI, MOV, WEBM, MPEG, FLV

Archives

ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ

Technical/Binary

EXE, DLL, ELF, SO, JAR, CLASS, APK, WASM, SQLite and other recognizable binary formats.

The system should gracefully handle unsupported/unknown files rather than crashing.

3. File Type Detection

Implement a multi-layer detection engine:

Filename extension

MIME type

Magic bytes/file signature

File structure validation

Container detection

Format-specific validation

Confidence score

Example:

salary_report.jpg

If its contents are actually an XLSX file:

Declared Type: JPEG
Actual Type: Microsoft Excel Workbook
Extension: .jpg
Correct Extension: NO
Confidence: 99.9%
Warning: File extension does not match detected content
Recommended Extension: .xlsx


For a file with no extension:

Filename: report
Extension: None
Detected Type: PDF
Confidence: 99.8%


Never rely only on the extension.

4. File Security Analysis

Security analysis is a major feature.

Before content extraction, perform a safe static security inspection.

Detect:

Extension/content mismatch

Double extensions

Suspicious filenames

Executable files

Scripts

Macros

Embedded executables

Suspicious archive contents

Nested archives

Password-protected archives

Potentially dangerous document features

PDF JavaScript/actions

Office macros/VBA

Suspicious URLs where safely extractable

Embedded files

Obfuscated/suspicious scripts

Known malicious signatures when available

Extremely unusual file structures

Corrupted/malformed files

Polyglot-file indicators where detectable

High-risk file types

Potentially dangerous payloads

Use appropriate static-analysis libraries/tools where practical.

Do NOT execute uploaded files.

For executable files, perform metadata/static analysis only:

PE/ELF Detection
Architecture
Sections
Imports
Exports
Strings
Hashes
Metadata
Entropy indicators
Suspicious characteristics


For archives:

Archive
 ↓
Safe listing
 ↓
Inspect contained files
 ↓
Recursively detect file types
 ↓
Security analysis


Use recursion limits, file-count limits, decompression limits, and size limits to prevent archive bombs/resource exhaustion.

5. Security Risk Score

Every file should receive a security classification:

SAFE
LOW RISK
MEDIUM RISK
HIGH RISK
CRITICAL
UNKNOWN


Generate a risk score from 0–100.

Example:

Security Score: 87/100
Risk Level: HIGH

Reasons:
• Executable content detected
• Extension mismatch
• Suspicious embedded script
• High entropy section detected


The score must be explainable. Do not simply let the LLM invent a security score.

Use deterministic security rules for the primary risk calculation and optionally use AI to explain the findings.

6. Dashboard Warning System

If a file is potentially harmful or suspicious, immediately display a prominent warning on the dashboard.

Example:

⚠ SECURITY WARNING

HIGH-RISK FILE DETECTED

File: invoice.pdf

Detected Type: PDF
Risk Level: HIGH
Risk Score: 82/100

Reasons:
• PDF contains JavaScript
• Embedded external action detected
• Filename/content characteristics are suspicious

Recommended Action:
Do not open this file with an untrusted PDF viewer.


Dashboard should contain:

Total files analyzed

Safe files

Suspicious files

High-risk files

Critical files

Recent alerts

File-type distribution

Risk distribution

Security trend/history

Use clear visual indicators but don't rely only on color; include text/icons/status labels for accessibility.

7. Safe Processing Architecture

Treat every uploaded file as untrusted.

Implement:

Upload
 ↓
Temporary isolated storage
 ↓
Size/type validation
 ↓
Hash calculation
 ↓
Static detection
 ↓
Security analysis
 ↓
Safe extraction
 ↓
AI processing


Never:

execute uploaded files

import uploaded Python modules

run uploaded scripts

launch executables

render unsafe active content directly

allow arbitrary shell commands from uploaded content

Use strict timeouts and resource limits.

Delete temporary files according to a configurable retention policy.

8. Hashing

Calculate:

SHA-256

SHA-1

MD5 for identification/reference only

Display:

SHA-256:
xxxxxxxxxxxxxxxxxxxxxxxx


Use SHA-256 as the primary file identity.

Provide duplicate detection:

Same SHA-256 detected
→ Duplicate file


9. Content Extraction Engine

After safe analysis, extract readable information based on actual detected type.

PDF

Extract:

Text

Pages

Tables where possible

Metadata

Embedded images metadata

Links

Document properties

DOC/DOCX

Extract:

Paragraphs

Headings

Tables

Metadata

Hyperlinks

XLS/XLSX

Extract:

Sheet names

Columns

Rows

Data types

Statistics

Formulas where safely readable

CSV/TSV

Extract:

Columns

Rows

Data types

Missing values

Basic statistics

JSON/XML/YAML

Parse structure and create an understandable representation.

PPT/PPTX

Extract:

Slide text

Titles

Tables

Speaker notes where available

Metadata

Images

Use OCR and image understanding to extract:

Text

Objects

Scene information

Important visual information

Audio

Use speech-to-text to create a transcript, then summarize it.

Video

Use:

Audio transcription

Selected-frame analysis

Metadata extraction

Then generate a combined summary.

Archives

Safely inspect the archive and recursively analyze contained files.

10. Unknown File Handling

If the system cannot determine the format:

File Type: Unknown
Confidence: Low

Possible reasons:
• Unsupported format
• Corrupted file
• Encrypted file
• Custom binary format
• Insufficient signature information


Still provide:

File size

Hash

MIME information

Entropy/basic binary statistics

Hex/signature information where appropriate

Security findings

Never claim an unknown file is safe merely because no threat was detected.

11. AI Analysis

After extraction, normalize the content into a common internal representation.

Then send only the necessary safe extracted content to the AI layer.

AI features:

Automatic Summary

Generate:

One-line summary

Detailed summary

Key points

Important entities

Important dates

Important numbers

Topics

Action items when applicable

Ask Questions

Allow users to ask:

What is this file about?
Summarize this file.
Explain it simply.
What are the important points?
Find all important dates.
What are the main financial figures?
What are the risks mentioned?


Answers must be grounded in extracted file content.

For unsupported/binary files, explain what can and cannot be inferred.

12. AI Security Explanation

AI can explain deterministic security findings in natural language.

Example:

Security Engine:
Risk = HIGH
Reasons = PDF JavaScript + embedded action

AI Explanation:
"This PDF contains active JavaScript functionality. Although this
does not automatically prove that the file is malicious, active
content increases its security risk..."


Do not allow the AI to override the security engine's findings.

Clearly distinguish:

Detected Fact
AI Interpretation


13. Unified Analysis Result

Every analyzed file should produce a structured report:

FILE INFORMATION
----------------
Filename
Size
SHA-256
Declared Extension
MIME Type
Actual File Type
Confidence
Extension Match

SECURITY
--------
Risk Level
Risk Score
Threat Indicators
Security Findings
Recommended Actions

CONTENT
-------
Pages/Rows/Sheets/Duration/etc.
Extracted Text
Metadata
Tables
Entities

AI ANALYSIS
-----------
Short Summary
Detailed Summary
Key Points
Important Information
Questions/Answers


14. Frontend

Use:

React

TypeScript

Vite

Tailwind CSS

React Router

Create a modern cybersecurity-style dashboard.

Pages:

Dashboard

Show:

Files analyzed

Risk statistics

Recent uploads

Security alerts

File-type distribution

Recent analysis results

Upload

Drag-and-drop upload interface.

Show upload progress and processing stages:

Uploading
✓
Detecting Type
✓
Security Analysis
✓
Extracting Content
✓
AI Analysis
✓
Complete


Analysis Result

Display complete file report.

Sections:

File identity

Detected type

Extension validation

Security status

Content preview

AI summary

Metadata

Extracted tables

Findings

AI Chat

Chat with the uploaded file.

Security Alerts

List suspicious/high-risk files.

History

Show previously analyzed files.

15. Backend

Use:

Python

FastAPI

Structure the backend modularly:

backend/
├── app/
│   ├── main.py
│   ├── config.py
│   │
│   ├── api/
│   │   ├── upload.py
│   │   ├── analysis.py
│   │   ├── security.py
│   │   └── chat.py
│   │
│   ├── detection/
│   │   ├── detector.py
│   │   ├── magic.py
│   │   ├── mime.py
│   │   ├── extension.py
│   │   └── signatures.py
│   │
│   ├── security/
│   │   ├── scanner.py
│   │   ├── rules.py
│   │   ├── risk_engine.py
│   │   └── hash.py
│   │
│   ├── extractors/
│   │   ├── base.py
│   │   ├── pdf.py
│   │   ├── office.py
│   │   ├── spreadsheet.py
│   │   ├── text.py
│   │   ├── image.py
│   │   ├── audio.py
│   │   ├── video.py
│   │   ├── archive.py
│   │   └── binary.py
│   │
│   ├── ai/
│   │   ├── summarizer.py
│   │   ├── qa.py
│   │   └── prompts.py
│   │
│   ├── models/
│   └── utils/
│
├── tests/
├── requirements.txt
└── README.md


Use interfaces/base classes for detectors and extractors so new formats can be added without changing the core pipeline.

16. API

Implement clean REST APIs such as:

POST /api/files/upload
GET  /api/files
GET  /api/files/{id}
GET  /api/files/{id}/security
GET  /api/files/{id}/content
GET  /api/files/{id}/summary
POST /api/files/{id}/chat
DELETE /api/files/{id}
GET  /api/dashboard
GET  /api/alerts
GET  /health


Return structured JSON.

17. Database

Use PostgreSQL.

Store:

File
- id
- original_name
- size
- sha256
- declared_extension
- detected_type
- mime_type
- confidence
- extension_match
- risk_score
- risk_level
- status
- created_at

SecurityFinding
- id
- file_id
- category
- severity
- description
- evidence
- recommendation

Analysis
- id
- file_id
- extracted_content
- summary
- metadata
- created_at


Do not store sensitive extracted content unnecessarily. Make storage configurable.

18. AI Provider Architecture

Do not hard-code the application to one AI provider.

Create an abstraction:

AIProvider
 ├── LocalLLMProvider
 ├── OpenAIProvider
 └── GeminiProvider


Allow configuration through environment variables.

Support local LLMs where practical so sensitive documents can optionally remain local.

19. Performance

For large files:

Stream uploads where possible

Do not load huge files completely into memory

Extract incrementally

Chunk large documents

Use background processing for expensive analysis

Show progress

Enforce configurable upload limits

Enforce extraction limits

Prevent zip bombs and decompression attacks

20. Error Handling

Never crash because of an unsupported or malformed file.

Return useful messages:

Unsupported format
Corrupted file
Encrypted file
Password protected
Extraction failed
OCR unavailable
Transcription unavailable
AI processing failed
Security scan incomplete


If security scanning fails, do NOT mark the file as SAFE.

Use:

SECURITY STATUS: SCAN INCOMPLETE


21. Important Security Rule

The application itself must be designed as a secure file-analysis platform.

Implement:

File size limits

MIME validation

Magic-byte validation

Filename sanitization

Path traversal protection

Temporary isolated storage

Resource limits

Extraction limits

Archive recursion limits

Timeout handling

No arbitrary command execution

No uploaded-code execution

Secure deletion/retention policy

API authentication if required

Rate limiting

Logging

Error isolation

22. Testing

Create test files for:

Correct extensions

report.pdf
data.xlsx
photo.jpg


Missing extensions

report
data
image


Wrong extensions

report.jpg → PDF
data.txt → XLSX
image.pdf → PNG


Security tests

Use safe test fixtures to verify detection of:

executable files

scripts

macro-enabled documents

suspicious PDFs

nested archives

password-protected archives

malformed files

extension mismatches

Do not execute malicious samples during tests.

23. UX Principle

The application should make complex technical analysis understandable to normal users.

Instead of:

PE32+ x86-64 executable


show:

⚠ Executable File

This file contains Windows executable code.
It should not be opened unless you trust its source.


But preserve a Technical Details section for cybersecurity users.

24. Final Dashboard Example

FILEFORENSICS AI
────────────────────────────────────────

Files Analyzed       1,248
Safe Files             982
Suspicious              187
High Risk                63
Critical                 16

────────────────────────────────────────
SECURITY ALERTS

🔴 CRITICAL
malware_sample.exe
Executable detected
Suspicious static indicators

🟠 HIGH
invoice.pdf
Embedded JavaScript detected
Extension mismatch

🟡 MEDIUM
document.jpg
Actual type: DOCX
Incorrect extension

────────────────────────────────────────
RECENT ANALYSIS

📄 report.pdf
Type: PDF
Risk: SAFE
AI Summary: Available

📊 sales
Type: XLSX
Risk: SAFE
AI Summary: Available

🎵 meeting.mp3
Type: Audio
Risk: SAFE
Transcript: Available


25. Development Strategy

Do NOT attempt to implement every format at once.

Build in phases:

Phase 1 — Core

Upload

Hash

Magic-byte detection

MIME detection

Extension mismatch

Dashboard

Phase 2 — Documents/Data

PDF

DOCX

TXT

CSV

XLSX

JSON

XML

PPTX

Phase 3 — AI

Extraction

Summarization

Key points

Q&A

Chat with file

Phase 4 — Media

Images + OCR

Audio + transcription

Video + transcription

Phase 5 — Archives/Binaries

ZIP/RAR/7Z

EXE/DLL

ELF

JAR/APK

SQLite

Static analysis

Phase 6 — Security

Security rule engine

Risk scoring

Suspicious-file alerts

Dashboard security center

Advanced static analysis

Final Requirement

Build this as a production-quality mini-project, not a simple demo.

The central principle is:

"Never trust the extension. Detect the real file, safely inspect it, determine whether it is potentially dangerous, extract what can be safely understood, and use AI to explain the content."

The application must clearly distinguish between:

File Type Detection → Security Detection → Content Extraction → AI Understanding

Do not fake support for a format. If a format cannot be safely parsed, identify it and provide the available metadata/security analysis instead.

Start by creating the complete project structure, configuration, backend API, frontend UI, detection engine, security engine, extraction framework, AI abstraction, database models, and tests. Then implement the supported formats incrementally while keeping the application runnable after every phase.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/b8fd7ae9-a3ef-47c9-b69e-2070839d2b77).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
