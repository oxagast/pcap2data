// Controls the Conv workspace UI for conversions, hashes, decoders, and subnet tools.


const CryptoJS = require("crypto-js");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");

const threadName = "DataTools";


// ── Conv tab constants ────────────────────────────────────────────────────────

const DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD = 0.9;
const DATA_TOOLS_ENTROPY_HIGH_THRESHOLD = 6.8;
const DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD = 4.5;
const DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES = 4096;
const DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH = 12;
const DATA_TOOLS_TEXT_ENCODER = new TextEncoder();
const DATA_TOOLS_HEX_BYTE_RE = /^[0-9a-fA-F]{2}$/;

const CONV_CONVERSIONS_SUBTAB = "conversions";
const CONV_HASHES_SUBTAB = "hashes";
const CONV_DECODES_SUBTAB = "decodes";
const CONV_SUBNET_SUBTAB = "subnet";
const CONV_THREAT_INTEL_SUBTAB = "threat-intel";
const CONV_PACKET_JSON_SUBTAB = "packet-json";

const VALID_CONV_SUBTABS = [
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_DECODES_SUBTAB,
  CONV_SUBNET_SUBTAB,
  CONV_THREAT_INTEL_SUBTAB,
  CONV_PACKET_JSON_SUBTAB,
];

const HASH_IDS = [
  "data-tools-md5-output",
  "data-tools-sha1-output",
  "data-tools-sha256-output",
  "data-tools-sha384-output",
  "data-tools-sha512-output",
  "data-tools-sha3-256-output",
  "data-tools-sha3-512-output",
  "data-tools-ripemd160-output",
  "data-tools-whirlpool-output",
];

// ── Conv tab state ────────────────────────────────────────────────────────────

let activeConvSubtab = CONV_CONVERSIONS_SUBTAB;
let activeDataToolsProtoResult = null;

// ── Injected dependencies (set via initConvPanel) ─────────────────────────────

let _writeLogEntry = () => { };
let _statusUpdate = () => { };
let _setActiveMainTab = () => { };

// Initializes conv panel.
function initConvPanel({ writeLogEntry, statusUpdate, setActiveMainTab }) {
  _writeLogEntry = writeLogEntry;
  _statusUpdate = statusUpdate;
  _setActiveMainTab = setActiveMainTab;
}

// ── State accessors ───────────────────────────────────────────────────────────

function getActiveConvSubtab() {
  return activeConvSubtab;
}

// Returns active data tools proto result.
function getActiveDataToolsProtoResult() {
  return activeDataToolsProtoResult;
}

// ── Input parsing ─────────────────────────────────────────────────────────────



function parseDataToolsInput(format, rawInput) {
  if (!rawInput || rawInput.trim() === "") {
    throw new Error("Enter input data first.");
  }

  if (format === "hex") {
    // Parse forgiving hexdump-like input: ignore leading offsets, ASCII sidebars,
    // and arbitrary spacing/separators; keep only explicit 2-digit byte tokens.
    const byteTokens = [];
    const lines = rawInput.split(/\r?\n/);
    lines.forEach((line) => {
      let work = line;
      const pipeIdx = work.indexOf("|");
      if (pipeIdx !== -1) {
        work = work.slice(0, pipeIdx);
      }

      // Remove optional offset prefixes like "00000000  " or "1a3f:  ".
      work = work.replace(/^\s*[0-9a-fA-F]{1,8}:?\s{2,}/, "");

      const tokens = work.match(/(?:0x)?[0-9a-fA-F]{2}/g);
      if (tokens) {
        tokens.forEach((token) => {
          byteTokens.push(token.replace(/^0x/i, ""));
        });
      }
    });

    if (!byteTokens.length) {
      throw new Error("No hex bytes were found.");
    }
    const bytes = new Uint8Array(byteTokens.length);
    for (let i = 0; i < byteTokens.length; i += 1) {
      bytes[i] = parseInt(byteTokens[i], 16);
    }
    return bytes;
  }

  if (format === "binary") {
    const normalized = rawInput.replace(/\s+/g, "");
    if (!normalized) throw new Error("No binary bits were found.");
    if (!/^[01]+$/.test(normalized)) {
      throw new Error("Binary input can only contain 0 and 1.");
    }
    if (normalized.length % 8 !== 0) {
      throw new Error("Binary input must be grouped into full 8-bit bytes.");
    }
    const bytes = new Uint8Array(normalized.length / 8);
    for (let i = 0; i < normalized.length; i += 8) {
      bytes[i / 8] = parseInt(normalized.slice(i, i + 8), 2);
    }
    return bytes;
  }

  if (format === "base64") {
    const normalized = rawInput
      .trim()
      .replace(/^data:[^;]+;base64,/i, "")
      .replace(/\s+/g, "");
    if (!normalized) throw new Error("No base64 content was found.");
    let decoded = "";
    try {
      decoded = atob(normalized);
    } catch {
      throw new Error("Invalid base64 input.");
    }
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
      bytes[i] = decoded.charCodeAt(i);
    }
    return bytes;
  }

  if (format === "decimal") {
    const tokens = rawInput.split(/[\s,]+/).filter(Boolean);
    if (!tokens.length) throw new Error("No decimal byte values were found.");
    const values = tokens.map((token) => {
      const parsed = Number(token);
      if (!/^\d+$/.test(token) || parsed > 255) {
        throw new Error(
          "Each decimal value must be a non-negative integer between 0 and 255.",
        );
      }
      return parsed;
    });
    return Uint8Array.from(values);
  }

  // ascii / utf-8 fallback
  return new TextEncoder().encode(rawInput);
}

// Formats bytes as a hexdump with ASCII sidebar (output display).
function bytesToHexdump(bytes) {
  if (!bytes.length) return "";
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, "0");
    const hexParts = [...row].map((b) => b.toString(16).padStart(2, "0").toUpperCase());
    const group1 = hexParts.slice(0, 8).join(" ").padEnd(23, " ");
    const group2 = hexParts.slice(8, 16).join(" ").padEnd(23, " ");
    const ascii = [...row]
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${offset}  ${group1}  ${group2}  |${ascii}|`);
  }
  return lines.join("\n");
}

// Formats bytes as hex groups for input display (no ASCII sidebar).
function formatHexInputBytes(bytes) {
  if (!bytes.length) return "";
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const hexParts = [...row].map((b) =>
      b.toString(16).padStart(2, "0").toUpperCase(),
    );
    lines.push(hexParts.join(" "));
  }
  return lines.join("\n");
}

// Handles bytes to base64.
function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

// Handles bytes to printable ascii.
function bytesToPrintableAscii(bytes) {
  return [...bytes]
    .map((byte) =>
      byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".",
    )
    .join("");
}

// Handles bytes to big int decimal.
function bytesToBigIntDecimal(bytes) {
  let total = 0n;
  bytes.forEach((byte) => {
    total = (total << 8n) + BigInt(byte);
  });
  return total.toString(10);
}

// Handles calculate shannon entropy.
function calculateShannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Array(256).fill(0);
  bytes.forEach((byte) => {
    counts[byte] += 1;
  });
  let entropy = 0;
  counts.forEach((count) => {
    if (!count) return;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  });
  return entropy;
}

// Handles infer mime type.
function inferMimeType(bytes) {
  if (!bytes || !bytes.length) return "application/octet-stream";

  const startsWith = (signature) =>
    signature.every((value, index) => bytes[index] === value);
  if (startsWith([0x89, 0x50, 0x4e, 0x47])) return "image/png";
  if (startsWith([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith([0x47, 0x49, 0x46, 0x38])) return "image/gif";
  if (startsWith([0x25, 0x50, 0x44, 0x46])) return "application/pdf";
  if (startsWith([0x50, 0x4b, 0x03, 0x04])) return "application/zip";
  if (startsWith([0x1f, 0x8b])) return "application/gzip";
  if (startsWith([0x7f, 0x45, 0x4c, 0x46])) return "application/x-elf";

  const utf8Text = new TextDecoder().decode(bytes);
  const trimmed = utf8Text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "application/json";
    } catch {
      // Keep evaluating as plain text/binary.
    }
  }

  const printableChars = [...utf8Text].filter((ch) => {
    const code = ch.charCodeAt(0);
    return (
      (code >= 32 && code <= 126) || ch === "\n" || ch === "\r" || ch === "\t"
    );
  }).length;
  if (
    utf8Text.length > 0 &&
    printableChars / utf8Text.length > DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD
  ) {
    return "text/plain; charset=utf-8";
  }

  return "application/octet-stream";
}

// Returns entropy label.
function getEntropyLabel(entropy) {
  if (entropy >= DATA_TOOLS_ENTROPY_HIGH_THRESHOLD) return "High";
  if (entropy >= DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD) return "Medium";
  return "Low";
}

// ── Data type guesser ─────────────────────────────────────────────────────────

const GUESS_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GUESS_JWT_RE =
  /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;
const BASE64_VALID_PADDING_SCORE = 80;
const BASE64_MISSING_PADDING_SCORE = 50;

// Handles guess data type.
function guessDataType(rawInput) {
  const trimmed = rawInput.trim();
  if (!trimmed) return [];

  const candidates = [];

  // PGP ASCII armor
  if (/^-----BEGIN PGP/.test(trimmed)) {
    candidates.push({ label: "PGP ASCII Armored Data", score: 100 });
  }

  // bcrypt hash
  if (/^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$/.test(trimmed)) {
    candidates.push({ label: "bcrypt Hash", score: 99 });
  }

  // UUID / GUID
  if (GUESS_UUID_RE.test(trimmed)) {
    candidates.push({ label: "UUID / GUID", score: 98 });
  }

  // JWT token — three base64url segments each at least 10 chars (prevents
  // false positives like 'abc.def.ghi')
  if (GUESS_JWT_RE.test(trimmed)) {
    candidates.push({ label: "JWT Token", score: 95 });
  }

  // Hex hash / hex data (strip optional 0x prefix and colon/space separators)
  const cleanHex = trimmed
    .toLowerCase()
    .replace(/^0x/i, "")
    .replace(/[\s:]/g, "");
  const isLikelyHex = /^[0-9a-f]+$/.test(cleanHex);
  if (isLikelyHex) {
    switch (cleanHex.length) {
      case 32:
        candidates.push({ label: "MD5 / NTLM Hash", score: 90 });
        break;
      case 40:
        candidates.push({ label: "SHA-1 / RIPEMD-160 Hash", score: 90 });
        break;
      case 56:
        candidates.push({ label: "SHA-224 / SHA3-224 Hash", score: 90 });
        break;
      case 64:
        candidates.push({ label: "SHA-256 / SHA3-256 Hash", score: 90 });
        break;
      case 96:
        candidates.push({ label: "SHA-384 / SHA3-384 Hash", score: 90 });
        break;
      case 128:
        candidates.push({ label: "SHA-512 / Whirlpool Hash", score: 90 });
        break;
      default:
        if (cleanHex.length >= 8) {
          candidates.push({ label: "Hexadecimal Data", score: 55 });
        }
    }
  }

  // Base64 / Base64URL detection.
  // Skip strings already identified as hex, UUID, or JWT to avoid false
  // positives (e.g. a hex string is valid base64 by charset alone).
  const noWs = trimmed.replace(/\s+/g, "");
  const alreadySpecific =
    isLikelyHex || GUESS_UUID_RE.test(trimmed) || GUESS_JWT_RE.test(trimmed);
  if (noWs.length >= 4 && !alreadySpecific) {
    const hasUrlChars = /[-_]/.test(noWs);
    if (hasUrlChars && /^[A-Za-z0-9_-]+$/.test(noWs)) {
      // Unambiguously base64url (contains - or _)
      candidates.push({ label: "Base64URL Encoded Data", score: BASE64_VALID_PADDING_SCORE });
    } else if (/^[A-Za-z0-9+/]+=*$/.test(noWs)) {
      // Standard base64 — properly padded strings are a more confident match
      const score =
        noWs.length % 4 === 0
          ? BASE64_VALID_PADDING_SCORE
          : BASE64_MISSING_PADDING_SCORE;
      candidates.push({ label: "Base64 Encoded Data", score });
    }
  }

  candidates.sort((a, b) => b.score - a.score);
  return candidates.slice(0, 3).map((c) => ({
    label: c.label,
    confidence: c.score >= 85 ? "High" : c.score >= 60 ? "Medium" : "Low",
  }));
}

// Renders data type guesses.
function renderDataTypeGuesses(guesses) {
  const el = document.getElementById("data-tools-data-type-guesses");
  if (!el) return;
  el.innerHTML = "";
  const header = document.createElement("span");
  header.textContent = "Data Type Guesses:";
  el.appendChild(header);
  if (!guesses || guesses.length === 0) {
    const none = document.createElement("span");
    none.textContent = " None";
    el.appendChild(none);
    return;
  }
  guesses.forEach((g, i) => {
    const row = document.createElement("div");
    row.className = "data-tools-guess-item";
    row.textContent = `${i + 1}. ${g.label} (${g.confidence})`;
    el.appendChild(row);
  });
}

// ── Hash outputs ──────────────────────────────────────────────────────────────

function resetHashOutputs() {
  document.getElementById("data-tools-hash-input-reading").value = "";
  for (const id of HASH_IDS) {
    document.getElementById(id).value = "";
  }
}

// Handles bytes to char string.
function bytesToCharString(bytes) {
  const CHUNK_SIZE = 0x8000;
  let result = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    result += String.fromCharCode(...chunk);
  }
  return result;
}

// Formats hash input reading.
function formatHashInputReading(bytes) {
  return [...bytes]
    .map((byte) => {
      if (byte === 0x5c) return "\\\\";
      if (byte === 0x0a) return "\\n";
      if (byte === 0x0d) return "\\r";
      if (byte === 0x09) return "\\t";
      if (byte >= 0x20 && byte <= 0x7e) return String.fromCharCode(byte);
      return `\\x${byte.toString(16).padStart(2, "0").toUpperCase()}`;
    })
    .join("");
}

// Sets hash input reading from bytes.
function setHashInputReadingFromBytes(bytes) {
  document.getElementById("data-tools-hash-input-reading").value =
    formatHashInputReading(bytes);
}

// Computes data tools hashes.
function computeDataToolsHashes(bytes) {
  const wordArray = CryptoJS.lib.WordArray.create(bytes);
  const byteString = bytesToCharString(bytes);

  document.getElementById("data-tools-md5-output").value =
    CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha1-output").value =
    CryptoJS.SHA1(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha256-output").value =
    CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha384-output").value =
    CryptoJS.SHA384(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha512-output").value =
    CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha3-256-output").value = sha3_256(bytes);
  document.getElementById("data-tools-sha3-512-output").value = sha3_512(bytes);
  document.getElementById("data-tools-ripemd160-output").value =
    CryptoJS.RIPEMD160(wordArray).toString(CryptoJS.enc.Hex);
  const whirlpoolHash =
    bytes.length > 0 ? whirlpool.encSync(byteString, "hex") : "";
  document.getElementById("data-tools-whirlpool-output").value = whirlpoolHash;
}
// we need to use 

function runDataToolsHashesFromInput() {
  const hashInput = document.getElementById("data-tools-hash-input-reading").value;
  const bytes = parseHashInputReadingBytes(hashInput);
  computeDataToolsHashes(bytes);
}

function getSelectedHashValue() {
  const activeEl = document.activeElement;
  if (activeEl && HASH_IDS.includes(activeEl.id)) {
    return activeEl.value.trim() || "";
  }
  return "";
}

function crossReferenceCurrentHash(runThreatIntelHashLookup) {
  const selectedHash = getSelectedHashValue();
  const hashValue = selectedHash
    || document.getElementById("data-tools-sha256-output")?.value.trim();
  if (!hashValue) {
    _statusUpdate("Status: Generate a hash first to cross-reference it.");
    return;
  }
  _writeLogEntry(`[${threadName}] Cross-referencing hash in Threat Intel: ${hashValue}`);
  setConvSubtab(CONV_THREAT_INTEL_SUBTAB);
  if (typeof runThreatIntelHashLookup === "function") {
    runThreatIntelHashLookup(hashValue);
  }
}

// Parses hash input reading bytes.
function parseHashInputReadingBytes(input) {
  const bytes = [];
  let plainStart = 0;
  const flushPlain = (end) => {
    if (end <= plainStart) return;
    bytes.push(...DATA_TOOLS_TEXT_ENCODER.encode(input.slice(plainStart, end)));
  };

  for (let i = 0; i < input.length; i++) {
    if (input[i] !== "\\") continue;
    flushPlain(i);
    const next = input[i + 1];
    if (next === "n") {
      bytes.push(0x0a);
      i += 1;
    } else if (next === "r") {
      bytes.push(0x0d);
      i += 1;
    } else if (next === "t") {
      bytes.push(0x09);
      i += 1;
    } else if (next === "\\") {
      bytes.push(0x5c);
      i += 1;
    } else if (
      next === "x" &&
      i + 3 < input.length &&
      DATA_TOOLS_HEX_BYTE_RE.test(input.slice(i + 2, i + 4))
    ) {
      bytes.push(parseInt(input.slice(i + 2, i + 4), 16));
      i += 3;
    } else {
      bytes.push(0x5c);
    }
    plainStart = i + 1;
  }

  flushPlain(input.length);
  return new Uint8Array(bytes);
}

// ── Conversions panel ─────────────────────────────────────────────────────────

function resetDataToolsOutputs() {
  document.getElementById("data-tools-hex-output").value = "";
  document.getElementById("data-tools-binary-output").value = "";
  document.getElementById("data-tools-decimal-output").value = "";
  document.getElementById("data-tools-decimal-integer-output").value = "";
  document.getElementById("data-tools-ascii-output").value = "";
  document.getElementById("data-tools-base64-output").value = "";
  document.getElementById("data-tools-byte-length").textContent =
    "Byte Length: 0";
  document.getElementById("data-tools-mime-type").textContent =
    "MIME Type: Unknown";
  renderDataTypeGuesses([]);
  document.getElementById("data-tools-entropy").textContent =
    "Shannon Entropy: 0.00 (Low)";
  resetHashOutputs();
  clearProtoDecoderOutput();
}

// Runs data tools conversion.
function runDataToolsConversion() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const errorEl = document.getElementById("data-tools-error");

  try {
    const bytes = parseDataToolsInput(formatEl.value, inputEl.value);
    if (formatEl.value === "hex") {
      inputEl.value = formatHexInputBytes(bytes);
    }
    const hexDump = bytesToHexdump(bytes);
    const binarySpaced = [...bytes]
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join(" ");
    const decimalBytes = [...bytes].join(" ");
    const asciiPreview = bytesToPrintableAscii(bytes);
    const base64Value = bytesToBase64(bytes);
    const entropy = calculateShannonEntropy(bytes);
    const entropyLabel = getEntropyLabel(entropy);
    const decimalInteger =
      bytes.length > DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES
        ? `Input exceeds ${DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES} bytes for decimal integer display`
        : bytesToBigIntDecimal(bytes);

    document.getElementById("data-tools-hex-output").value = hexDump;
    document.getElementById("data-tools-binary-output").value = binarySpaced;
    document.getElementById("data-tools-decimal-output").value = decimalBytes;
    document.getElementById("data-tools-decimal-integer-output").value =
      decimalInteger;
    document.getElementById("data-tools-ascii-output").value = asciiPreview;
    document.getElementById("data-tools-base64-output").value = base64Value;
    document.getElementById("data-tools-byte-length").textContent =
      `Byte Length: ${bytes.length}`;
    document.getElementById("data-tools-mime-type").textContent =
      `MIME Type: ${inferMimeType(bytes)}`;
    renderDataTypeGuesses(guessDataType(inputEl.value));
    document.getElementById("data-tools-entropy").textContent =
      `Shannon Entropy: ${entropy.toFixed(2)} (${entropyLabel})`;
    errorEl.textContent = "";
    setHashInputReadingFromBytes(bytes);
    computeDataToolsHashes(bytes);
    runProtoDecoder(bytes);
  } catch (error) {
    resetDataToolsOutputs();
    errorEl.textContent =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
  }
}

// ── Protocol decoders for the Conv tab ───────────────────────────────────────

function decodeHttpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/);
  if (!lines.length) return null;
  const requestPattern = /^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/;
  const responsePattern = /^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)/;
  const isHttpStartLine = (line) => requestPattern.test(line) || responsePattern.test(line);

  const startIndexes = [];
  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim();
    if (trimmed && isHttpStartLine(trimmed)) {
      startIndexes.push(index);
    }
  });
  if (!startIndexes.length) return null;

  const fields = [];
  const maxBlocks = 25;
  for (let blockIndex = 0; blockIndex < startIndexes.length && blockIndex < maxBlocks; blockIndex += 1) {
    const startLineIndex = startIndexes[blockIndex];
    const nextStartLineIndex =
      blockIndex + 1 < startIndexes.length ? startIndexes[blockIndex + 1] : lines.length;
    const firstLine = (lines[startLineIndex] || "").trim();
    const requestMatch = firstLine.match(requestPattern);
    const responseMatch = firstLine.match(responsePattern);
    if (!requestMatch && !responseMatch) continue;

    const headerEndIndex = lines
      .slice(startLineIndex + 1, nextStartLineIndex)
      .findIndex((line) => line.trim() === "");
    const absoluteHeaderEndIndex =
      headerEndIndex >= 0
        ? startLineIndex + 1 + headerEndIndex
        : nextStartLineIndex;
    const headerLines = lines.slice(startLineIndex + 1, absoluteHeaderEndIndex);
    const headers = {};
    headerLines.forEach((headerLine) => {
      const separatorIndex = headerLine.indexOf(":");
      if (separatorIndex > 0) {
        headers[headerLine.slice(0, separatorIndex).trim()] =
          headerLine.slice(separatorIndex + 1).trim();
      }
    });

    fields.push({ name: `Block ${blockIndex + 1}`, value: requestMatch ? "HTTP Request" : "HTTP Response" });
    if (requestMatch) {
      fields.push(
        { name: "Type", value: "Request" },
        { name: "Method", value: requestMatch[1] },
        { name: "URL", value: requestMatch[2] },
        { name: "Version", value: requestMatch[3] },
      );
      [
        "Host",
        "User-Agent",
        "Content-Type",
        "Content-Length",
        "Accept",
        "Accept-Encoding",
        "Connection",
        "Authorization",
        "Referer",
        "Cookie",
      ].forEach((headerName) => {
        if (headers[headerName]) fields.push({ name: headerName, value: headers[headerName] });
      });
    } else {
      fields.push(
        { name: "Type", value: "Response" },
        { name: "Version", value: responseMatch[1] },
        { name: "Status Code", value: responseMatch[2] },
        { name: "Status Message", value: responseMatch[3] || "—" },
      );
      [
        "Server",
        "Content-Type",
        "Content-Length",
        "Content-Encoding",
        "Transfer-Encoding",
        "Connection",
        "Location",
        "Set-Cookie",
        "Cache-Control",
        "Date",
      ].forEach((headerName) => {
        if (headers[headerName]) fields.push({ name: headerName, value: headers[headerName] });
      });
    }

    const bodyStartIndex = absoluteHeaderEndIndex < nextStartLineIndex
      ? absoluteHeaderEndIndex + 1
      : absoluteHeaderEndIndex;
    if (bodyStartIndex < nextStartLineIndex) {
      const bodyPreview = lines
        .slice(bodyStartIndex, nextStartLineIndex)
        .join("\n")
        .trim();
      if (bodyPreview) {
        fields.push({
          name: "Body (preview)",
          value: bodyPreview.length > 200 ? bodyPreview.slice(0, 200) + "…" : bodyPreview,
        });
      }
    }
  }

  if (startIndexes.length > maxBlocks) {
    fields.push({
      name: "Notice",
      value: `Showing first ${maxBlocks} HTTP blocks out of ${startIndexes.length}.`,
    });
  }

  if (!fields.length) return null;
  return { protocol: "HTTP", fields };
}

// Handles decode telnet from bytes.
function decodeTelnetFromBytes(bytes) {
  const IAC = 0xff;
  const WILL = 0xfb,
    WONT = 0xfc,
    DO = 0xfd,
    DONT = 0xfe;
  const SB = 0xfa,
    SE = 0xf0;
  const optionNames = {
    0: "Binary",
    1: "Echo",
    3: "Suppress Go Ahead",
    5: "Status",
    24: "Terminal Type",
    31: "Window Size",
    32: "Terminal Speed",
    34: "Linemode",
    39: "New Environment",
  };
  const negotiations = [];
  let text = "";
  let i = 0;
  let hasIac = false;
  while (i < bytes.length) {
    if (bytes[i] === IAC) {
      hasIac = true;
      i++;
      if (i >= bytes.length) break;
      const cmd = bytes[i++];
      if (cmd === WILL || cmd === WONT || cmd === DO || cmd === DONT) {
        if (i < bytes.length) {
          const opt = bytes[i++];
          const cmdName =
            cmd === WILL
              ? "WILL"
              : cmd === WONT
                ? "WONT"
                : cmd === DO
                  ? "DO"
                  : "DONT";
          negotiations.push(`${cmdName} ${optionNames[opt] ?? `Option ${opt}`}`);
        }
      } else if (cmd === SB) {
        while (i < bytes.length) {
          if (bytes[i] === IAC && i + 1 < bytes.length && bytes[i + 1] === SE) {
            i += 2;
            break;
          }
          i++;
        }
      }
    } else {
      const b = bytes[i++];
      if (b >= 32 && b < 127) text += String.fromCharCode(b);
      else if (b === 10) text += "\n";
      else if (b === 13) text += "\r";
    }
  }
  if (!hasIac && !text.trim()) return null;
  const fields = [];
  if (negotiations.length) {
    fields.push({ name: "Negotiations", value: negotiations.join(", ") });
  }
  if (text.trim()) {
    const t = text.trim();
    fields.push({
      name: "Text",
      value: t.length > 500 ? t.slice(0, 500) + "…" : t,
    });
  }
  if (!fields.length) return null;
  return { protocol: "Telnet", fields };
}

// Handles decode ssh from bytes.
function decodeSshFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, 512),
  );
  const bannerMatch = text.match(/^SSH-([\S]+)\r?\n/);
  if (!bannerMatch) return null;
  const versionStr = bannerMatch[1];
  const dashIdx = versionStr.indexOf("-");
  const protocolVersion =
    dashIdx >= 0 ? versionStr.slice(0, dashIdx) : versionStr;
  const softwareVersion = dashIdx >= 0 ? versionStr.slice(dashIdx + 1) : "—";
  const fields = [
    { name: "Protocol Version", value: protocolVersion },
    { name: "Software Version", value: softwareVersion },
  ];
  const bannerEnd = text.indexOf("\n");
  if (bannerEnd > 0 && bytes.length > bannerEnd + 1) {
    fields.push({
      name: "Additional Data",
      value: `${bytes.length - bannerEnd - 1} bytes (key exchange)`,
    });
  }
  return { protocol: "SSH / OpenSSH", fields };
}

// Handles decode pop3 from bytes.
function decodePop3FromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const POP3_COMMANDS = new Set([
    "USER",
    "PASS",
    "STAT",
    "LIST",
    "RETR",
    "DELE",
    "NOOP",
    "RSET",
    "QUIT",
    "APOP",
    "TOP",
    "UIDL",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    if (line.startsWith("+OK")) {
      fields.push({ name: "Response", value: "+OK" });
      const msg = line.slice(3).trim();
      if (msg) fields.push({ name: "Message", value: msg });
      detected = true;
    } else if (line.startsWith("-ERR")) {
      fields.push({ name: "Response", value: "-ERR" });
      const msg = line.slice(4).trim();
      if (msg) fields.push({ name: "Error", value: msg });
      detected = true;
    } else {
      const parts = line.split(/\s+/);
      const cmd = parts[0].toUpperCase();
      if (POP3_COMMANDS.has(cmd)) {
        fields.push({ name: "Command", value: cmd });
        if (parts.length > 1) {
          fields.push({ name: "Argument", value: parts.slice(1).join(" ") });
        }
        detected = true;
      }
    }
  }
  if (!detected) return null;
  return { protocol: "POP3", fields };
}

// Handles decode imap from bytes.
function decodeImapFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const IMAP_STATUSES = new Set(["OK", "NO", "BAD", "PREAUTH", "BYE"]);
  const IMAP_COMMANDS = new Set([
    "CAPABILITY",
    "NOOP",
    "LOGOUT",
    "AUTHENTICATE",
    "LOGIN",
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
    "IDLE",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    if (line.startsWith("* ")) {
      const val = line.slice(2).trim();
      fields.push({
        name: "Untagged",
        value: val.length > 100 ? val.slice(0, 100) + "…" : val,
      });
      detected = true;
    } else if (line.startsWith("+ ")) {
      fields.push({ name: "Continuation", value: line.slice(2).trim() });
      detected = true;
    } else {
      const m = line.match(/^(\S+)\s+(\S+)\s*(.*)/);
      if (m) {
        const tag = m[1];
        const word = m[2].toUpperCase();
        const rest = m[3];
        if (IMAP_STATUSES.has(word)) {
          const val = `${word} ${rest}`.trim();
          fields.push({
            name: `[${tag}] Status`,
            value: val.length > 100 ? val.slice(0, 100) + "…" : val,
          });
          detected = true;
        } else if (IMAP_COMMANDS.has(word)) {
          fields.push({ name: `[${tag}] Command`, value: word });
          if (rest) {
            fields.push({
              name: "Arguments",
              value: rest.length > 100 ? rest.slice(0, 100) + "…" : rest,
            });
          }
          detected = true;
        }
      }
    }
  }
  if (!detected) return null;
  return { protocol: "IMAP", fields };
}

// Handles decode smtp from bytes.
function decodeSmtpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const SMTP_COMMANDS = new Set([
    "HELO",
    "EHLO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "VRFY",
    "EXPN",
    "NOOP",
    "QUIT",
    "AUTH",
    "STARTTLS",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    const rm = line.match(/^(\d{3})([\s-])(.*)/);
    if (rm) {
      const label = `Response ${rm[1]}${rm[2] === "-" ? " (cont.)" : ""}`;
      fields.push({ name: label, value: rm[3] });
      detected = true;
    } else {
      const parts = line.split(/\s+/);
      const cmd = parts[0].toUpperCase();
      if (SMTP_COMMANDS.has(cmd)) {
        fields.push({ name: "Command", value: cmd });
        if (parts.length > 1) {
          const arg = parts.slice(1).join(" ");
          fields.push({
            name: "Argument",
            value: arg.length > 100 ? arg.slice(0, 100) + "…" : arg,
          });
        }
        detected = true;
      }
    }
  }
  if (!detected) return null;
  return { protocol: "SMTP", fields };
}

// Handles decode ftp from bytes.
function decodeFtpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (!lines.length) return null;

  const FTP_COMMANDS = new Set([
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "PWD",
    "TYPE",
    "PASV",
    "EPSV",
    "PORT",
    "EPRT",
    "LIST",
    "NLST",
    "RETR",
    "STOR",
    "DELE",
    "RNFR",
    "RNTO",
    "MKD",
    "RMD",
    "SYST",
    "STAT",
    "FEAT",
    "AUTH",
    "QUIT",
    "NOOP",
  ]);

  const fields = [];
  let detected = false;
  for (const line of lines) {
    const responseMatch = line.match(/^(\d{3})([\s-])(.*)/);
    if (responseMatch) {
      const code = responseMatch[1];
      const suffix = responseMatch[2] === "-" ? " (cont.)" : "";
      fields.push({
        name: `Response ${code}${suffix}`,
        value: responseMatch[3] || "—",
      });
      detected = true;
    } else {
      const parts = line.trim().split(/\s+/);
      const command = (parts[0] || "").toUpperCase();
      if (FTP_COMMANDS.has(command)) {
        fields.push({ name: "Command", value: command });
        if (parts.length > 1) {
          const argument = parts.slice(1).join(" ");
          fields.push({
            name: "Argument",
            value: argument.length > 160 ? argument.slice(0, 160) + "…" : argument,
          });
        }
        detected = true;
      }
    }
  }

  if (!detected) return null;
  return { protocol: "FTP", fields };
}

function parseAsn1Length(buffer, startIndex, endIndex, enforceDer = false) {
  if (!(buffer instanceof Uint8Array)) return null;
  if (startIndex >= endIndex) return null;
  const firstByte = buffer[startIndex];
  if ((firstByte & 0x80) === 0) {
    return { length: firstByte, nextIndex: startIndex + 1 };
  }

  const octetCount = firstByte & 0x7f;
  if (octetCount === 0 || octetCount > 4) return null;
  if (startIndex + octetCount >= endIndex) return null;

  if (enforceDer && octetCount === 1 && buffer[startIndex + 1] < 0x80) {
    return null;
  }

  let length = 0;
  for (let offset = 1; offset <= octetCount; offset += 1) {
    const byteValue = buffer[startIndex + offset];
    if (enforceDer && offset === 1 && byteValue === 0x00) {
      return null;
    }
    length = (length << 8) | byteValue;
  }
  return {
    length,
    nextIndex: startIndex + 1 + octetCount,
  };
}

function decodeLdapFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;

  const LDAP_OPERATIONS = {
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x62: "UnbindRequest",
    0x63: "SearchRequest",
    0x64: "SearchResEntry",
    0x65: "SearchResDone",
    0x66: "SearchResRef",
    0x67: "ModifyRequest",
    0x68: "ModifyResponse",
    0x69: "AddRequest",
    0x6a: "AddResponse",
    0x6b: "DelRequest",
    0x6c: "DelResponse",
    0x6d: "ModDNRequest",
    0x6e: "ModDNResponse",
    0x6f: "CompareRequest",
    0x70: "CompareResponse",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
    0x79: "IntermediateResponse",
  };

  try {
    const fields = [];
    const maxMessages = 100;
    let parsedMessages = 0;
    let index = 0;

    while (index < bytes.length && parsedMessages < maxMessages) {
      while (index < bytes.length && bytes[index] !== 0x30) {
        index += 1;
      }
      if (index >= bytes.length) break;

      const sequenceStart = index;
      const sequenceLengthInfo = parseAsn1Length(bytes, sequenceStart + 1, bytes.length);
      if (!sequenceLengthInfo) {
        index = sequenceStart + 1;
        continue;
      }

      const sequenceValueStart = sequenceLengthInfo.nextIndex;
      const sequenceEnd = sequenceValueStart + sequenceLengthInfo.length;
      if (sequenceEnd > bytes.length) break;

      let cursor = sequenceValueStart;
      if (cursor >= sequenceEnd || bytes[cursor] !== 0x02) {
        index = sequenceStart + 1;
        continue;
      }

      const messageIdLengthInfo = parseAsn1Length(bytes, cursor + 1, sequenceEnd);
      if (!messageIdLengthInfo) {
        index = sequenceStart + 1;
        continue;
      }

      const messageIdStart = messageIdLengthInfo.nextIndex;
      const messageIdEnd = messageIdStart + messageIdLengthInfo.length;
      if (messageIdLengthInfo.length < 1 || messageIdEnd > sequenceEnd) {
        index = sequenceStart + 1;
        continue;
      }

      let messageId = 0;
      for (let offset = messageIdStart; offset < messageIdEnd; offset += 1) {
        messageId = (messageId << 8) | bytes[offset];
      }

      cursor = messageIdEnd;
      if (cursor >= sequenceEnd) {
        index = Math.max(sequenceEnd, sequenceStart + 1);
        continue;
      }

      const operationTag = bytes[cursor];
      if (operationTag < 0x60 || operationTag > 0x7f) {
        index = sequenceStart + 1;
        continue;
      }

      parsedMessages += 1;
      fields.push(
        { name: `Message ${parsedMessages} ID`, value: String(messageId) },
        {
          name: `Message ${parsedMessages} Operation`,
          value:
            LDAP_OPERATIONS[operationTag] ||
            `0x${operationTag.toString(16).padStart(2, "0").toUpperCase()}`,
        },
      );

      index = Math.max(sequenceEnd, sequenceStart + 1);
    }

    if (!fields.length) return null;
    if (parsedMessages >= maxMessages && index < bytes.length) {
      fields.push({
        name: "Notice",
        value: `Showing first ${maxMessages} LDAP messages from stream.`,
      });
    }

    return {
      protocol: "LDAP",
      fields,
    };
  } catch {
    return null;
  }
}

function getAsn1TagDescription(tagByte) {
  const tagClass = (tagByte & 0xc0) >> 6;
  const classLabel = ["Universal", "Application", "Context-specific", "Private"][tagClass] || "Unknown";
  const constructed = Boolean(tagByte & 0x20);
  const tagNumber = tagByte & 0x1f;
  return {
    classLabel,
    constructed,
    tagNumber,
    tagHex: `0x${tagByte.toString(16).padStart(2, "0").toUpperCase()}`,
  };
}

function decodeAsn1GenericFromBytes(bytes, { encodingLabel = "BER", enforceDer = false } = {}) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

  const fields = [];
  const maxNodes = 100;
  let parsedNodes = 0;
  let index = 0;

  while (index < bytes.length && parsedNodes < maxNodes) {
    const tagByte = bytes[index];
    const lengthInfo = parseAsn1Length(bytes, index + 1, bytes.length, enforceDer);
    if (!lengthInfo) {
      index += 1;
      continue;
    }

    const valueStart = lengthInfo.nextIndex;
    const valueEnd = valueStart + lengthInfo.length;
    if (valueEnd > bytes.length) break;

    parsedNodes += 1;
    const tagInfo = getAsn1TagDescription(tagByte);
    fields.push(
      {
        name: `Node ${parsedNodes} Tag`,
        value: `${tagInfo.tagHex} (${tagInfo.classLabel}, ${tagInfo.constructed ? "Constructed" : "Primitive"}, #${tagInfo.tagNumber})`,
      },
      { name: `Node ${parsedNodes} Length`, value: String(lengthInfo.length) },
    );

    if (lengthInfo.length > 0) {
      const previewBytes = bytes.slice(valueStart, Math.min(valueEnd, valueStart + 32));
      const previewHex = Array.from(previewBytes, (byteValue) =>
        byteValue.toString(16).padStart(2, "0"),
      ).join(" ");
      fields.push({
        name: `Node ${parsedNodes} Value (hex preview)`,
        value: valueEnd - valueStart > 32 ? `${previewHex} …` : previewHex,
      });
    }

    index = Math.max(valueEnd, index + 1);
  }

  if (!fields.length) return null;
  if (parsedNodes >= maxNodes && index < bytes.length) {
    fields.push({
      name: "Notice",
      value: `Showing first ${maxNodes} ASN.1 nodes from stream.`,
    });
  }
  return {
    protocol: `ASN.1 ${encodingLabel}`,
    fields,
  };
}

function decodeBerFromBytes(bytes) {
  return decodeAsn1GenericFromBytes(bytes, { encodingLabel: "BER", enforceDer: false });
}

function decodeDerFromBytes(bytes) {
  return decodeAsn1GenericFromBytes(bytes, { encodingLabel: "DER", enforceDer: true });
}

function parseSimpleYamlScalar(valueText) {
  const text = String(valueText || "").trim();
  if (text === "") return "";
  if (/^(true|false)$/i.test(text)) return /^true$/i.test(text);
  if (/^(null|~)$/i.test(text)) return null;
  if (/^[+-]?\d+$/.test(text)) {
    const parsedInt = Number.parseInt(text, 10);
    if (Number.isFinite(parsedInt)) return parsedInt;
  }
  if (/^[+-]?(?:\d+\.\d+|\d+\.\d*|\.\d+)$/.test(text)) {
    const parsedFloat = Number.parseFloat(text);
    if (Number.isFinite(parsedFloat)) return parsedFloat;
  }
  if (
    (text.startsWith('"') && text.endsWith('"')) ||
    (text.startsWith("'") && text.endsWith("'"))
  ) {
    return text.slice(1, -1);
  }
  return text;
}

function parseSimpleYamlKeyValue(content) {
  const separatorIndex = content.indexOf(":");
  if (separatorIndex <= 0) return null;
  const key = content.slice(0, separatorIndex).trim().replace(/^['"]|['"]$/g, "");
  if (!key) return null;
  const rawValue = content.slice(separatorIndex + 1);
  const hasInlineValue = rawValue.trim().length > 0;
  return {
    key,
    hasInlineValue,
    value: hasInlineValue ? parseSimpleYamlScalar(rawValue) : null,
  };
}

function parseSimpleYamlToObject(rawText) {
  if (typeof rawText !== "string") return null;
  const sourceLines = rawText.split(/\r?\n/);
  const lines = sourceLines
    .map((line) => line.replace(/\t/g, "  "))
    .filter((line) => {
      const trimmed = line.trim();
      return (
        trimmed &&
        !trimmed.startsWith("#") &&
        trimmed !== "---" &&
        trimmed !== "..."
      );
    })
    .map((line) => ({
      indent: (line.match(/^\s*/) || [""])[0].length,
      content: line.trim(),
    }));
  if (!lines.length) return null;

  function parseBlock(startIndex, expectedIndent) {
    if (startIndex >= lines.length) return { value: null, nextIndex: startIndex };

    const startsWithList = lines[startIndex].content.startsWith("-");
    if (startsWithList) {
      const resultList = [];
      let index = startIndex;
      while (index < lines.length) {
        const line = lines[index];
        if (line.indent < expectedIndent || !line.content.startsWith("-")) break;
        if (line.indent > expectedIndent) {
          index += 1;
          continue;
        }

        const itemText = line.content.replace(/^-\s?/, "").trim();
        if (!itemText) {
          const nextLine = lines[index + 1];
          if (nextLine && nextLine.indent > line.indent) {
            const nested = parseBlock(index + 1, nextLine.indent);
            resultList.push(nested.value);
            index = nested.nextIndex;
            continue;
          }
          resultList.push(null);
          index += 1;
          continue;
        }

        const maybeKv = parseSimpleYamlKeyValue(itemText);
        if (maybeKv) {
          const itemObject = { [maybeKv.key]: maybeKv.value };
          if (!maybeKv.hasInlineValue) {
            const nextLine = lines[index + 1];
            if (nextLine && nextLine.indent > line.indent) {
              const nested = parseBlock(index + 1, nextLine.indent);
              itemObject[maybeKv.key] = nested.value;
              index = nested.nextIndex;
            } else {
              index += 1;
            }
          } else {
            index += 1;
          }

          while (index < lines.length && lines[index].indent > line.indent) {
            const siblingLine = lines[index];
            if (siblingLine.content.startsWith("-")) break;
            const siblingKv = parseSimpleYamlKeyValue(siblingLine.content);
            if (!siblingKv) break;
            if (!siblingKv.hasInlineValue) {
              const nestedLine = lines[index + 1];
              if (nestedLine && nestedLine.indent > siblingLine.indent) {
                const nested = parseBlock(index + 1, nestedLine.indent);
                itemObject[siblingKv.key] = nested.value;
                index = nested.nextIndex;
              } else {
                itemObject[siblingKv.key] = null;
                index += 1;
              }
            } else {
              itemObject[siblingKv.key] = siblingKv.value;
              index += 1;
            }
          }

          resultList.push(itemObject);
          continue;
        }

        resultList.push(parseSimpleYamlScalar(itemText));
        index += 1;
      }

      return {
        value: resultList,
        nextIndex: index,
      };
    }

    const resultObject = {};
    let index = startIndex;
    while (index < lines.length) {
      const line = lines[index];
      if (line.indent < expectedIndent) break;
      if (line.indent > expectedIndent) {
        index += 1;
        continue;
      }
      if (line.content.startsWith("-")) break;

      const maybeKv = parseSimpleYamlKeyValue(line.content);
      if (!maybeKv) {
        index += 1;
        continue;
      }

      if (maybeKv.hasInlineValue) {
        resultObject[maybeKv.key] = maybeKv.value;
        index += 1;
        continue;
      }

      const nextLine = lines[index + 1];
      if (nextLine && nextLine.indent > line.indent) {
        const nested = parseBlock(index + 1, nextLine.indent);
        resultObject[maybeKv.key] = nested.value;
        index = nested.nextIndex;
      } else {
        resultObject[maybeKv.key] = null;
        index += 1;
      }
    }

    return {
      value: resultObject,
      nextIndex: index,
    };
  }

  const parsed = parseBlock(0, lines[0].indent).value;
  return parsed;
}

function parseXmlElementToTreeObject(element, depth = 0) {
  if (!(element instanceof Element)) return null;
  if (depth > 40) return "[max-depth]";

  const nodeObject = {};
  const attributes = Array.from(element.attributes || []);
  if (attributes.length) {
    nodeObject["@attributes"] = {};
    attributes.forEach((attr) => {
      nodeObject["@attributes"][attr.name] = attr.value;
    });
  }

  const textNodes = Array.from(element.childNodes || [])
    .filter((node) => node.nodeType === Node.TEXT_NODE)
    .map((node) => (node.textContent || "").trim())
    .filter(Boolean);
  if (textNodes.length) {
    nodeObject["#text"] = textNodes.join(" ");
  }

  const childElements = Array.from(element.children || []);
  childElements.forEach((child) => {
    const childValue = parseXmlElementToTreeObject(child, depth + 1);
    if (nodeObject[child.tagName] === undefined) {
      nodeObject[child.tagName] = childValue;
      return;
    }
    if (!Array.isArray(nodeObject[child.tagName])) {
      nodeObject[child.tagName] = [nodeObject[child.tagName]];
    }
    nodeObject[child.tagName].push(childValue);
  });

  if (!Object.keys(nodeObject).length) return "";
  return nodeObject;
}

function formatDataTreeLeafValue(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function getDataTreeBranchSummary(value) {
  if (Array.isArray(value)) return `[${value.length}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).length}}`;
  return "";
}

function createDataTreeNode(label, value, depth = 0) {
  const isBranch =
    Array.isArray(value) || (value !== null && typeof value === "object");

  if (!isBranch) {
    const leaf = document.createElement("div");
    leaf.className = "data-tools-tree-leaf";

    const keySpan = document.createElement("span");
    keySpan.className = "data-tools-tree-key";
    keySpan.textContent = `${label}: `;

    const valueSpan = document.createElement("span");
    valueSpan.className = "data-tools-tree-value";
    valueSpan.textContent = formatDataTreeLeafValue(value);

    leaf.appendChild(keySpan);
    leaf.appendChild(valueSpan);
    return leaf;
  }

  const details = document.createElement("details");
  details.className = "data-tools-tree-branch";
  details.open = depth < 2;

  const summary = document.createElement("summary");
  summary.className = "data-tools-tree-summary";

  const keySpan = document.createElement("span");
  keySpan.className = "data-tools-tree-key";
  keySpan.textContent = label;

  const metaSpan = document.createElement("span");
  metaSpan.className = "data-tools-tree-meta";
  metaSpan.textContent = ` ${getDataTreeBranchSummary(value)}`;

  summary.appendChild(keySpan);
  summary.appendChild(metaSpan);
  details.appendChild(summary);

  const children = document.createElement("div");
  children.className = "data-tools-tree-children";
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      children.appendChild(createDataTreeNode(`[${index}]`, item, depth + 1));
    });
    if (!value.length) {
      children.appendChild(createDataTreeNode("(empty)", "", depth + 1));
    }
  } else {
    const keys = Object.keys(value);
    keys.forEach((key) => {
      children.appendChild(createDataTreeNode(key, value[key], depth + 1));
    });
    if (!keys.length) {
      children.appendChild(createDataTreeNode("(empty)", "", depth + 1));
    }
  }
  details.appendChild(children);
  return details;
}

function renderStructuredDecoderTree(protoOutput, result) {
  if (!protoOutput || !result || !result.treeData) return false;
  const treeFormats = new Set(["JSON", "XML", "YAML"]);
  if (!treeFormats.has(result.protocol)) return false;

  const wrapper = document.createElement("div");
  wrapper.className = "data-tools-structured-tree";

  const title = document.createElement("div");
  title.className = "data-tools-tree-title";
  title.textContent = `${result.protocol} Data Tree`;
  wrapper.appendChild(title);

  const treeRoot = createDataTreeNode("root", result.treeData, 0);
  wrapper.appendChild(treeRoot);
  protoOutput.appendChild(wrapper);
  return true;
}

function decodeJsonFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
  if (!rawText) return null;
  if (!rawText.startsWith("{") && !rawText.startsWith("[")) return null;

  try {
    const parsed = JSON.parse(rawText);
    const pretty = JSON.stringify(parsed, null, 2) || "";
    const fields = [];
    if (Array.isArray(parsed)) {
      fields.push({ name: "Type", value: "Array" });
      fields.push({ name: "Items", value: String(parsed.length) });
    } else if (parsed && typeof parsed === "object") {
      const keys = Object.keys(parsed);
      fields.push({ name: "Type", value: "Object" });
      fields.push({ name: "Top-level keys", value: keys.length ? keys.join(", ") : "(none)" });
    } else {
      fields.push({ name: "Type", value: typeof parsed });
    }
    fields.push({
      name: "Pretty JSON",
      value: pretty.length > 2000 ? `${pretty.slice(0, 2000)}…` : pretty,
    });
    return { protocol: "JSON", fields, treeData: parsed };
  } catch {
    return null;
  }
}

function decodeXmlFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
  if (!rawText) return null;
  if (!rawText.startsWith("<")) return null;

  try {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(rawText, "application/xml");
    const parserError = xmlDoc.querySelector("parsererror");
    if (parserError) return null;

    const rootTag = xmlDoc.documentElement?.tagName || "(none)";
    const childCount = xmlDoc.documentElement?.childElementCount || 0;
    const attrs = Array.from(xmlDoc.documentElement?.attributes || []).map((attr) => `${attr.name}=${JSON.stringify(attr.value)}`);
    const treeData = {
      [rootTag]: parseXmlElementToTreeObject(xmlDoc.documentElement, 0),
    };
    const fields = [
      { name: "Root Element", value: rootTag },
      { name: "Child Elements", value: String(childCount) },
      { name: "Root Attributes", value: attrs.length ? attrs.join(", ") : "(none)" },
      {
        name: "Preview",
        value: rawText.length > 2000 ? `${rawText.slice(0, 2000)}…` : rawText,
      },
    ];
    return { protocol: "XML", fields, treeData };
  } catch {
    return null;
  }
}

function decodeYamlFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const trimmed = rawText.trim();
  if (!trimmed) return null;

  const lines = rawText
    .split(/\r?\n/)
    .map((line) => line.replace(/\t/g, "  "))
    .filter((line) => line.trim() && !line.trimStart().startsWith("#"));
  if (!lines.length) return null;

  const hasDocMarker = /^---|^\.\.\./m.test(trimmed);
  const hasKeyValue = lines.some((line) => /^\s*[A-Za-z0-9_"'\-]+\s*:\s*.*$/.test(line));
  const hasList = lines.some((line) => /^\s*-\s+.+$/.test(line));
  if (!hasDocMarker && !hasKeyValue && !hasList) return null;

  const topLevelKeys = [];
  lines.forEach((line) => {
    const match = line.match(/^([A-Za-z0-9_"'\-]+)\s*:/);
    if (match && !line.startsWith(" ")) {
      topLevelKeys.push(match[1].replace(/^['"]|['"]$/g, ""));
    }
  });

  const treeData = parseSimpleYamlToObject(rawText);
  return {
    protocol: "YAML",
    fields: [
      { name: "Top-level keys", value: topLevelKeys.length ? topLevelKeys.join(", ") : "(none detected)" },
      { name: "Contains lists", value: hasList ? "Yes" : "No" },
      {
        name: "Preview",
        value: trimmed.length > 2000 ? `${trimmed.slice(0, 2000)}…` : trimmed,
      },
    ],
    treeData,
  };
}

function readVarint(bytes, startIndex) {
  let value = 0;
  let shift = 0;
  let index = startIndex;
  while (index < bytes.length && shift < 35) {
    const byteValue = bytes[index];
    value |= (byteValue & 0x7f) << shift;
    index += 1;
    if ((byteValue & 0x80) === 0) {
      return { value, nextIndex: index };
    }
    shift += 7;
  }
  return null;
}

function decodeProtobufFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

  const fields = [];
  const maxFields = 100;
  let index = 0;
  let parsedFields = 0;

  while (index < bytes.length && parsedFields < maxFields) {
    const keyInfo = readVarint(bytes, index);
    if (!keyInfo || keyInfo.value <= 0) break;
    index = keyInfo.nextIndex;

    const fieldNumber = keyInfo.value >> 3;
    const wireType = keyInfo.value & 0x07;
    if (fieldNumber <= 0) break;

    let valueLabel = "";
    if (wireType === 0) {
      const valueInfo = readVarint(bytes, index);
      if (!valueInfo) break;
      index = valueInfo.nextIndex;
      valueLabel = `varint=${valueInfo.value}`;
    } else if (wireType === 1) {
      if (index + 8 > bytes.length) break;
      const raw = bytes.slice(index, index + 8);
      index += 8;
      valueLabel = `fixed64=${Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    } else if (wireType === 2) {
      const lengthInfo = readVarint(bytes, index);
      if (!lengthInfo) break;
      index = lengthInfo.nextIndex;
      const length = lengthInfo.value;
      if (index + length > bytes.length) break;
      const raw = bytes.slice(index, index + length);
      index += length;
      const previewHex = Array.from(raw.slice(0, 24), (b) => b.toString(16).padStart(2, "0")).join(" ");
      valueLabel = `len=${length} data=${raw.length > 24 ? `${previewHex} …` : previewHex}`;
    } else if (wireType === 5) {
      if (index + 4 > bytes.length) break;
      const raw = bytes.slice(index, index + 4);
      index += 4;
      valueLabel = `fixed32=${Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    } else {
      break;
    }

    parsedFields += 1;
    fields.push({ name: `Field ${fieldNumber} (wire ${wireType})`, value: valueLabel || "(empty)" });
  }

  if (!fields.length) return null;
  return { protocol: "Protobuf", fields };
}

function decodeMessagePackFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

  const firstByte = bytes[0];
  const byteLength = bytes.length;
  let classification = "unknown";
  if ((firstByte & 0x80) === 0x00 || (firstByte & 0xe0) === 0xe0) classification = "int";
  else if ((firstByte & 0xe0) === 0xa0 || firstByte === 0xd9 || firstByte === 0xda || firstByte === 0xdb) classification = "string";
  else if ((firstByte & 0xf0) === 0x90 || firstByte === 0xdc || firstByte === 0xdd) classification = "array";
  else if ((firstByte & 0xf0) === 0x80 || firstByte === 0xde || firstByte === 0xdf) classification = "map";
  else if ((firstByte & 0xe0) === 0xc0) classification = "misc/bin/ext/float";

  if (classification === "unknown") return null;
  const previewHex = Array.from(bytes.slice(0, 48), (byteValue) =>
    byteValue.toString(16).padStart(2, "0"),
  ).join(" ");
  return {
    protocol: "MessagePack",
    fields: [
      { name: "First byte", value: `0x${firstByte.toString(16).padStart(2, "0").toUpperCase()}` },
      { name: "Likely type", value: classification },
      { name: "Byte length", value: String(byteLength) },
      { name: "Preview (hex)", value: byteLength > 48 ? `${previewHex} …` : previewHex },
    ],
  };
}

function decodeBsonFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 5) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const totalLength = view.getInt32(0, true);
  if (totalLength < 5 || totalLength > bytes.length) return null;
  if (bytes[totalLength - 1] !== 0x00) return null;

  const typeNames = {
    0x01: "double",
    0x02: "string",
    0x03: "document",
    0x04: "array",
    0x05: "binary",
    0x08: "boolean",
    0x09: "datetime",
    0x0a: "null",
    0x10: "int32",
    0x12: "int64",
  };

  const fields = [{ name: "Document length", value: String(totalLength) }];
  let index = 4;
  let elementCount = 0;
  const maxElements = 100;
  while (index < totalLength - 1 && elementCount < maxElements) {
    const typeByte = bytes[index++];
    if (typeByte === 0x00) break;

    let keyEnd = index;
    while (keyEnd < totalLength && bytes[keyEnd] !== 0x00) keyEnd += 1;
    if (keyEnd >= totalLength) break;
    const key = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(index, keyEnd));
    index = keyEnd + 1;

    const typeName = typeNames[typeByte] || `0x${typeByte.toString(16).padStart(2, "0")}`;
    fields.push({ name: `Element ${elementCount + 1}`, value: `${key || "(empty-key)"}: ${typeName}` });
    elementCount += 1;

    if (typeByte === 0x01) index += 8;
    else if (typeByte === 0x02) {
      if (index + 4 > totalLength) break;
      const strLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
      index += 4 + Math.max(0, strLen);
    } else if (typeByte === 0x03 || typeByte === 0x04) {
      if (index + 4 > totalLength) break;
      const docLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
      index += Math.max(0, docLen);
    } else if (typeByte === 0x05) {
      if (index + 4 > totalLength) break;
      const binLen = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getInt32(0, true);
      index += 4 + 1 + Math.max(0, binLen);
    } else if (typeByte === 0x08) index += 1;
    else if (typeByte === 0x09) index += 8;
    else if (typeByte === 0x0a) index += 0;
    else if (typeByte === 0x10) index += 4;
    else if (typeByte === 0x12) index += 8;
    else break;

    if (index > totalLength) break;
  }

  if (elementCount === 0) return null;
  if (elementCount >= maxElements) {
    fields.push({ name: "Notice", value: `Showing first ${maxElements} BSON elements.` });
  }
  return { protocol: "BSON", fields };
}

function normalizeSmbDecoderBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return bytes;
  for (let offset = 0; offset <= Math.min(bytes.length - 4, 16); offset += 1) {
    const first = bytes[offset];
    if (
      (first === 0xff || first === 0xfe) &&
      bytes[offset + 1] === 0x53 &&
      bytes[offset + 2] === 0x4d &&
      bytes[offset + 3] === 0x42
    ) {
      return bytes.slice(offset);
    }
  }
  return bytes;
}

function findBytesSubsequence(bytes, subsequence) {
  if (!(bytes instanceof Uint8Array) || !(subsequence instanceof Uint8Array)) return -1;
  if (!subsequence.length || subsequence.length > bytes.length) return -1;
  for (let index = 0; index <= bytes.length - subsequence.length; index += 1) {
    let matched = true;
    for (let offset = 0; offset < subsequence.length; offset += 1) {
      if (bytes[index + offset] !== subsequence[offset]) {
        matched = false;
        break;
      }
    }
    if (matched) return index;
  }
  return -1;
}

function parseSmbNtlmSecurityBuffer(bytes, fieldOffset) {
  if (!(bytes instanceof Uint8Array) || bytes.length < fieldOffset + 8) return new Uint8Array();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const valueLength = view.getUint16(fieldOffset, true);
  const bufferOffset = view.getUint32(fieldOffset + 4, true);
  if (valueLength <= 0 || bufferOffset + valueLength > bytes.length) return new Uint8Array();
  return bytes.slice(bufferOffset, bufferOffset + valueLength);
}

function decodeSmbTextBytes(bytes, useUnicode = true) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
  try {
    const decoder = new TextDecoder(useUnicode ? "utf-16le" : "utf-8", {
      fatal: false,
    });
    return decoder.decode(bytes).replace(/\u0000+$/g, "").trim();
  } catch {
    return "";
  }
}

function bytesToHexLower(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
  return Array.from(bytes, (byteValue) =>
    byteValue.toString(16).padStart(2, "0"),
  ).join("");
}

function decodeSmbFromBytes(bytes) {
  const normalized = normalizeSmbDecoderBytes(bytes);
  if (!(normalized instanceof Uint8Array) || normalized.length < 8) return null;

  const SMB1_COMMANDS = {
    0x70: "TREE_CONNECT",
    0x72: "NEGOTIATE",
    0x73: "SESSION_SETUP_ANDX",
    0x74: "LOGOFF_ANDX",
    0x75: "TREE_CONNECT_ANDX",
  };
  const SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT",
    0x0004: "TREE_DISCONNECT",
    0x0005: "CREATE",
    0x0008: "READ",
    0x0009: "WRITE",
    0x0010: "QUERY_INFO",
    0x0011: "SET_INFO",
  };

  const view = new DataView(
    normalized.buffer,
    normalized.byteOffset,
    normalized.byteLength,
  );
  let result = null;
  let blobStart = 0;

  if (
    normalized[0] === 0xff && normalized[1] === 0x53 && normalized[2] === 0x4d && normalized[3] === 0x42
  ) {
    const commandCode = normalized[4];
    const status = view.getUint32(5, true);
    const isResponse = Boolean(normalized[9] & 0x80);
    result = {
      protocol: "SMB",
      fields: [
        { name: "Version", value: "SMBv1" },
        { name: "Command", value: SMB1_COMMANDS[commandCode] || `0x${commandCode.toString(16).padStart(2, "0")}` },
        { name: "Status", value: `0x${status.toString(16).padStart(8, "0")}` },
        { name: "Is Response", value: isResponse ? "Yes" : "No" },
      ],
    };
    blobStart = 32;
  } else if (
    normalized[0] === 0xfe && normalized[1] === 0x53 && normalized[2] === 0x4d && normalized[3] === 0x42
  ) {
    const commandCode = view.getUint16(12, true);
    const status = view.getUint32(8, true);
    const isResponse = Boolean(view.getUint32(16, true) & 0x00000001);
    result = {
      protocol: "SMB",
      fields: [
        { name: "Version", value: "SMBv2/v3" },
        { name: "Command", value: SMB2_COMMANDS[commandCode] || `0x${commandCode.toString(16).padStart(4, "0")}` },
        { name: "Status", value: `0x${status.toString(16).padStart(8, "0")}` },
        { name: "Is Response", value: isResponse ? "Yes" : "No" },
      ],
    };
    blobStart = 64;
  }

  if (!result) return null;

  const blob = normalized.slice(blobStart);
  const ntlmIndex = findBytesSubsequence(blob, new Uint8Array([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]));
  if (ntlmIndex === -1) return result;
  const ntlmBlob = blob.slice(ntlmIndex);
  if (ntlmBlob.length < 12) return result;

  const ntlmView = new DataView(ntlmBlob.buffer, ntlmBlob.byteOffset, ntlmBlob.byteLength);
  const messageType = ntlmView.getUint32(8, true);
  const pushField = (name, value) => {
    if (typeof value === "string" && value) result.fields.push({ name, value });
  };

  if (messageType === 1) {
    pushField("NTLMSSP", "NEGOTIATE");
    return result;
  }
  if (messageType === 2) {
    pushField("NTLMSSP", "CHALLENGE");
    pushField(
      "Target Name",
      decodeSmbTextBytes(parseSmbNtlmSecurityBuffer(ntlmBlob, 12), true),
    );
    return result;
  }
  if (messageType !== 3) {
    pushField("NTLMSSP", `TYPE_${messageType}`);
    return result;
  }

  const flags = ntlmBlob.length >= 64 ? ntlmView.getUint32(60, true) : 0;
  const useUnicode = Boolean(flags & 0x00000001);
  const lmResponse = parseSmbNtlmSecurityBuffer(ntlmBlob, 12);
  const ntlmResponse = parseSmbNtlmSecurityBuffer(ntlmBlob, 20);
  const domain = parseSmbNtlmSecurityBuffer(ntlmBlob, 28);
  const username = parseSmbNtlmSecurityBuffer(ntlmBlob, 36);
  const workstation = parseSmbNtlmSecurityBuffer(ntlmBlob, 44);

  pushField("NTLMSSP", "AUTHENTICATE");
  pushField("Domain", decodeSmbTextBytes(domain, useUnicode));
  pushField("Username", decodeSmbTextBytes(username, useUnicode));
  pushField("Workstation", decodeSmbTextBytes(workstation, useUnicode));
  if (lmResponse.length) pushField("LM Response", bytesToHexLower(lmResponse));
  if (ntlmResponse.length) pushField("NTLM Response", bytesToHexLower(ntlmResponse));
  return result;
}

// Handles decode sip from bytes.
function decodeSipFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/);
  if (!lines.length) return null;

  const firstLine = (lines[0] || "").trim();
  if (!firstLine) return null;

  const sipMethods = new Set([
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "INFO",
    "UPDATE",
    "PRACK",
    "MESSAGE",
    "PUBLISH",
  ]);
  const requestMatch = firstLine.match(/^([A-Z]+)\s+(\S+)\s+SIP\/([\d.]+)$/i);
  const responseMatch = firstLine.match(/^SIP\/([\d.]+)\s+(\d{3})(?:\s+(.*))?$/i);
  const isRequest = Boolean(requestMatch && sipMethods.has(requestMatch[1].toUpperCase()));
  const isResponse = Boolean(responseMatch);
  if (!isRequest && !isResponse) return null;

  const headerLines = [];
  let bodyStartIndex = lines.length;
  for (let i = 1; i < lines.length; i += 1) {
    const rawLine = lines[i] || "";
    if (!rawLine.trim()) {
      bodyStartIndex = i + 1;
      break;
    }
    if (/^[ \t]/.test(rawLine) && headerLines.length) {
      headerLines[headerLines.length - 1] += ` ${rawLine.trim()}`;
      continue;
    }
    headerLines.push(rawLine);
  }

  const compactHeaderNames = {
    f: "from",
    t: "to",
    i: "call-id",
    m: "contact",
    v: "via",
    l: "content-length",
    c: "content-type",
    r: "refer-to",
  };
  const headerMap = new Map();
  headerLines.forEach((line) => {
    const separator = line.indexOf(":");
    if (separator <= 0) return;
    const rawName = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!rawName || !value) return;
    const lowered = rawName.toLowerCase();
    const normalizedName = compactHeaderNames[lowered] || lowered;
    if (!headerMap.has(normalizedName)) headerMap.set(normalizedName, []);
    headerMap.get(normalizedName).push(value);
  });

  const truncateField = (value, limit = 180) => {
    if (typeof value !== "string") return "";
    const trimmed = value.trim();
    if (!trimmed) return "";
    return trimmed.length > limit ? `${trimmed.slice(0, limit)}...` : trimmed;
  };
  const getHeaderValue = (name) => {
    const values = headerMap.get(String(name || "").toLowerCase());
    if (!Array.isArray(values) || !values.length) return "";
    return values.join(" | ");
  };

  const fields = [];
  if (isRequest && requestMatch) {
    fields.push(
      { name: "Type", value: "Request" },
      { name: "Method", value: requestMatch[1].toUpperCase() },
      { name: "Request URI", value: requestMatch[2] || "N/A" },
      { name: "SIP Version", value: requestMatch[3] || "N/A" },
    );
  }
  if (isResponse && responseMatch) {
    fields.push(
      { name: "Type", value: "Response" },
      { name: "SIP Version", value: responseMatch[1] || "N/A" },
      { name: "Status Code", value: responseMatch[2] || "N/A" },
      { name: "Reason Phrase", value: responseMatch[3] || "N/A" },
    );
  }

  [
    ["from", "From"],
    ["to", "To"],
    ["call-id", "Call-ID"],
    ["cseq", "CSeq"],
    ["via", "Via"],
    ["contact", "Contact"],
    ["max-forwards", "Max-Forwards"],
    ["user-agent", "User-Agent"],
    ["authorization", "Authorization"],
    ["proxy-authorization", "Proxy-Authorization"],
    ["route", "Route"],
    ["record-route", "Record-Route"],
    ["content-type", "Content-Type"],
    ["content-length", "Content-Length"],
    ["expires", "Expires"],
  ].forEach(([headerKey, label]) => {
    const value = truncateField(getHeaderValue(headerKey));
    if (value) fields.push({ name: label, value });
  });

  const bodyText = lines.slice(bodyStartIndex).join("\n").trim();
  if (bodyText) {
    fields.push({
      name: "Body Preview",
      value: truncateField(bodyText, 220),
    });
  }

  return fields.length ? { protocol: "SIP", fields } : null;
}

function decodeSmppFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 16) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const commandLength = view.getUint32(0, false);
  const commandId = view.getUint32(4, false);
  const commandStatus = view.getUint32(8, false);
  const sequenceNumber = view.getUint32(12, false);

  if (commandLength < 16 || commandLength > bytes.length) return null;

  const commandMap = {
    0x00000001: "bind_receiver",
    0x00000002: "bind_transmitter",
    0x00000003: "query_sm",
    0x00000004: "submit_sm",
    0x00000005: "deliver_sm",
    0x00000006: "unbind",
    0x00000009: "bind_transceiver",
    0x00000015: "enquire_link",
    0x00000021: "submit_multi",
    0x00000103: "data_sm",
  };
  const baseCommandId = commandId & 0x7fffffff;
  const command = commandMap[baseCommandId];
  if (!command) return null;

  return {
    protocol: "SMPP",
    fields: [
      { name: "Command", value: command },
      { name: "Command ID", value: `0x${commandId.toString(16).padStart(8, "0")}` },
      { name: "Is Response", value: (commandId & 0x80000000) !== 0 ? "Yes" : "No" },
      { name: "Command Status", value: String(commandStatus) },
      { name: "Sequence Number", value: String(sequenceNumber) },
      { name: "Body Length", value: String(commandLength - 16) },
    ],
  };
}

function decodeSoulseekFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messageLength = view.getUint32(0, true);
  const messageCode = view.getUint32(4, true);
  const totalLength = messageLength + 4;

  if (messageLength < 4 || totalLength > bytes.length || messageCode > 0xffff) {
    return null;
  }

  const body = bytes.slice(8, totalLength);
  const preview = new TextDecoder("utf-8", { fatal: false })
    .decode(body)
    .replace(/\u0000+/g, "")
    .trim();

  const fields = [
    { name: "Message Code", value: String(messageCode) },
    { name: "Message Code Hex", value: `0x${messageCode.toString(16).padStart(4, "0")}` },
    { name: "Message Length", value: String(messageLength) },
    { name: "Body Length", value: String(body.length) },
  ];
  if (preview) {
    fields.push({
      name: "Payload Preview",
      value: preview.length > 120 ? `${preview.slice(0, 120)}...` : preview,
    });
  }

  return { protocol: "Soulseek", fields };
}

function decodeBittorrentFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

  try {

    if (bytes.length >= 68 && bytes[0] === 19) {
      const protocol = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(1, 20));
      if (protocol === "BitTorrent protocol") {
        const infoHash = bytesToHexLower(bytes.slice(28, 48));
        const peerIdBytes = bytes.slice(48, 68);
        const peerIdHex = bytesToHexLower(peerIdBytes);
        const peerId = Array.from(peerIdBytes, (value) =>
          value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".",
        )
          .join("")
          .replace(/^\.+|\.+$/g, "");
        const fields = [
          { name: "Type", value: "Handshake" },
          { name: "Protocol", value: "BitTorrent protocol" },
          { name: "Info Hash", value: infoHash },
          { name: "Peer ID Hex", value: peerIdHex },
        ];
        if (peerId) fields.push({ name: "Peer ID", value: peerId });
        return { protocol: "BitTorrent", fields };
      }
    }

    if (bytes.length >= 4) {
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const messageLength = view.getUint32(0, false);
      if (messageLength === 0) {
        return {
          protocol: "BitTorrent",
          fields: [
            { name: "Type", value: "Peer Wire" },
            { name: "Message", value: "keepalive" },
            { name: "Message Length", value: "0" },
          ],
        };
      }
      if (messageLength >= 1 && messageLength <= bytes.length - 4) {
        const messageId = bytes[4];
        const messageMap = {
          0: "choke",
          1: "unchoke",
          2: "interested",
          3: "not interested",
          4: "have",
          5: "bitfield",
          6: "request",
          7: "piece",
          8: "cancel",
          9: "port",
          20: "extended",
        };
        return {
          protocol: "BitTorrent",
          fields: [
            { name: "Type", value: "Peer Wire" },
            { name: "Message", value: messageMap[messageId] || `id_${messageId}` },
            { name: "Message ID", value: String(messageId) },
            { name: "Message Length", value: String(messageLength) },
          ],
        };
      }
    }

    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 256));
    if (text.startsWith("d") && text.includes("1:y1:") && (text.includes("1:q") || text.includes("1:r"))) {
      const txMatch = text.match(/1:y1:([qre])/);
      const queryMatch = text.match(/1:q(\d+):([a-z_]+)/i);
      const fields = [
        { name: "Type", value: "DHT KRPC" },
        { name: "Transaction Type", value: txMatch?.[1] || "unknown" },
      ];
      if (queryMatch?.[2]) fields.push({ name: "Query", value: queryMatch[2] });
      return { protocol: "BitTorrent", fields };
    }

    return null;
  } catch {
    return null;
  }
}

// Handles auto detect proto from bytes.
function autoDetectProtoFromBytes(bytes) {
  const normalizedSmbBytes = normalizeSmbDecoderBytes(bytes);
  if (
    normalizedSmbBytes instanceof Uint8Array &&
    normalizedSmbBytes.length >= 4 &&
    ((normalizedSmbBytes[0] === 0xff && normalizedSmbBytes[1] === 0x53 && normalizedSmbBytes[2] === 0x4d && normalizedSmbBytes[3] === 0x42) ||
      (normalizedSmbBytes[0] === 0xfe && normalizedSmbBytes[1] === 0x53 && normalizedSmbBytes[2] === 0x4d && normalizedSmbBytes[3] === 0x42))
  ) {
    return "smb";
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, 256),
  );
  if (/^SSH-/.test(text)) return "ssh";
  const trimmedText = text.trimStart();
  if ((trimmedText.startsWith("{") || trimmedText.startsWith("[")) && decodeJsonFromBytes(bytes)) {
    return "json";
  }
  if (trimmedText.startsWith("<") && decodeXmlFromBytes(bytes)) return "xml";
  if (decodeBsonFromBytes(bytes)) return "bson";
  if (decodeMessagePackFromBytes(bytes)) return "msgpack";
  if (decodeProtobufFromBytes(bytes)) return "protobuf";
  if (decodeBerFromBytes(bytes)) return "ber";
  if (decodeDerFromBytes(bytes)) return "der";
  if (decodeYamlFromBytes(bytes)) return "yaml";
  if (
    /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s/.test(text) ||
    /^HTTP\/[\d.]+ \d{3}/.test(text)
  )
    return "http";
  if (
    /^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)\b/i.test(text) ||
    /^\d{3}[\s-]/.test(text)
  )
    return "smtp";
  if (
    /^(USER|PASS|ACCT|CWD|CDUP|PWD|TYPE|PASV|EPSV|PORT|EPRT|LIST|NLST|RETR|STOR|DELE|RNFR|RNTO|MKD|RMD|SYST|STAT|FEAT|AUTH|NOOP|QUIT)\b/i.test(
      text,
    ) ||
    /^220[\s-].*ftp/i.test(text)
  )
    return "ftp";
  if (
    /^\+OK/.test(text) ||
    /^-ERR/.test(text) ||
    /^(USER|PASS|STAT|LIST|RETR|DELE|QUIT)\b/i.test(text)
  )
    return "pop3";
  if (
    /^\* /.test(text) ||
    /^\+ /.test(text) ||
    /^\S+ (OK|NO|BAD|PREAUTH|BYE)\b/i.test(text) ||
    /^\S+ (SELECT|LOGIN|FETCH|AUTHENTICATE)\b/i.test(text)
  )
    return "imap";
  if (decodeLdapFromBytes(bytes)) return "ldap";
  try {
    if (typeof decodeSmppFromBytes === "function" && decodeSmppFromBytes(bytes)) {
      return "smpp";
    }
    if (typeof decodeSoulseekFromBytes === "function" && decodeSoulseekFromBytes(bytes)) {
      return "soulseek";
    }
    if (typeof decodeBittorrentFromBytes === "function" && decodeBittorrentFromBytes(bytes)) {
      return "bittorrent";
    }
  } catch {
    // Keep auto-detect resilient; one decoder failure must not abort the whole chain.
  }
  if (
    /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|INFO|UPDATE|PRACK|MESSAGE|PUBLISH)\s+\S+\s+SIP\/[\d.]+/i.test(
      trimmedText,
    ) ||
    /^SIP\/[\d.]+\s+\d{3}(?:\s|$)/i.test(trimmedText)
  )
    return "sip";
  // Telnet: require IAC (0xFF) followed by a valid command byte (0xF0–0xFF)
  const TELNET_COMMANDS = new Set([
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  ]);
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 0xff && TELNET_COMMANDS.has(bytes[i + 1])) return "telnet";
  }
  return null;
}

// Renders proto decoder output.
function renderProtoDecoderOutput(result, selectedProtocol, protocol) {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (!protoOutput) return;
  activeDataToolsProtoResult = result || null;
  protoOutput.innerHTML = "";
  delete protoOutput.dataset.decodedResult;
  if (!result) {
    const span = document.createElement("span");
    span.className = "data-tools-proto-none";
    span.textContent =
      selectedProtocol === "auto"
        ? "No known protocol detected"
        : `Could not decode as ${(protocol || selectedProtocol).toUpperCase()}`;
    protoOutput.appendChild(span);
    return;
  }
  protoOutput.dataset.decodedResult = JSON.stringify({
    protocol: result.protocol,
    fields: Array.isArray(result.fields) ? result.fields : [],
  });
  if (renderStructuredDecoderTree(protoOutput, result)) {
    return;
  }
  const table = document.createElement("table");
  table.className = "data-tools-proto-table";
  const headerRow = document.createElement("tr");
  const th1 = document.createElement("th");
  th1.textContent = `${result.protocol} Field`;
  const th2 = document.createElement("th");
  th2.textContent = "Value";
  headerRow.appendChild(th1);
  headerRow.appendChild(th2);
  table.appendChild(headerRow);
  result.fields.forEach((field) => {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = field.name;
    const tdVal = document.createElement("td");
    tdVal.textContent = field.value;
    tr.appendChild(tdName);
    tr.appendChild(tdVal);
    table.appendChild(tr);
  });
  protoOutput.appendChild(table);
}

// Runs proto decoder.
function runProtoDecoder(bytes) {
  const selectEl = document.getElementById("data-tools-proto-select");
  const selectedProtocol = selectEl ? selectEl.value : "auto";
  let protocol = selectedProtocol;
  if (protocol === "auto") {
    protocol = autoDetectProtoFromBytes(bytes);
  }
  let result = null;
  switch (protocol) {
    case "http":
      result = decodeHttpFromBytes(bytes);
      break;
    case "telnet":
      result = decodeTelnetFromBytes(bytes);
      break;
    case "ssh":
      result = decodeSshFromBytes(bytes);
      break;
    case "pop3":
      result = decodePop3FromBytes(bytes);
      break;
    case "imap":
      result = decodeImapFromBytes(bytes);
      break;
    case "smtp":
      result = decodeSmtpFromBytes(bytes);
      break;
    case "ftp":
      result = decodeFtpFromBytes(bytes);
      break;
    case "ber":
      result = decodeBerFromBytes(bytes);
      break;
    case "der":
      result = decodeDerFromBytes(bytes);
      break;
    case "json":
      result = decodeJsonFromBytes(bytes);
      break;
    case "xml":
      result = decodeXmlFromBytes(bytes);
      break;
    case "yaml":
      result = decodeYamlFromBytes(bytes);
      break;
    case "protobuf":
      result = decodeProtobufFromBytes(bytes);
      break;
    case "msgpack":
      result = decodeMessagePackFromBytes(bytes);
      break;
    case "bson":
      result = decodeBsonFromBytes(bytes);
      break;
    case "ldap":
      result = decodeLdapFromBytes(bytes);
      break;
    case "smb":
      result = decodeSmbFromBytes(bytes);
      break;
    case "sip":
      result = decodeSipFromBytes(bytes);
      break;
    case "smpp":
      result = decodeSmppFromBytes(bytes);
      break;
    case "soulseek":
      result = decodeSoulseekFromBytes(bytes);
      break;
    case "bittorrent":
      result = decodeBittorrentFromBytes(bytes);
      break;
    default:
      protocol = null;
  }
  renderProtoDecoderOutput(result, selectedProtocol, protocol);
}

// Clears proto decoder output.
function clearProtoDecoderOutput() {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (protoOutput) {
    protoOutput.innerHTML = "";
    delete protoOutput.dataset.decodedResult;
  }
}
//    Packet JSON decoder setup
document.getElementById("conv-subtab-packet-json").addEventListener("click", () => {
  setConvSubtab(CONV_PACKET_JSON_SUBTAB);
});






// ── Conv tab navigation ───────────────────────────────────────────────────────

function showDataTools(tabName = CONV_CONVERSIONS_SUBTAB) {
  _setActiveMainTab("data-tools");
  _statusUpdate("Status: Displaying data conversion tools");
  _writeLogEntry(`[${threadName}] User opened data conversion tools view`);
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("data_tools_box").style.display = "flex";
  setConvSubtab(tabName);
}

// Syncs right sidebar visibility for Conv subtabs.
function syncConvSidebarVisibility(conversionsActive) {
  const dataToolsBoxEl = document.getElementById("data_tools_box");
  const isDataToolsVisible = dataToolsBoxEl && dataToolsBoxEl.style.display === "flex";
  if (!isDataToolsVisible) return;

  const rightsideEl = document.getElementById("rightside");
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  const rightsideConvInsightsEl = document.getElementById("rightside-conv-insights");

  if (rightsideEl) {
    rightsideEl.style.display = conversionsActive ? "block" : "none";
  }
  if (rightsideDataEl) rightsideDataEl.hidden = true;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;
  if (rightsideConvInsightsEl) {
    rightsideConvInsightsEl.hidden = !conversionsActive;
  }
}

// Sets conv subtab.
function setConvSubtab(tabName) {
  activeConvSubtab = tabName;
  const conversionsActive = tabName === CONV_CONVERSIONS_SUBTAB;
  const hashesActive = tabName === CONV_HASHES_SUBTAB;
  const decodesActive = tabName === CONV_DECODES_SUBTAB;
  const subnetActive = tabName === CONV_SUBNET_SUBTAB;
  const threatIntelActive = tabName === CONV_THREAT_INTEL_SUBTAB;
  const packetJsonActive = tabName === CONV_PACKET_JSON_SUBTAB;
  document
    .getElementById("conv-subtab-conversions")
    .classList.toggle("active", conversionsActive);
  document
    .getElementById("conv-subtab-hashes")
    .classList.toggle("active", hashesActive);
  document
    .getElementById("conv-subtab-decodes")
    .classList.toggle("active", decodesActive);
  document
    .getElementById("conv-subtab-subnet")
    .classList.toggle("active", subnetActive);
  document
    .getElementById("conv-subtab-threat-intel")
    .classList.toggle("active", threatIntelActive);
  document
    .getElementById("conv-subtab-packet-json")
    .classList.toggle("active", packetJsonActive);
  document.getElementById("conv-conversions-panel").hidden = !conversionsActive;
  document.getElementById("conv-hashes-panel").hidden = !hashesActive;
  document.getElementById("conv-decodes-panel").hidden = !decodesActive;
  document.getElementById("conv-subnet-panel").hidden = !subnetActive;
  document.getElementById("conv-threat-intel-panel").hidden = !threatIntelActive;
  document.getElementById("conv-packet-json-panel").hidden = !packetJsonActive;
  syncConvSidebarVisibility(conversionsActive);
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  id: "data-tools",
  initConvPanel,
  // Constants
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_DECODES_SUBTAB,
  CONV_SUBNET_SUBTAB,
  CONV_THREAT_INTEL_SUBTAB,
  CONV_PACKET_JSON_SUBTAB,
  VALID_CONV_SUBTABS,
  DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH,
  DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD,
  DATA_TOOLS_ENTROPY_HIGH_THRESHOLD,
  DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD,
  DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES,
  // State accessors
  getActiveConvSubtab,
  getActiveDataToolsProtoResult,
  // Functions
  parseDataToolsInput,
  bytesToPrintableAscii,
  decodeHttpFromBytes,
  decodeTelnetFromBytes,
  decodeSshFromBytes,
  decodePop3FromBytes,
  decodeImapFromBytes,
  decodeSmtpFromBytes,
  decodeFtpFromBytes,
  decodeBerFromBytes,
  decodeDerFromBytes,
  decodeJsonFromBytes,
  decodeXmlFromBytes,
  decodeYamlFromBytes,
  decodeProtobufFromBytes,
  decodeMessagePackFromBytes,
  decodeBsonFromBytes,
  decodeLdapFromBytes,
  decodeSmbFromBytes,
  decodeSipFromBytes,
  decodeSmppFromBytes,
  decodeSoulseekFromBytes,
  decodeBittorrentFromBytes,
  autoDetectProtoFromBytes,
  resetDataToolsOutputs,
  runProtoDecoder,
  formatHexInputBytes,
  runDataToolsConversion,
  runDataToolsHashesFromInput,
  crossReferenceCurrentHash,
  showDataTools,
  setConvSubtab,
};
