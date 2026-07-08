
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
const CONV_PACKET_JSON_SUBTAB = "packet-json";

const VALID_CONV_SUBTABS = [
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_DECODES_SUBTAB,
  CONV_SUBNET_SUBTAB,
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
    const normalized = rawInput
      .replace(/0x/gi, "")
      .replace(/[\s,:;-]+/g, "")
      .trim();
    if (!normalized) throw new Error("No hex bytes were found.");
    if (!/^[0-9a-fA-F]+$/.test(normalized)) {
      throw new Error("Hex input can only contain 0-9 and A-F.");
    }
    if (normalized.length % 2 !== 0) {
      throw new Error("Hex input must contain an even number of characters.");
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
      bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
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
    const hexSpaced = [...bytes]
      .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
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

    document.getElementById("data-tools-hex-output").value = hexSpaced;
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
  const firstLine = lines[0].trim();
  const requestMatch = firstLine.match(
    /^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/,
  );
  const responseMatch = firstLine.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)/);
  if (!requestMatch && !responseMatch) return null;

  const emptyLineIdx = lines.findIndex((l, i) => i > 0 && l.trim() === "");
  const headerLines = lines.slice(
    1,
    emptyLineIdx > 0 ? emptyLineIdx : lines.length,
  );
  const headers = {};
  headerLines.forEach((hl) => {
    const idx = hl.indexOf(":");
    if (idx > 0) {
      headers[hl.slice(0, idx).trim()] = hl.slice(idx + 1).trim();
    }
  });

  const fields = [];
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
    ].forEach((h) => {
      if (headers[h]) fields.push({ name: h, value: headers[h] });
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
    ].forEach((h) => {
      if (headers[h]) fields.push({ name: h, value: headers[h] });
    });
  }
  if (emptyLineIdx > 0 && emptyLineIdx < lines.length - 1) {
    const body = lines
      .slice(emptyLineIdx + 1)
      .join("\n")
      .trim();
    if (body) {
      fields.push({
        name: "Body (preview)",
        value: body.length > 200 ? body.slice(0, 200) + "…" : body,
      });
    }
  }
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
    if (fields.length >= 10) break;
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
    if (fields.length >= 12) break;
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
    if (fields.length >= 12) break;
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

    if (fields.length >= 12) break;
  }

  if (!detected) return null;
  return { protocol: "FTP", fields };
}

// Handles decode sip from bytes.
function decodeSipFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/);
  if (!lines.length) return null;

  const firstLine = lines[0].trim();
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
  ]);

  // Check if first line is a SIP request or response
  const isRequest =
    sipMethods.has(firstLine.split(/\s+/)[0]?.toUpperCase());
  const isResponse = firstLine.startsWith("SIP/");

  if (!isRequest && !isResponse) return null;

  const fields = [];
  const headers = {};

  // Parse headers
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) break;
    if (line.includes(": ")) {
      const [key, value] = line.split(": ", 2);
      headers[key.trim()] = value.trim();
    }
  }

  if (isRequest) {
    const parts = firstLine.split(/\s+/);
    fields.push(
      { name: "Type", value: "Request" },
      { name: "Method", value: parts[0] || "—" },
      { name: "Request URI", value: parts[1] || "—" },
    );
  } else {
    const parts = firstLine.split(/\s+/);
    fields.push(
      { name: "Type", value: "Response" },
      { name: "Status Code", value: parts[1] || "—" },
      { name: "Status Message", value: parts[2] || "—" },
    );
  }

  // Add common SIP headers
  [
    "From",
    "To",
    "Call-ID",
    "CSeq",
    "Via",
    "Contact",
    "Authorization",
    "Proxy-Authorization",
    "Route",
    "Record-Route",
  ].forEach((headerName) => {
    if (headers[headerName]) {
      const value = headers[headerName];
      fields.push({
        name: headerName,
        value: value.length > 100 ? value.slice(0, 100) + "…" : value,
      });
    }
  });

  if (!fields.length) return null;
  return { protocol: "SIP", fields };
}

// Handles auto detect proto from bytes.
function autoDetectProtoFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, 256),
  );
  if (/^SSH-/.test(text)) return "ssh";
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
  if (
    /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|INFO|UPDATE|PRACK)\s+\S+\s+SIP\/[\d.]+/i.test(
      text,
    ) ||
    /^SIP\/[\d.]+ \d{3}/i.test(text)
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
    case "sip":
      result = decodeSipFromBytes(bytes);
      break;
    default:
      protocol = null;
  }
  renderProtoDecoderOutput(result, selectedProtocol, protocol);
}

// Clears proto decoder output.
function clearProtoDecoderOutput() {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (protoOutput) protoOutput.innerHTML = "";
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

// Sets conv subtab.
function setConvSubtab(tabName) {
  activeConvSubtab = tabName;
  const conversionsActive = tabName === CONV_CONVERSIONS_SUBTAB;
  const hashesActive = tabName === CONV_HASHES_SUBTAB;
  const decodesActive = tabName === CONV_DECODES_SUBTAB;
  const subnetActive = tabName === CONV_SUBNET_SUBTAB;
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
    .getElementById("conv-subtab-packet-json")
    .classList.toggle("active", packetJsonActive);
  document.getElementById("conv-conversions-panel").hidden = !conversionsActive;
  document.getElementById("conv-hashes-panel").hidden = !hashesActive;
  document.getElementById("conv-decodes-panel").hidden = !decodesActive;
  document.getElementById("conv-subnet-panel").hidden = !subnetActive;
  document.getElementById("conv-packet-json-panel").hidden = !packetJsonActive;
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
  resetDataToolsOutputs,
  runProtoDecoder,
  runDataToolsConversion,
  runDataToolsHashesFromInput,
  showDataTools,
  setConvSubtab,
};
