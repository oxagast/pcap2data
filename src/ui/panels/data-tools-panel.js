// Controls the Conv workspace UI for conversions, hashes, decoders, and subnet tools.


const CryptoJS = require("crypto-js");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");
const ExifReader = require('exifreader');
const {
  initDataToolsLlmSummarizer,
  requestDataToolsBackgroundSummary,
  clearDataToolsSummary,
} = require("./data-tools-llm-summarizer");

// Phase 1 of the decoder refactor: structured-text decoders live in
// src/ui/decoders/conv/. They are re-exported here via a barrel so the
// existing exports surface is unchanged.
const convDecoders = require("../decoders/conv");

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
const CONV_EXTRACTION_SUBTAB = "extraction";
const CONV_DECODES_SUBTAB = "decodes";
const CONV_SUBNET_SUBTAB = "subnet";
const CONV_THREAT_INTEL_SUBTAB = "threat-intel";
const CONV_PACKET_JSON_SUBTAB = "packet-json";

const VALID_CONV_SUBTABS = [
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_EXTRACTION_SUBTAB,
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

// ID prefix + hash-algorithm pairs used to render the Crypt-side Hashes
// mirror. Same algorithms as the Conv-side outputs; only the DOM IDs
// differ so we don't collide with the Conv Hashes panel.
const CRYPT_HASH_IDS = [
  "crypt-hashes-md5-output",
  "crypt-hashes-sha1-output",
  "crypt-hashes-sha256-output",
  "crypt-hashes-sha384-output",
  "crypt-hashes-sha512-output",
  "crypt-hashes-sha3-256-output",
  "crypt-hashes-sha3-512-output",
  "crypt-hashes-ripemd160-output",
  "crypt-hashes-whirlpool-output",
];
// DOM IDs that pair HASH_IDS ↔ CRYPT_HASH_IDS 1:1. Used by
// ``renderHashesIntoOutputs`` below to keep the two panels in sync.
const HASH_ID_PAIRS = HASH_IDS.map((convId, index) => ({
  convId,
  cryptId: CRYPT_HASH_IDS[index],
}));

// ── Conv tab state ────────────────────────────────────────────────────────────

let activeConvSubtab = CONV_CONVERSIONS_SUBTAB;
let activeDataToolsProtoResult = null;
let decodedImageRegistry = [];
const MAX_DECODED_IMAGE_REGISTRY_SIZE = 50;

// Per-packet byte slices captured when an entire stream is loaded into the
// Decodes subtab. When populated, runProtoDecoder iterates over each entry
// and renders the decodes as a vertical stack (newest first) instead of
// decoding the concatenated stream as a single blob. Entries are plain
// Uint8Array slices and the per-packet info needed to label them; the array
// is cleared whenever the user edits the underlying input or loads a fresh
// non-stream source.
let dataToolsStreamPackets = null;
const MAX_DATA_TOOLS_STREAM_PACKETS = 512;

// User-toggleable filter for the Conv Decodes stacked view. When true,
// packets whose bytes do not produce a decoder result (or are skipped by
// the per-packet filter for being empty/unsupported) are not rendered as
// blocks in the stacked list. The toggle is renderer-only state and is
// intentionally NOT persisted to settings.json — it is a per-session
// convenience for analysts triaging a stream with many no-op packets.
let convDecodesHideNoOp = false;

// ── Injected dependencies (set via initConvPanel) ─────────────────────────────

let _writeLogEntry = () => { };
let _statusUpdate = () => { };
let _setActiveMainTab = () => { };
let _getCurrentContextPacket = () => null;
let _getActiveMainTab = () => "data-tools";
let _callLargeLanguageModel = null;
let _isLlmRuntimeEnabled = () => false;
let _isBackgroundSummaryGenerationEnabled = () => false;
let _appendAnalysisBlub = null;
let _addHashReverseToKeystore = () => 0;
let _recordHashesComLookupOutcome = () => { };

// Initializes conv panel.
function initConvPanel({ writeLogEntry, statusUpdate, setActiveMainTab, getCurrentContextPacket, getActiveMainTab, callLargeLanguageModel, isLlmRuntimeEnabled, isBackgroundSummaryGenerationEnabled, appendAnalysisBlub, addHashReverseToKeystore, recordHashesComLookupOutcome, markovData }) {
  _writeLogEntry = writeLogEntry;
  _statusUpdate = statusUpdate;
  _setActiveMainTab = setActiveMainTab;
  _getCurrentContextPacket = getCurrentContextPacket || (() => null);
  _getActiveMainTab = getActiveMainTab || (() => "data-tools");
  _callLargeLanguageModel = callLargeLanguageModel || null;
  _isLlmRuntimeEnabled = isLlmRuntimeEnabled || (() => false);
  _isBackgroundSummaryGenerationEnabled = isBackgroundSummaryGenerationEnabled || (() => false);
  _appendAnalysisBlub = appendAnalysisBlub || null;
  // ``addHashReverseToKeystore`` is a renderer-side bridge into the
  // keystore panel. We deliberately keep data-tools-panel agnostic of
  // keystore-panel (the keystore panel is loaded separately and the
  // circular import would otherwise be a pain); the bridge accepts a
  // list of plaintext entries that came back from hashes.com and
  // returns the count that were actually persisted.
  _addHashReverseToKeystore = typeof addHashReverseToKeystore === "function"
    ? addHashReverseToKeystore
    : () => 0;
  // ``recordHashesComLookupOutcome`` is the renderer-side hook that
  // updates the Settings "Last Cost" / "Last Lookup" pills. Failures
  // here would only break indicator freshness, so we swallow them and
  // log instead of bubbling.
  _recordHashesComLookupOutcome = typeof recordHashesComLookupOutcome === "function"
    ? (outcome) => {
      try {
        recordHashesComLookupOutcome(outcome);
      } catch (hookError) {
        try {
          _writeLogEntry(
            `[${threadName}] recordHashesComLookupOutcome threw message=${JSON.stringify(hookError?.message || String(hookError))}`,
          );
        } catch (_nestedError) {
          // best-effort logging only
        }
      }
    }
    : () => { };
  initDataToolsLlmSummarizer({
    callLargeLanguageModel: _callLargeLanguageModel,
    isLlmRuntimeEnabled: _isLlmRuntimeEnabled,
    isBackgroundSummaryGenerationEnabled: _isBackgroundSummaryGenerationEnabled,
    statusUpdate: _statusUpdate,
    writeLogEntry: _writeLogEntry,
    appendAnalysisBlub: _appendAnalysisBlub,
  });
  if (markovData) {
    renderMarkovData(markovData);
  }
}

// ── State accessors ───────────────────────────────────────────────────────────

function renderMarkovData(data) {
  const outputElement = document.getElementById("markov-output");
  if (outputElement) {
    outputElement.innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
  }
}

function getActiveConvSubtab() {
  return activeConvSubtab;
}

// Returns active data tools proto result.
function getActiveDataToolsProtoResult() {
  return activeDataToolsProtoResult;
}

// Returns the per-packet byte slice list captured when an entire stream was
// loaded into the Decodes subtab. Returns null when no stream is active, so
// callers can fall back to the single-blob decode path.
function getDataToolsStreamPackets() {
  return Array.isArray(dataToolsStreamPackets) ? dataToolsStreamPackets : null;
}

// Stores the per-packet byte slices for the active stream. Each entry is
// expected to be { bytes: Uint8Array, info?: { packetIndex?, sourceKey? } }
// so the stacked renderer can label the decode blocks (newest first) and
// the user can correlate each block back to its packet. Passing null/empty
// clears the stream state and reverts to single-blob decoding.
function setDataToolsStreamPackets(packets) {
  if (!Array.isArray(packets) || packets.length === 0) {
    dataToolsStreamPackets = null;
    return;
  }
  const normalized = packets
    .filter((entry) => entry && entry.bytes instanceof Uint8Array && entry.bytes.length > 0)
    .slice(0, MAX_DATA_TOOLS_STREAM_PACKETS)
    .map((entry, index) => ({
      bytes: entry.bytes,
      info: entry.info && typeof entry.info === "object" ? entry.info : {},
      orderIndex: index,
    }));
  dataToolsStreamPackets = normalized.length ? normalized : null;
}

// Clears the per-packet stream state. Called when the user edits the
// underlying input or loads a fresh non-stream source.
function clearDataToolsStreamPackets() {
  dataToolsStreamPackets = null;
}

// Returns whether the Conv Decodes stacked view is configured to suppress
// packets whose bytes fail to decode. The renderer reads this inside the
// stacked-render loop and skips appending the corresponding block when
// true. False by default — analysts see every packet in capture order
// until they explicitly opt in to the filter.
function getConvDecodesHideNoOp() {
  return convDecodesHideNoOp === true;
}

// Sets the hide-no-op filter toggle. The change is reflected on the next
// stacked render; the caller is responsible for triggering a re-render
// (typically via runProtoDecoder on the active bytes).
function setConvDecodesHideNoOp(nextValue) {
  convDecodesHideNoOp = nextValue === true;
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

// Pure computation: returns the nine hash hex strings that the
// Conv + Crypt Hashes panels render. No DOM access; safe to call
// from anywhere. Matches ``HASH_IDS`` order: MD5, SHA-1, SHA-256,
// SHA-384, SHA-512, SHA3-256, SHA3-512, RIPEMD-160, Whirlpool.
function computeHashValues(bytes) {
  const wordArray = CryptoJS.lib.WordArray.create(bytes);
  const byteString = bytesToCharString(bytes);
  const whirlpoolHash = bytes.length > 0 ? whirlpool.encSync(byteString, "hex") : "";
  return [
    CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex),
    CryptoJS.SHA1(wordArray).toString(CryptoJS.enc.Hex),
    CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex),
    CryptoJS.SHA384(wordArray).toString(CryptoJS.enc.Hex),
    CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex),
    sha3_256(bytes),
    sha3_512(bytes),
    CryptoJS.RIPEMD160(wordArray).toString(CryptoJS.enc.Hex),
    whirlpoolHash,
  ];
}

// Writes a list of nine hash hex strings into the matching DOM input
// elements. ``ids`` mirrors the order produced by ``computeHashValues``.
// Missing DOM nodes are silently skipped (so a partially-mounted
// Crypt panel doesn't blow up if a hash element hasn't rendered yet).
function writeHashOutputs(ids, values) {
  for (let i = 0; i < ids.length && i < values.length; i += 1) {
    const el = document.getElementById(ids[i]);
    if (el) el.value = values[i];
  }
}

// Computes data tools hashes and writes them into the Conv Hashes
// outputs. The Crypt-side mirror is updated separately by
// ``renderCryptHashesFromConvInput`` so the two panels don't have
// to share a refresh path.
function computeDataToolsHashes(bytes) {
  const values = computeHashValues(bytes);
  writeHashOutputs(HASH_IDS, values);
}
// we need to use 

function runDataToolsHashesFromInput() {
  const hashInput = document.getElementById("data-tools-hash-input-reading").value;
  const bytes = parseHashInputReadingBytes(hashInput);
  computeDataToolsHashes(bytes);
  // Clear the reverse-lookup section below so the user isn't misled
  // by stale results from a previous hash.
  const reverseInputEl = document.getElementById("data-tools-hash-reverse-input");
  const reverseStatusEl = document.getElementById("data-tools-hash-reverse-status");
  const reverseResultEl = document.getElementById("data-tools-hash-reverse-result");
  const identifyResultEl = document.getElementById("data-tools-hash-identify-result");
  if (reverseInputEl) reverseInputEl.value = "";
  if (reverseStatusEl) reverseStatusEl.textContent = "Enter a hash and click Reverse Hash. The request is sent to hashes.com; cost is deducted from your account.";
  if (reverseResultEl) reverseResultEl.textContent = "No reverse-lookup has been run yet.";
  if (identifyResultEl) identifyResultEl.textContent = "No identifier-lookup has been run yet.";
  if (activeConvSubtab === CONV_HASHES_SUBTAB) {
    requestDataToolsBackgroundSummary(CONV_HASHES_SUBTAB);
  }
}

// Mirrors the Conv Hashes outputs into the Crypt → Hashes panel.
// Reads whatever is currently in ``#data-tools-hash-input-reading``,
// recomputes the nine digests, and writes them into the
// ``crypt-hashes-*-output`` inputs. Also reflects the Conv input box
// contents into the read-only ``crypt-hashes-input-reading`` display so
// the user sees exactly what got hashed. Silently no-ops when the
// Conv input box has never been populated (no bytes means no hashes).
function renderCryptHashesFromConvInput() {
  const convInputEl = document.getElementById("data-tools-hash-input-reading");
  const cryptInputEl = document.getElementById("crypt-hashes-input-reading");
  if (!convInputEl) return;
  const hashInput = convInputEl.value;
  if (cryptInputEl) {
    cryptInputEl.value = hashInput;
  }
  // Empty input → empty hash outputs (don't throw).
  if (!hashInput) {
    writeHashOutputs(CRYPT_HASH_IDS, new Array(CRYPT_HASH_IDS.length).fill(""));
    return;
  }
  let bytes;
  try {
    bytes = parseHashInputReadingBytes(hashInput);
  } catch (error) {
    _writeLogEntry(
      `[${threadName}] renderCryptHashesFromConvInput parse failed message=${JSON.stringify(error?.message || String(error))}`,
    );
    writeHashOutputs(CRYPT_HASH_IDS, new Array(CRYPT_HASH_IDS.length).fill(""));
    return;
  }
  const values = computeHashValues(bytes);
  writeHashOutputs(CRYPT_HASH_IDS, values);
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

// Reverse-lookup panel (Hashes subtab). The keystore "Send to Hashes" button
// pre-fills the input, but the user can also paste any hash here. We POST
// to hashes.com via the IPC bridge and render the ``founds`` array as
// ``algorithm:plaintext`` lines (with ``salt`` when present).
//
// We deliberately do NOT call into Threat Intel / VirusTotal: hashes.com
// is a dedicated reverse-hash service and runs on a different auth
// surface (the user's hashes.com account, not their VT quota).
async function runDataToolsHashReverseLookup() {
  const inputEl = document.getElementById("data-tools-hash-reverse-input");
  const statusEl = document.getElementById("data-tools-hash-reverse-status");
  const resultEl = document.getElementById("data-tools-hash-reverse-result");
  if (!inputEl || !statusEl || !resultEl) {
    return;
  }
  // Clear the hash computation section above so the user isn't misled
  // by stale hash outputs from a previous input.
  resetHashOutputs();
  const rawHash = String(inputEl.value || "").trim();
  if (!rawHash) {
    statusEl.textContent = "Enter a hash to reverse.";
    resultEl.textContent = "No reverse-lookup has been run yet.";
    _statusUpdate("Status: Enter a hash to reverse-lookup.");
    return;
  }
  // The hashes.com API accepts multiple hashes per request, but the
  // single-input UI only ever sends one. Whitespace-separating on
  // space / comma / semicolon makes it forgiving for users who paste
  // "abc123 def456" or "abc123,def456".
  const hashes = rawHash
    .split(/[\s,;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (!hashes.length) {
    statusEl.textContent = "Enter a hash to reverse.";
    return;
  }
  const setStatus = (text) => {
    statusEl.textContent = text;
  };
  const setResult = (text) => {
    resultEl.textContent = text;
  };
  setStatus(`Querying hashes.com for ${hashes.length} hash(es)…`);
  setResult("Reverse-lookup in progress…");
  _statusUpdate(`Status: Reverse-looking up hash via hashes.com…`);
  _writeLogEntry(
    `[${threadName}] Hash reverse lookup begin count=${hashes.length}`,
  );
  const bridge = typeof window !== "undefined" ? window.extractapi : null;
  if (!bridge || typeof bridge.hashesComSearch !== "function") {
    setStatus("Hashes.com bridge is unavailable (preload missing hashesComSearch).");
    setResult("IPC bridge is unavailable. Try restarting the app.");
    _recordHashesComLookupOutcome({
      success: false,
      cost: 0,
      error: "hashesComSearch bridge unavailable",
    });
    return;
  }
  try {
    const response = await bridge.hashesComSearch({ hashes });
    if (!response || response.success === false) {
      const errorMessage = response?.error || "Hashes.com lookup failed.";
      setStatus(`Hashes.com lookup failed: ${errorMessage}`);
      setResult(`Error: ${errorMessage}`);
      _statusUpdate("Status: Hashes.com lookup failed.");
      _writeLogEntry(
        `[${threadName}] Hash reverse lookup failed message=${JSON.stringify(errorMessage)}`,
      );
      _recordHashesComLookupOutcome({
        success: false,
        cost: Number.isFinite(Number(response?.cost)) ? Number(response.cost) : 0,
        error: errorMessage,
      });
      return;
    }
    const founds = Array.isArray(response.founds) ? response.founds : [];
    const unfounds = Array.isArray(response.unfounds) ? response.unfounds : [];
    const lines = [];
    lines.push(`Endpoint: ${response.endpoint || "https://hashes.com/en/api/search"}`);
    lines.push(`HTTP status: ${response.httpStatus ?? "n/a"}`);
    lines.push(`API success: ${response.success === false ? "false" : "true"}`);
    if (Number.isFinite(Number(response.cost))) {
      lines.push(`Cost: ${response.cost}`);
    }
    lines.push(`Matched: ${founds.length}`);
    lines.push(`Unmatched: ${unfounds.length}`);
    lines.push("");
    if (founds.length === 0) {
      lines.push("No plaintext matches were returned by hashes.com.");
    } else {
      lines.push("Plaintext matches:");
      for (const found of founds) {
        const algo = found.algorithm || "Unknown";
        const plaintext = found.plaintext || "";
        const hashLabel = found.hash || "";
        const salt = found.salt ? ` (salt=${found.salt})` : "";
        const leadingHash = hashLabel && hashLabel !== plaintext
          ? `${hashLabel} → `
          : "";
        lines.push(`- ${algo}: ${leadingHash}${plaintext}${salt}`);
      }
    }
    if (unfounds.length > 0) {
      lines.push("");
      lines.push("Unmatched hashes:");
      for (const missed of unfounds) {
        const missedHash = formatUnmatchedHashLine(missed);
        if (!missedHash) continue;
        lines.push(`- ${missedHash}`);
      }
    }
    setResult(lines.join("\n"));
    setStatus(
      `Done. ${founds.length} matched / ${unfounds.length} unmatched.`,
    );
    _statusUpdate(
      `Status: Hashes.com reverse-lookup complete (matched=${founds.length}).`,
    );
    _writeLogEntry(
      `[${threadName}] Hash reverse lookup complete matched=${founds.length} unmatched=${unfounds.length} cost=${response.cost ?? "n/a"}`,
    );
    _recordHashesComLookupOutcome({
      success: true,
      cost: Number.isFinite(Number(response.cost)) ? Number(response.cost) : 0,
      error: "",
    });
    // Mirror successful reverses back into the keystore so the user
    // can find them later without re-running the lookup. Each match
    // becomes a ``secret``-typed entry carrying the plaintext, the
    // algorithm hashes.com reported, and the original hash. We
    // dedupe inside ``addSessionKeystoreEntry`` itself, so passing
    // the same reverse twice is a safe no-op.
    if (founds.length > 0) {
      const keystoreEntries = buildHashReverseKeystoreEntries({
        queryHashes: hashes,
        founds,
      });
      if (keystoreEntries.length > 0) {
        const persistedCount = _addHashReverseToKeystore(keystoreEntries);
        if (persistedCount > 0) {
          const keystoreNote = ` Persisted ${persistedCount} match(es) to keystore.`;
          setStatus(
            `Done. ${founds.length} matched / ${unfounds.length} unmatched.${keystoreNote}`,
          );
          _statusUpdate(
            `Status: Hashes.com reverse-lookup complete (matched=${founds.length}, keystore=${persistedCount}).`,
          );
          _writeLogEntry(
            `[${threadName}] Hash reverse results persisted to keystore count=${persistedCount}`,
          );
        }
      }
    }
  } catch (error) {
    // See the matching block in ``runDataToolsHashIdentify`` for
    // context: Electron throws ``No handler registered for '<channel>'``
    // when the running Electron app bundle predates the IPC handler
    // the renderer is calling. Surface a specific hint so the user
    // knows to restart instead of wondering why their click fails.
    const errorMessage = error?.message || String(error);
    let friendly = `Error: ${errorMessage}`;
    if (/No handler registered/i.test(errorMessage)) {
      friendly +=
        "\n\nThe Electron main process is missing this IPC handler. "
        + "Stop the running app (Ctrl+C in the terminal where `npm start` is running) "
        + "and relaunch it so the updated main/preload bundles reload.";
    }
    setStatus(`Hashes.com lookup failed: ${errorMessage}`);
    setResult(friendly);
    _statusUpdate("Status: Hashes.com lookup failed.");
    _writeLogEntry(
      `[${threadName}] Hash reverse lookup threw message=${JSON.stringify(errorMessage)}`,
    );
    _recordHashesComLookupOutcome({
      success: false,
      cost: 0,
      error: errorMessage,
    });
  }
}

// Identify what algorithm(s) a given hash could possibly be.
// hashes.com exposes a public GET endpoint ``/en/api/identifier``
// that takes ``hash=<value>`` (plus optional ``extended=true``)
// and returns a candidate algorithm list. This is the "what kind
// of hash is this?" companion to the reverse-lookup button —
// when the user has a hash of unknown provenance they can ask
// hashes.com to enumerate the likely algorithms *before* burning
// credits on a reverse-lookup that targets the wrong one.
async function runDataToolsHashIdentify() {
  const inputEl = document.getElementById("data-tools-hash-reverse-input");
  const resultEl = document.getElementById("data-tools-hash-identify-result");
  if (!resultEl) return;
  const rawHash = String(inputEl?.value || "").trim();
  if (!rawHash) {
    resultEl.textContent =
      "Enter a hash and click Identify Hash Types.";
    _statusUpdate("Status: Enter a hash to identify.");
    return;
  }
  // Clear the hash computation section above so the user isn't misled
  // by stale hash outputs from a previous input.
  resetHashOutputs();
  const setResult = (text) => {
    resultEl.textContent = text;
  };
  setResult("Identifier-lookup in progress…");
  _statusUpdate("Status: Asking hashes.com what algorithms this hash could be…");
  _writeLogEntry(
    `[${threadName}] Hash identifier lookup begin hashLength=${rawHash.length}`,
  );
  const bridge = typeof window !== "undefined" ? window.extractapi : null;
  if (!bridge || typeof bridge.hashesComIdentify !== "function") {
    setResult(
      "IPC bridge is unavailable (preload missing hashesComIdentify). Try restarting the app.",
    );
    return;
  }
  try {
    const response = await bridge.hashesComIdentify({
      hash: rawHash,
      extended: true,
    });
    if (!response || response.success === false) {
      const errorMessage =
        (response && response.error)
        || (response && response.message)
        || "Hashes.com identifier lookup failed.";
      setResult(`Error: ${errorMessage}`);
      _statusUpdate("Status: Hashes.com identifier lookup failed.");
      _writeLogEntry(
        `[${threadName}] Hash identifier lookup failed message=${JSON.stringify(errorMessage)}`,
      );
      return;
    }
    const algorithms = Array.isArray(response.algorithms)
      ? response.algorithms
      : [];
    const lines = [];
    lines.push(
      `Endpoint: ${response.endpoint || "https://hashes.com/en/api/identifier"}`,
    );
    lines.push(`HTTP status: ${response.httpStatus ?? "n/a"}`);
    lines.push(`Mode: ${response.extended ? "extended" : "concise"}`);
    lines.push(`Matches: ${algorithms.length}`);
    lines.push("");
    if (algorithms.length === 0) {
      const note = response.message
        ? ` (${response.message})`
        : "";
      lines.push(`No candidate algorithms returned.${note}`);
    } else {
      lines.push("Candidate algorithms:");
      for (const algo of algorithms) {
        lines.push(`- ${algo}`);
      }
    }
    setResult(lines.join("\n"));
    _statusUpdate(
      `Status: Hashes.com identifier complete (candidates=${algorithms.length}).`,
    );
    _writeLogEntry(
      `[${threadName}] Hash identifier lookup complete candidates=${algorithms.length} mode=${response.extended ? "extended" : "concise"}`,
    );
  } catch (error) {
    // Electron rejects ``ipcRenderer.invoke`` with a generic
    // ``"No handler registered for '<channel>'"`` Error whenever
    // the renderer's preload was loaded against a main process
    // bundle that doesn't (yet) have the matching ``ipcMain.handle``.
    // That almost always means the running Electron process was
    // launched *before* the handler was added and the user is
    // running stale main/preload bundles. Surface a specific hint
    // so they don't have to guess why their click mysteriously
    // fails after pulling new code.
    const errorMessage = error?.message || String(error);
    let friendly = `Error: ${errorMessage}`;
    if (/No handler registered/i.test(errorMessage)) {
      friendly +=
        "\n\nThe Electron main process is missing this IPC handler. "
        + "Stop the running app (Ctrl+C in the terminal where `npm start` is running) "
        + "and relaunch it so the updated main/preload bundles reload.";
    }
    setResult(friendly);
    _statusUpdate("Status: Hashes.com identifier lookup failed.");
    _writeLogEntry(
      `[${threadName}] Hash identifier lookup threw message=${JSON.stringify(errorMessage)}`,
    );
  }
}

// Coerce an ``unfounds`` entry (either ``{hash, salt, algorithm}``
// object or legacy bare string) into the hash string the renderer
// wants to show in the result panel. Returns the empty string when
// no hash can be extracted, so callers can skip rendering.
function formatUnmatchedHashLine(entry) {
  if (!entry) return "";
  if (typeof entry === "string") return entry.trim();
  if (typeof entry === "object") {
    return String(entry.hash || "").trim();
  }
  return "";
}

// Build a list of keystore-shaped entries from a successful
// hashes.com reverse lookup. Each ``found`` is one entry; we
// carry the plaintext (so the entry is actually useful), the
// algorithm hashes.com reported, and the original hash as both
// ``content`` (so the keystore dedupe logic sees a stable value)
// and a human-readable ``summary`` line. When a single hash
// resolves to multiple plaintexts (rare but possible with weak
// algorithms), each gets its own entry so the user can audit
// every reversal independently.
function buildHashReverseKeystoreEntries({ queryHashes, founds }) {
  if (!Array.isArray(founds) || founds.length === 0) return [];
  const queryHashIndex = new Map();
  if (Array.isArray(queryHashes)) {
    queryHashes.forEach((entry) => {
      const normalized = String(entry || "").trim().toLowerCase();
      if (normalized) queryHashIndex.set(normalized, true);
    });
  }
  const entries = [];
  for (const found of founds) {
    const plaintext = String(found?.plaintext || "").trim();
    if (!plaintext) continue;
    const hash = String(found?.hash || "").trim();
    const algorithm = String(found?.algorithm || "Unknown").trim();
    const salt = String(found?.salt || "").trim();
    const labelSuffix = hash
      ? `${hash.slice(0, 12)}…${hash.slice(-8) || ""}`
      : `${algorithm}`;
    const summary = salt
      ? `Reversed ${algorithm} hash (salt=${salt})`
      : `Reversed ${algorithm} hash`;
    // Sanity-check that the resolved hash matches something we
    // actually asked for — a guard against a future hashes.com
    // response shape that drifts and accidentally returns hashes
    // the user never submitted. If the lookup didn't echo a
    // ``hash`` field, we still record the entry (the plaintext is
    // useful on its own) but tag the summary so the user knows.
    const requestedHash = hash
      ? queryHashIndex.has(hash.toLowerCase())
      : false;
    entries.push({
      type: "secret",
      label: `reversed-${algorithm}-${labelSuffix}`,
      source: "hashes-com-reverse",
      content: plaintext,
      summary: requestedHash || !hash
        ? summary
        : `${summary} (unverified origin)`,
      packetIndex: "?",
    });
  }
  return entries;
}

// Pre-fill the reverse-lookup input. Called by the Keystore
// "Send to Hashes" button so a saved secret/cert/key that is already a
// hash doesn't have to be retyped.
function setDataToolsHashReverseInput(value) {
  const inputEl = document.getElementById("data-tools-hash-reverse-input");
  if (!inputEl) return false;
  inputEl.value = String(value || "").trim();
  // Clear the hash computation section above so stale hash outputs
  // don't mislead the user when a hash is sent from another tab.
  resetHashOutputs();
  return true;
}

// Parse common hash hex formats ("0x...", with/without separators, etc.)
// into a single normalized string. We deliberately accept multiple
// lengths (32, 40, 56, 64, 96, 128 hex chars) so users can paste
// MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / RIPEMD-160.
// We do NOT attempt to actually identify the algorithm from the
// length — hashes.com accepts all of these and returns the algorithm
// in the response.
function normalizeDataToolsHashForReverseLookup(rawValue) {
  const text = String(rawValue || "");
  // Strip leading ``0x`` (with or without a separator character after it)
  // and any non-hex / non-separator characters. Keep hex digits only so
  // pasted hashes with stray whitespace, commas, dashes, or colons still
  // come through.
  const stripped = text
    .trim()
    .replace(/^0x\s*/i, "")
    .replace(/[\s,:;\-_./|\\()\[\]{}<>'"`]+/g, "")
    .toLowerCase();
  // Drop any further non-hex bytes (defensive — if the user pastes a
  // long string that isn't a hash, we surface an empty result and let
  // the UI tell them so instead of forwarding garbage to hashes.com).
  const hexOnly = stripped.replace(/[^0-9a-f]/g, "");
  return hexOnly;
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
  clearDecodedImageRegistry();
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
    requestDataToolsBackgroundSummary(activeConvSubtab);
  } catch (error) {
    resetDataToolsOutputs();
    errorEl.textContent =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
  }
}

// Phase 2 of the decoder refactor: text-based wire-protocol decoders (HTTP,
// Telnet, SSH, POP3, IMAP, SMTP, FTP) now live under src/ui/decoders/conv/.
// The local names below preserve the rest of this file unchanged.
const decodeHttpFromBytes = convDecoders.decodeHttpFromBytes;
const decodeTelnetFromBytes = convDecoders.decodeTelnetFromBytes;
const decodeSshFromBytes = convDecoders.decodeSshFromBytes;
const decodePop3FromBytes = convDecoders.decodePop3FromBytes;
const decodeImapFromBytes = convDecoders.decodeImapFromBytes;
const decodeSmtpFromBytes = convDecoders.decodeSmtpFromBytes;
const decodeFtpFromBytes = convDecoders.decodeFtpFromBytes;

// HTTP body-boundary detection helpers (Phase 2.5 of the decoder refactor).
// These are consumed by the file-carver path in main-frontend.js — they used
// to live inline in main-frontend.js but were moved here so the protocol
// decoder module owns all of the HTTP surface.
const extractHttpBodyHex = convDecoders.extractHttpBodyHex;
const findHttpHeaderBodySeparators = convDecoders.findHttpHeaderBodySeparators;
const looksLikeHttpStartLine = convDecoders.looksLikeHttpStartLine;
const sliceHttpMessageSegments = convDecoders.sliceHttpMessageSegments;
const httpHeadersHaveExplicitFraming = convDecoders.httpHeadersHaveExplicitFraming;
const collectHttpMessageBodiesFromStream = convDecoders.collectHttpMessageBodiesFromStream;
const HTTP_FILENAME_EXT_BY_MIME = convDecoders.HTTP_FILENAME_EXT_BY_MIME;
const getHttpBodyFilenameExtension = convDecoders.getHttpBodyFilenameExtension;
const extractFilenameFromContentDisposition = convDecoders.extractFilenameFromContentDisposition;
const extractMultipartBoundaryFromContentType = convDecoders.extractMultipartBoundaryFromContentType;
const extractMultipartFilenameFromBodyBytes = convDecoders.extractMultipartFilenameFromBodyBytes;
const findMultipartFileByteRange = convDecoders.findMultipartFileByteRange;
const findMultipartFileByteRanges = convDecoders.findMultipartFileByteRanges;
const sliceCompleteChunkedHttpBodyHex = convDecoders.sliceCompleteChunkedHttpBodyHex;
const hexToAsciiString = convDecoders.hexToAsciiString;
const isChunkedTransferEncodingHeader = convDecoders.isChunkedTransferEncodingHeader;
const parseContentLengthFromHeaderAscii = convDecoders.parseContentLengthFromHeaderAscii;
const splitHttpMessageHeaders = convDecoders.splitHttpMessageHeaders;

// parseAsn1Length is consumed by decodeLdapFromBytes below; the implementation
// now lives in src/ui/decoders/conv/asn1.js.
const parseAsn1Length = convDecoders.parseAsn1Length;

// Phase 4 of the decoder refactor: app-layer protocol decoders (LDAP, SMB,
// SIP, SMPP, Soulseek, BitTorrent, Kerberos) plus the shared SMB helpers
// now live under src/ui/decoders/conv/. The local names below keep the
// rest of this file unchanged and preserve the existing exports surface.
const normalizeSmbDecoderBytes = convDecoders.normalizeSmbDecoderBytes;
const findBytesSubsequence = convDecoders.findBytesSubsequence;
const parseSmbNtlmSecurityBuffer = convDecoders.parseSmbNtlmSecurityBuffer;
const decodeSmbTextBytes = convDecoders.decodeSmbTextBytes;
const bytesToHexLower = convDecoders.bytesToHexLower;
const extractSmb2CreateFileName = convDecoders.extractSmb2CreateFileName;
const parseDceRpcBind = convDecoders.parseDceRpcBind;
const formatDceRpcUuid = convDecoders.formatDceRpcUuid;
const lookupDceRpcService = convDecoders.lookupDceRpcService;
const decodeLdapFromBytes = convDecoders.decodeLdapFromBytes;
const decodeSmbFromBytes = convDecoders.decodeSmbFromBytes;
const decodeEpmapFromBytes = convDecoders.decodeEpmapFromBytes;
const decodeSipFromBytes = convDecoders.decodeSipFromBytes;
const decodeSmppFromBytes = convDecoders.decodeSmppFromBytes;
const decodeSoulseekFromBytes = convDecoders.decodeSoulseekFromBytes;
const decodeBittorrentFromBytes = convDecoders.decodeBittorrentFromBytes;
const decodeKerberosFromBytes = convDecoders.decodeKerberosFromBytes;
const decodeDnsFromBytes = convDecoders.decodeDnsFromBytes;
const decodeLlmnrFromBytes = convDecoders.decodeLlmnrFromBytes;
const decodeNbnsFromBytes = convDecoders.decodeNbnsFromBytes;
const decodeNbdgmFromBytes = convDecoders.decodeNbdgmFromBytes;
const decodeSnmpFromBytes = convDecoders.decodeSnmpFromBytes;
const decodeDhcpFromBytes = convDecoders.decodeDhcpFromBytes;
const decodeDhcpv6FromBytes = convDecoders.decodeDhcpv6FromBytes;
const decodeIso8583FromBytes = convDecoders.decodeIso8583FromBytes;

// Phase 3 of the decoder refactor: ASN.1 helpers + BER/DER/Protobuf/MessagePack/
// BSON now live under src/ui/decoders/conv/. The local names below keep the
// rest of this file (e.g. decodeLdapFromBytes) unchanged.
const getAsn1TagDescription = convDecoders.getAsn1TagDescription;
const decodeAsn1GenericFromBytes = convDecoders.decodeAsn1GenericFromBytes;
const decodeBerFromBytes = convDecoders.decodeBerFromBytes;
const decodeDerFromBytes = convDecoders.decodeDerFromBytes;
const readVarint = convDecoders.readVarint;
const decodeProtobufFromBytes = convDecoders.decodeProtobufFromBytes;
const decodeMessagePackFromBytes = convDecoders.decodeMessagePackFromBytes;
const decodeBsonFromBytes = convDecoders.decodeBsonFromBytes;

// Phase 1 of the decoder refactor: these implementations now live in
// src/ui/decoders/conv/. The local names below keep the rest of this file
// unchanged and preserve the existing exports surface.
const parseSimpleYamlScalar = convDecoders.parseSimpleYamlScalar;
const parseSimpleYamlKeyValue = convDecoders.parseSimpleYamlKeyValue;
const parseSimpleYamlToObject = convDecoders.parseSimpleYamlToObject;
const parseXmlElementToTreeObject = convDecoders.parseXmlElementToTreeObject;
const formatDataTreeLeafValue = convDecoders.formatDataTreeLeafValue;
const getDataTreeBranchSummary = convDecoders.getDataTreeBranchSummary;
const createDataTreeNode = convDecoders.createDataTreeNode;
const renderStructuredDecoderTree = convDecoders.renderStructuredDecoderTree;
const decodeJsonFromBytes = convDecoders.decodeJsonFromBytes;
const decodeXmlFromBytes = convDecoders.decodeXmlFromBytes;
const decodeHtmlFromBytes = convDecoders.decodeHtmlFromBytes;
const decodeYamlFromBytes = convDecoders.decodeYamlFromBytes;

// Decodes bytes as plain text.
function decodePlainTextFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return {
    protocol: "Plain text",
    fields: [
      { name: "Text", value: rawText },
      { name: "Byte Length", value: String(bytes.length) },
      { name: "Printable ASCII", value: bytesToPrintableAscii(bytes) },
    ],
  };
}

// Phase 5 of the decoder refactor: image decoders + ExifReader helpers now
// live under src/ui/decoders/conv/. The local names below keep the rest of
// this file unchanged and preserve the existing exports surface.
const decodeJpegFromBytes = convDecoders.decodeJpegFromBytes;
const decodePngFromBytes = convDecoders.decodePngFromBytes;
const decodeGifFromBytes = convDecoders.decodeGifFromBytes;
const decodeWebpFromBytes = convDecoders.decodeWebpFromBytes;
const EXIF_FILE_TYPE_TO_PROTO = convDecoders.EXIF_FILE_TYPE_TO_PROTO;
const getImageTypeFromExifReader = convDecoders.getImageTypeFromExifReader;

// Phase 6a of the decoder refactor: protocol/port/MIME hint maps now live
// under src/ui/decoders/conv/ (mime-maps.js, protocol-hints.js). The local
// aliases below keep the rest of this file unchanged and preserve the
// existing exports surface.
const PROTOCOL_DECODER_HINTS = convDecoders.PROTOCOL_DECODER_HINTS;
const PORT_DECODER_HINTS = convDecoders.PORT_DECODER_HINTS;
const MIME_TO_PROTO = convDecoders.MIME_TO_PROTO;

// Phase 6b of the decoder refactor: getPacketProtocolDecoderHint and
// autoDetectProtoFromBytes are pure (no DOM / no module state) and now live
// under src/ui/decoders/conv/auto-detect.js. The local names below keep the
// rest of this file unchanged and preserve the existing exports surface.
const getPacketProtocolDecoderHint = convDecoders.getPacketProtocolDecoderHint;
const autoDetectProtoFromBytes = convDecoders.autoDetectProtoFromBytes;

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
  if (result.imageDataUrl) {
    registerDecodedImage(result);
    const img = document.createElement("img");
    img.src = result.imageDataUrl;
    img.style.maxWidth = "100%";
    img.style.maxHeight = "400px";
    img.style.objectFit = "contain";
    img.style.display = "block";
    img.style.margin = "0 auto 12px auto";
    protoOutput.appendChild(img);
    if (result.fields && result.fields.length > 0) {
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
    return;
  }
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

// Runs the selected protocol decoder against the supplied bytes. Returns the
// decoded result object (or null when the selected protocol cannot decode
// the bytes). Pulled out of runProtoDecoder so the per-packet stream path
// can reuse the same protocol→function switch without duplicating it.
function decodeWithSelectedProtocol(bytes, protocol) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  if (!protocol) return null;
  switch (protocol) {
    case "http":
      return decodeHttpFromBytes(bytes);
    case "telnet":
      return decodeTelnetFromBytes(bytes);
    case "ssh":
      return decodeSshFromBytes(bytes);
    case "pop3":
      return decodePop3FromBytes(bytes);
    case "imap":
      return decodeImapFromBytes(bytes);
    case "smtp":
      return decodeSmtpFromBytes(bytes);
    case "ftp":
      return decodeFtpFromBytes(bytes);
    case "ber":
      return decodeBerFromBytes(bytes);
    case "der":
      return decodeDerFromBytes(bytes);
    case "json":
      return decodeJsonFromBytes(bytes);
    case "xml":
      return decodeXmlFromBytes(bytes);
    case "html":
      return decodeHtmlFromBytes(bytes);
    case "yaml":
      return decodeYamlFromBytes(bytes);
    case "protobuf":
      return decodeProtobufFromBytes(bytes);
    case "msgpack":
      return decodeMessagePackFromBytes(bytes);
    case "bson":
      return decodeBsonFromBytes(bytes);
    case "ldap":
      return decodeLdapFromBytes(bytes);
    case "smb":
      return decodeSmbFromBytes(bytes);
    case "epmap":
      return decodeEpmapFromBytes(bytes);
    case "sip":
      return decodeSipFromBytes(bytes);
    case "smpp":
      return decodeSmppFromBytes(bytes);
    case "soulseek":
      return decodeSoulseekFromBytes(bytes);
    case "bittorrent":
      return decodeBittorrentFromBytes(bytes);
    case "kerberos":
      return decodeKerberosFromBytes(bytes);
    case "dns":
      return decodeDnsFromBytes(bytes);
    case "llmnr":
      return decodeLlmnrFromBytes(bytes);
    case "nbns":
      return decodeNbnsFromBytes(bytes);
    case "nbdgm":
      return decodeNbdgmFromBytes(bytes);
    case "snmp":
      return decodeSnmpFromBytes(bytes);
    case "dhcp":
      return decodeDhcpFromBytes(bytes);
    case "dhcpv6":
      return decodeDhcpv6FromBytes(bytes);
    case "iso8583":
      return decodeIso8583FromBytes(bytes);
    case "plaintext":
      return decodePlainTextFromBytes(bytes);
    case "jpeg":
      return decodeJpegFromBytes(bytes);
    case "png":
      return decodePngFromBytes(bytes);
    case "gif":
      return decodeGifFromBytes(bytes);
    case "webp":
      return decodeWebpFromBytes(bytes);
    default:
      return null;
  }
}

// Renders one decode block in the stacked stream view. Mirrors the structure
// of the single-blob renderProtoDecoderOutput table but does NOT write to the
// shared dataset.decodedResult (which is reserved for the "active" result).
function appendStreamPacketBlock(protoOutput, blockEl, result, selectedProtocol, protocol, blockLabel) {
  if (!protoOutput || !blockEl) return;
  if (!result) {
    const span = document.createElement("div");
    span.className = "data-tools-proto-none data-tools-proto-stream-empty";
    span.textContent = selectedProtocol === "auto"
      ? "No known protocol detected"
      : `Could not decode as ${(protocol || selectedProtocol).toUpperCase()}`;
    blockEl.appendChild(span);
    if (blockLabel) {
      const note = document.createElement("div");
      note.className = "data-tools-proto-stream-block-note";
      note.textContent = blockLabel;
      blockEl.appendChild(note);
    }
    protoOutput.appendChild(blockEl);
    return;
  }

  if (result.imageDataUrl) {
    registerDecodedImage(result);
    const img = document.createElement("img");
    img.src = result.imageDataUrl;
    img.style.maxWidth = "100%";
    img.style.maxHeight = "300px";
    img.style.objectFit = "contain";
    img.style.display = "block";
    img.style.margin = "0 auto 12px auto";
    blockEl.appendChild(img);
  } else if (result.treeData) {
    // For structured results (JSON/XML/YAML/HTML) we delegate to the shared
    // tree renderer but into our block element rather than the panel root.
    const treeHost = document.createElement("div");
    treeHost.className = "data-tools-proto-stream-tree";
    blockEl.appendChild(treeHost);
    if (!renderStructuredDecoderTree(treeHost, result)) {
      treeHost.remove();
    }
  } else if (Array.isArray(result.fields) && result.fields.length) {
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
    blockEl.appendChild(table);
  }
  if (blockLabel) {
    const note = document.createElement("div");
    note.className = "data-tools-proto-stream-block-note";
    note.textContent = blockLabel;
    blockEl.appendChild(note);
  }
  protoOutput.appendChild(blockEl);
}

// Decodes a stream's per-packet byte slices and renders the results as a
// vertical stack (newest packet at the top, oldest at the bottom) in the
// Decodes subtab. The first packet to decode successfully is also exposed
// via activeDataToolsProtoResult / protoOutput.dataset.decodedResult so the
// existing "get active decoder result" helpers still work.
function runProtoDecoderForStreamPackets(streamPackets, options = {}) {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (!protoOutput) return;
  const packets = Array.isArray(streamPackets) ? streamPackets : [];
  if (!packets.length) {
    activeDataToolsProtoResult = null;
    protoOutput.innerHTML = "";
    delete protoOutput.dataset.decodedResult;
    const span = document.createElement("span");
    span.className = "data-tools-proto-none";
    span.textContent = "Stream has no payload data to decode.";
    protoOutput.appendChild(span);
    return;
  }

  const selectEl = document.getElementById("data-tools-proto-select");
  const selectedProtocol = selectEl ? selectEl.value : "auto";
  // For stacked rendering we need a stable protocol for every packet. If
  // the dropdown is on "auto" we try the hint on the first packet and fall
  // back to per-packet auto-detection. Once chosen we keep that protocol
  // across all packets so the panel shows homogeneous results.
  const contextPacket = _getCurrentContextPacket() || null;
  let resolvedProtocol = selectedProtocol;
  if (resolvedProtocol === "auto") {
    const firstPacketInfo = packets[0]?.info || null;
    const hintPacket = contextPacket || (firstPacketInfo && firstPacketInfo.packet) || null;
    const { protocolHint, portHint } = getPacketProtocolDecoderHint(hintPacket);
    const firstBytes = packets[0].bytes;
    const firstDetected = autoDetectProtoFromBytes(firstBytes, {
      protocolHint,
      portHint,
    });
    resolvedProtocol = firstDetected || "auto";
    if (selectEl && resolvedProtocol && selectEl.value !== resolvedProtocol && resolvedProtocol !== "auto") {
      selectEl.value = resolvedProtocol;
    }
  }

  // Render newest-first: walk the list in reverse so the most recent packet
  // appears at the top of the panel. We capture the first non-null result
  // (oldest in iteration order) for activeDataToolsProtoResult so the
  // existing single-result export helpers keep working. When the user has
  // toggled the hide-no-op filter, packets whose bytes do not produce a
  // decoder result are skipped here so the stack only shows packets with
  // decodable data.
  protoOutput.innerHTML = "";
  delete protoOutput.dataset.decodedResult;
  const summary = document.createElement("div");
  summary.className = "data-tools-proto-stream-summary";
  const protocolLabel = resolvedProtocol && resolvedProtocol !== "auto"
    ? resolvedProtocol.toUpperCase()
    : "AUTO";
  summary.textContent = `Decoded ${packets.length} packet${packets.length === 1 ? "" : "s"} as ${protocolLabel} (newest first).`;
  protoOutput.appendChild(summary);

  let firstSuccessfulResult = null;
  let renderedCount = 0;
  let hiddenCount = 0;
  const totalCount = packets.length;
  const hideNoOp = convDecodesHideNoOp === true;
  for (let reverseIndex = 0; reverseIndex < totalCount; reverseIndex += 1) {
    const packetIndex = totalCount - 1 - reverseIndex;
    const entry = packets[packetIndex] || {};
    const bytes = entry.bytes;
    const info = entry.info || {};
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) continue;
    const result = resolvedProtocol && resolvedProtocol !== "auto"
      ? decodeWithSelectedProtocol(bytes, resolvedProtocol)
      : decodeWithSelectedProtocol(bytes, autoDetectProtoFromBytes(bytes));
    if (!firstSuccessfulResult) firstSuccessfulResult = result;
    if (hideNoOp && !result) {
      hiddenCount += 1;
      continue;
    }
    const block = document.createElement("div");
    block.className = "data-tools-proto-stream-block";
    const header = document.createElement("div");
    header.className = "data-tools-proto-stream-header";
    const headerText = info.packetIndex !== undefined && info.packetIndex !== null
      ? `Packet ${info.packetIndex} of ${totalCount}`
      : `Packet ${packetIndex + 1} of ${totalCount}`;
    header.textContent = `${headerText} (${bytes.length} byte${bytes.length === 1 ? "" : "s"})`;
    block.appendChild(header);
    const blockLabel = info.sourceKey ? `Source: ${info.sourceKey}` : null;
    appendStreamPacketBlock(protoOutput, block, result, selectedProtocol, resolvedProtocol, blockLabel);
    renderedCount += 1;
  }

  // Annotate the summary line with shown / hidden counts when the filter is
  // active so analysts can tell at a glance how many no-op packets were
  // suppressed. Counts derive from the post-filter render so they reflect
  // what is actually visible in the panel.
  if (hideNoOp) {
    const hiddenNote = document.createElement("span");
    hiddenNote.className = "data-tools-proto-stream-summary-hidden";
    hiddenNote.textContent = ` (${renderedCount} shown, ${hiddenCount} no-op hidden)`;
    summary.appendChild(hiddenNote);
  }

  // If the hide-no-op filter is active and every packet failed to decode,
  // show an explicit empty-state message so the panel isn't an unhelpful
  // blank area below the summary line. The summary still reports the
  // hidden count so analysts can tell whether the filter is suppressing
  // anything.
  if (hideNoOp && renderedCount === 0 && totalCount > 0) {
    const empty = document.createElement("div");
    empty.className = "data-tools-proto-none";
    empty.textContent = `No packets with decodable data in this stream. Uncheck the option above to see all ${totalCount} packets.`;
    protoOutput.appendChild(empty);
  }

  if (firstSuccessfulResult) {
    activeDataToolsProtoResult = firstSuccessfulResult;
    protoOutput.dataset.decodedResult = JSON.stringify({
      protocol: firstSuccessfulResult.protocol,
      fields: Array.isArray(firstSuccessfulResult.fields)
        ? firstSuccessfulResult.fields
        : [],
    });
  } else {
    activeDataToolsProtoResult = null;
  }

  if (options && options.requestSummary && activeConvSubtab === CONV_DECODES_SUBTAB) {
    requestDataToolsBackgroundSummary(CONV_DECODES_SUBTAB);
  }
}

// Runs proto decoder.
function runProtoDecoder(bytes) {
  // When an entire stream has been loaded into the Decodes subtab we render
  // each packet's bytes as a separate stacked block (newest first) instead
  // of decoding the concatenated stream as a single blob. This makes the
  // panel behave the way an analyst expects: each row corresponds to a
  // captured packet rather than a single arbitrary parse of the merged
  // byte stream.
  if (Array.isArray(dataToolsStreamPackets) && dataToolsStreamPackets.length > 0) {
    runProtoDecoderForStreamPackets(dataToolsStreamPackets, { requestSummary: true });
    return;
  }
  const selectEl = document.getElementById("data-tools-proto-select");
  const selectedProtocol = selectEl ? selectEl.value : "auto";
  let protocol = selectedProtocol;
  if (protocol === "auto") {
    const contextPacket = _getCurrentContextPacket();
    const { protocolHint, portHint } = getPacketProtocolDecoderHint(contextPacket);
    protocol = autoDetectProtoFromBytes(bytes, {
      protocolHint,
      portHint,
    });
    if (selectEl && protocol && selectEl.value !== protocol) {
      selectEl.value = protocol;
    }
  }
  const actualImageType = getImageTypeFromExifReader(bytes);
  const isImageProtocolSelected = ["jpeg", "png", "gif", "webp"].includes(protocol);
  // If the user explicitly selected an image decoder and the bytes are not
  // actually that image type (per ExifReader), bail out so we don't render a
  // broken preview / wrong metadata.
  if (isImageProtocolSelected && actualImageType && actualImageType !== protocol) {
    renderProtoDecoderOutput(null, selectedProtocol, protocol);
    return;
  }
  const result = decodeWithSelectedProtocol(bytes, protocol);
  const resolvedProtocol = result ? protocol : null;
  renderProtoDecoderOutput(result, selectedProtocol, resolvedProtocol);
  if (activeConvSubtab === CONV_DECODES_SUBTAB) {
    requestDataToolsBackgroundSummary(CONV_DECODES_SUBTAB);
  }
}

// Clears proto decoder output.
function clearProtoDecoderOutput() {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (protoOutput) {
    protoOutput.innerHTML = "";
    delete protoOutput.dataset.decodedResult;
  }
  // Note: we deliberately do NOT drop dataToolsStreamPackets here. This
  // function is also invoked when the payload is large and we're sitting on
  // a non-Decodes subtab — at that point the per-packet stream association
  // must survive so the stacked render shows again when the user switches
  // back to Decodes. Full-reset paths (resetDataToolsOutputs and the
  // entry-point loaders in main-frontend.js) clear the stream state
  // explicitly via clearDataToolsStreamPackets().
}

// Registers a decoded image in the registry so it can be embedded in the
// HTML summary export near the context where it was decoded.
function registerDecodedImage(result) {
  if (!result || !result.imageDataUrl) return;
  const packet = _getCurrentContextPacket();
  const packetKey = packet?.__packetKey || "";
  const activeMainTab = _getActiveMainTab();
  const id = `img-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 8)}`;
  const mimeMatch = String(result.imageDataUrl).match(
    /^data:([^;]+);base64,/i,
  );
  const mime = mimeMatch ? mimeMatch[1] : "image/octet-stream";
  decodedImageRegistry.push({
    id,
    protocol: result.protocol || "image",
    mime,
    imageDataUrl: result.imageDataUrl,
    packetKey,
    convSubtab: activeConvSubtab,
    activeMainTab,
    decodedAt: Date.now(),
  });
  if (decodedImageRegistry.length > MAX_DECODED_IMAGE_REGISTRY_SIZE) {
    decodedImageRegistry.splice(
      0,
      decodedImageRegistry.length - MAX_DECODED_IMAGE_REGISTRY_SIZE,
    );
  }
}

function getDecodedImageRegistry() {
  return decodedImageRegistry.slice();
}

function clearDecodedImageRegistry() {
  decodedImageRegistry = [];
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
  const extractionActive = tabName === CONV_EXTRACTION_SUBTAB;
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
    .getElementById("conv-subtab-extraction")
    .classList.toggle("active", extractionActive);
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
  document.getElementById("conv-extraction-panel").hidden = !extractionActive;
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
  CONV_EXTRACTION_SUBTAB,
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
  getDecodedImageRegistry,
  clearDecodedImageRegistry,
  // Functions
  parseDataToolsInput,
  bytesToPrintableAscii,
  decodeHttpFromBytes,
  extractHttpBodyHex,
  findHttpHeaderBodySeparators,
  looksLikeHttpStartLine,
  sliceHttpMessageSegments,
  httpHeadersHaveExplicitFraming,
  collectHttpMessageBodiesFromStream,
  HTTP_FILENAME_EXT_BY_MIME,
  getHttpBodyFilenameExtension,
  extractFilenameFromContentDisposition,
  extractMultipartBoundaryFromContentType,
  extractMultipartFilenameFromBodyBytes,
  findMultipartFileByteRange,
  findMultipartFileByteRanges,
  sliceCompleteChunkedHttpBodyHex,
  hexToAsciiString,
  isChunkedTransferEncodingHeader,
  parseContentLengthFromHeaderAscii,
  splitHttpMessageHeaders,
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
  decodeHtmlFromBytes,
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
  decodeJpegFromBytes,
  decodePngFromBytes,
  decodeGifFromBytes,
  decodeWebpFromBytes,
  decodePlainTextFromBytes,
  autoDetectProtoFromBytes,
  resetDataToolsOutputs,
  renderProtoDecoderOutput,
  runProtoDecoder,
  runProtoDecoderForStreamPackets,
  decodeWithSelectedProtocol,
  formatHexInputBytes,
  clearProtoDecoderOutput,
  setDataToolsStreamPackets,
  getDataToolsStreamPackets,
  clearDataToolsStreamPackets,
  getConvDecodesHideNoOp,
  setConvDecodesHideNoOp,
  runDataToolsConversion,
  runDataToolsHashesFromInput,
  setHashInputReadingFromBytes,
  computeDataToolsHashes,
  renderCryptHashesFromConvInput,
  crossReferenceCurrentHash,
  runDataToolsHashReverseLookup,
  runDataToolsHashIdentify,
  setDataToolsHashReverseInput,
  normalizeDataToolsHashForReverseLookup,
  formatUnmatchedHashLine,
  buildHashReverseKeystoreEntries,
  showDataTools,
  setConvSubtab,
  getPacketProtocolDecoderHint,
  EXIF_FILE_TYPE_TO_PROTO,
  getImageTypeFromExifReader,
  clearDataToolsSummary,
  requestDataToolsBackgroundSummary,
};
