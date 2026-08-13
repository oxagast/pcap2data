// Renders SSH packet details into the shared sidebar table UI.
// Includes timing side-channel analysis for keystroke interval
// detection (MAD-based score, burst detection, z-score anomaly).

const { createTable, dotField } = require("./shared");

// ── Timing analysis constants ────────────────────────────────────────────
const TIMING_MIN_SAMPLES = 3;
const TIMING_KEYSTROKE_THRESHOLD_MS = 50;
const TIMING_MODERATE_THRESHOLD_MS = 200;
const TIMING_BURST_THRESHOLD_MS = 100;
const TIMING_ANOMALY_Z_THRESHOLD = 2;
const TIMING_DEFAULT_LOG_SIZE = 100;

// ── Pure timing helpers (testable, no DOM access) ──────────────────────

/**
 * Append a new inter-packet delay to the running history, dropping the
 * oldest sample once `maxLogSize` is exceeded. Returns a new array; does
 * not mutate the input.
 */
function recordDelay(delays, interPacketDelay, maxLogSize) {
  if (interPacketDelay === null || interPacketDelay === undefined) {
    return delays.slice();
  }
  const next = delays.concat([interPacketDelay]);
  if (next.length > maxLogSize) {
    next.shift();
  }
  return next;
}

/** Median of a (non-empty) numeric array. */
function median(values) {
  if (values.length === 0) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

/**
 * Median Absolute Deviation — robust measure of variability. Lower MAD
 * means more uniform intervals (typical of automated/keystroke traffic).
 */
function computeMad(values) {
  if (values.length === 0) return null;
  const med = median(values);
  if (med === null) return null;
  const deviations = values.map(v => Math.abs(v - med));
  return median(deviations);
}

/** Classify MAD into the same bins the UI uses. */
function classifyMad(mad) {
  if (mad === null) return { label: "—", className: "" };
  if (mad < TIMING_KEYSTROKE_THRESHOLD_MS) {
    return { label: mad.toFixed(1) + " ms — Low (keystroke-like)", className: "timing-low" };
  }
  if (mad < TIMING_MODERATE_THRESHOLD_MS) {
    return { label: mad.toFixed(1) + " ms — Moderate", className: "timing-moderate" };
  }
  return { label: mad.toFixed(1) + " ms — High (non-keystroke)", className: "timing-high" };
}

/** Classify a single inter-packet delay as a burst or normal sample. */
function classifyBurst(interPacketDelay) {
  if (interPacketDelay === null || interPacketDelay === undefined) {
    return "—";
  }
  return interPacketDelay < TIMING_BURST_THRESHOLD_MS
    ? "Yes (Burst)"
    : "No (Normal)";
}

/** Population standard deviation (0 when all samples equal). */
function stddev(values) {
  if (values.length === 0) return 0;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance =
    values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

/**
 * Z-score of a sample vs a population's mean/stddev. Returns null when
 * the population is empty.
 */
function zScore(sample, population) {
  if (population.length === 0) return null;
  const mean = population.reduce((s, v) => s + v, 0) / population.length;
  const std = stddev(population);
  if (std === 0) return 0;
  return (sample - mean) / std;
}

/** Classify a z-score as anomalous or normal. */
function classifyAnomaly(z) {
  if (z === null) return { label: "—", className: "" };
  if (z === 0) {
    return { label: "z = 0.00 — No variance", className: "" };
  }
  if (Math.abs(z) > TIMING_ANOMALY_Z_THRESHOLD) {
    return { label: "z = " + z.toFixed(2) + " — Anomalous", className: "timing-high" };
  }
  return { label: "z = " + z.toFixed(2) + " — Normal", className: "timing-low" };
}

/**
 * Build the four timing side-channel rows appended to the SSH info
 * table. Pure function: takes the current delays history and the new
 * sample, returns row objects. The caller is responsible for mutating
 * the persistent state.
 */
function buildTimingRows(delays, interPacketDelay) {
  const delayStr =
    interPacketDelay === null || interPacketDelay === undefined
      ? "—"
      : interPacketDelay.toFixed(1) + " ms";

  // MAD score
  let keystrokeScoreStr = "—";
  let keystrokeClass = "";
  if (delays.length >= TIMING_MIN_SAMPLES) {
    const mad = computeMad(delays);
    const cls = classifyMad(mad);
    keystrokeScoreStr = cls.label;
    keystrokeClass = cls.className;
  } else if (delays.length > 0) {
    keystrokeScoreStr =
      "Insufficient data (" + delays.length + "/" + TIMING_MIN_SAMPLES + " packets)";
  }

  const burstStr = classifyBurst(interPacketDelay);

  // Z-score anomaly
  let anomalyStr = "—";
  let anomalyClass = "";
  if (
    interPacketDelay !== null &&
    interPacketDelay !== undefined &&
    delays.length >= TIMING_MIN_SAMPLES
  ) {
    const z = zScore(interPacketDelay, delays);
    const cls = classifyAnomaly(z);
    anomalyStr = cls.label;
    anomalyClass = cls.className;
  } else if (delays.length > 0) {
    anomalyStr =
      "Insufficient data (" + delays.length + "/" + TIMING_MIN_SAMPLES + " packets)";
  }

  return [
    { name: "Inter-Packet Delay (Δ)", value: delayStr },
    { name: "Keystroke Timing Score (MAD)", value: keystrokeScoreStr, className: keystrokeClass },
    { name: "Burst Detection (<100 ms)", value: burstStr },
    { name: "Timing Anomaly Score (z)", value: anomalyStr, className: anomalyClass },
  ];
}

// ── Module-local timing state ───────────────────────────────────────────
//
// State persists across packets in the same detail-view session so that
// inter-packet delays accumulate. Call `resetSshTimingState()` (or
// restart the renderer) to start over.
let sshTimingState = {
  lastPacketTimestamp: null,
  interPacketDelays: [],
  maxLogSize: TIMING_DEFAULT_LOG_SIZE,
};

function resetSshTimingState() {
  sshTimingState.lastPacketTimestamp = null;
  sshTimingState.interPacketDelays = [];
  sshTimingState.maxLogSize = TIMING_DEFAULT_LOG_SIZE;
}

// ── Rendering ───────────────────────────────────────────────────────────

function renderSshTable(transportData, packetTimestamp = null) {
  const sshData = transportData["SSH"];
  if (!sshData) return;

  const sshRows = [
    { name: "Type", value: sshData["Type"] || "—" },
    { name: "Direction", value: sshData["Direction"] || "—" },
    { name: "Banner", value: sshData["Banner"] || "—" },
    { name: "Protocol Version", value: dotField(sshData, "ssh.protocol_version", "Protocol Version") },
    { name: "Software Version", value: dotField(sshData, "ssh.software_version", "Software Version") },
    { name: "Comments", value: sshData["Comments"] || "—" },
    { name: "Packet Length", value: dotField(sshData, "ssh.packet_length", "Packet Length") },
    { name: "Padding Length", value: dotField(sshData, "ssh.padding_length", "Padding Length") },
    { name: "Message Type", value: dotField(sshData, "ssh.msg_type", "Message Type") },
    {
      name: "Likely Encrypted",
      value:
        (sshData["ssh.likely_encrypted"] ?? sshData["Likely Encrypted"]) === undefined
          ? "—"
          : (sshData["ssh.likely_encrypted"] ?? sshData["Likely Encrypted"])
            ? "Yes"
            : "No",
    },
  ];

  // ── Update timing state with this packet's sample ──────────────────────
  const prevTs = sshTimingState.lastPacketTimestamp;
  let interPacketDelay = null;
  if (packetTimestamp !== null && prevTs !== null) {
    interPacketDelay = packetTimestamp - prevTs; // ms (already numeric)
  }
  sshTimingState.interPacketDelays = recordDelay(
    sshTimingState.interPacketDelays,
    interPacketDelay,
    sshTimingState.maxLogSize,
  );
  sshTimingState.lastPacketTimestamp = packetTimestamp;

  sshRows.push(
    ...buildTimingRows(sshTimingState.interPacketDelays, interPacketDelay),
  );

  createTable(sshRows, ["SSH Field", "Value"], "sidedatatable");
}

module.exports = {
  renderSshTable,
  resetSshTimingState,
  // Pure helpers exposed for unit tests; not part of the renderer API.
  _internals: {
    recordDelay,
    median,
    computeMad,
    classifyMad,
    classifyBurst,
    stddev,
    zScore,
    classifyAnomaly,
    buildTimingRows,
  },
};
