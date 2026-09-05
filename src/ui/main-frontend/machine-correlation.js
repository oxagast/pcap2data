"use strict";

const { computeMachineCorrelation } = require("../../session-merge");

const CORRELATION_STATE_VERSION = 1;

function clone(value) {
    if (Array.isArray(value)) return value.map(clone);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
}

function getPacketKey(packet, host, index) {
    return String(
        packet?.__packetKey
        || packet?.["packet.info"]?.["capture.packetId"]
        || `${host}$${index}`,
    );
}

function createMachineCorrelationHelpers({
    documentRef = document,
    getCapturedPackets,
    getCurrentSettings,
    getCurrentPacket,
    getCurrentHost,
    getSourceColor,
    refreshList,
    refreshStats,
    writeLogEntry,
}) {
    let correlation = null;
    let enabled = false;
    let collapseEnabled = false;
    const listeners = new Set();

    const notify = () => listeners.forEach((listener) => {
        try {
            listener(getState());
        } catch (_error) {
            // UI refresh callbacks must not break the correlation state machine.
        }
    });

    const getState = () => ({
        version: CORRELATION_STATE_VERSION,
        enabled,
        collapseEnabled,
        correlation: correlation ? clone(correlation) : null,
    });

    const updateButtons = () => {
        const snapButton = documentRef.getElementById("snap-correlate-btn");
        const collapseButton = documentRef.getElementById("collapse-entities-btn");
        if (snapButton) {
            snapButton.classList.toggle("active", enabled);
            snapButton.setAttribute("aria-pressed", String(enabled));
            snapButton.value = enabled ? "Snap & Correlate: On" : "Snap & Correlate";
        }
        if (collapseButton) {
            collapseButton.classList.toggle("active", collapseEnabled);
            collapseButton.setAttribute("aria-pressed", String(collapseEnabled));
            collapseButton.value = collapseEnabled ? "Collapse Entities: On" : "Collapse Entities";
            collapseButton.disabled = !correlation;
        }
    };

    const getPacketMatch = (packet, host, index) => {
        if (!correlation?.packetMatches || !packet) return null;
        const packetInfo = packet?.["packet.info"] || {};
        const candidateHosts = [
            packetInfo["capture.sourceHost"],
            host,
        ].filter((value, position, values) => (
            typeof value === "string" && value.trim() && values.indexOf(value) === position
        ));
        for (const candidateHost of candidateHosts) {
            const match = correlation.packetMatches[getPacketKey(packet, candidateHost, index)];
            if (match) return match;
        }
        return null;
    };

    const getVerifiedCount = (host, packet, index) => {
        if (!enabled || !correlation) return null;
        const packetMatch = getPacketMatch(packet, host, index);
        if (packetMatch?.verifiedAcrossPcaps) return packetMatch.verifiedAcrossPcaps;
        // Packet-level readouts must not silently become group-level counts.
        // A group count answers a different question and caused Host Data and
        // List to disagree when the exact packet was not present in every pcap.
        if (packet) return null;
        const groupId = correlation.hostToGroup?.[host];
        const group = correlation.groups?.find((entry) => entry.groupId === groupId);
        return group?.verifiedAcrossPcaps || null;
    };

    const getCollapsedHostKey = (host) => {
        if (!collapseEnabled || !correlation) return host;
        const groupId = correlation.hostToGroup?.[host];
        return groupId ? `Entity ${groupId.replace(/^machine-/, "")}` : host;
    };

    const normalizeHexColor = (value) => {
        const match = String(value || "").trim().match(/^#([0-9a-f]{6})$/i);
        return match ? match[1].toLowerCase() : null;
    };

    const blendColors = (colors) => {
        const channels = colors
            .map(normalizeHexColor)
            .filter(Boolean)
            .map((hex) => [0, 1, 2].map((index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)));
        if (channels.length < 2) return null;
        const blended = [0, 1, 2].map((index) => Math.round(
            channels.reduce((total, color) => total + color[index], 0) / channels.length,
        ));
        return `#${blended.map((value) => value.toString(16).padStart(2, "0")).join("")}`;
    };

    const getPacketPresentation = (host, packet, index) => {
        const packetMatch = getPacketMatch(packet, host, index);
        if (!packetMatch) {
            return {
                verifiedAcrossPcaps: null,
                sourceNames: [],
                color: null,
            };
        }
        const sources = Array.isArray(packetMatch.verifiedSources) ? packetMatch.verifiedSources : [];
        const sourceNames = sources.map((source) => source.sourceName || source.sourceId).filter(Boolean);
        const colors = sources
            .map((source) => getSourceColor?.(source.sourceId))
            .filter(Boolean);
        return {
            verifiedAcrossPcaps: packetMatch.verifiedAcrossPcaps || null,
            sourceNames,
            color: sources.length > 1 ? blendColors(colors) : null,
        };
    };

    const updateVerifiedReadout = (context = {}) => {
        const readout = documentRef.getElementById("verified-across-pcaps");
        if (!readout) return;
        const packetContext = context.packet
            ? context
            : typeof getCurrentPacket === "function" ? getCurrentPacket() : null;
        const host = context.host
            || (typeof getCurrentHost === "function" ? getCurrentHost() : "");
        const count = getVerifiedCount(host, packetContext?.packet, packetContext?.index);
        readout.textContent = count ? `Verified across ${count} pcaps` : "Verified across: —";
    };

    const runCorrelation = () => {
        const captureData = typeof getCapturedPackets === "function" ? getCapturedPackets() : null;
        if (!captureData?.host) return null;
        const configuredThreshold = getCurrentSettings?.()?.merge?.timestampSnapThresholdMs;
        correlation = computeMachineCorrelation(captureData, { thresholdMs: configuredThreshold });
        enabled = true;
        collapseEnabled = false;
        updateButtons();
        updateVerifiedReadout();
        refreshList?.();
        refreshStats?.();
        writeLogEntry?.(`[machine-correlation] ${correlation.groups.length} groups, ${correlation.anomalies.length} cross-capture anomalies`);
        notify();
        return correlation;
    };

    const toggleSnapCorrelate = () => {
        if (enabled) {
            enabled = false;
            collapseEnabled = false;
            updateButtons();
            updateVerifiedReadout();
            refreshList?.();
            refreshStats?.();
            notify();
            return null;
        }
        return runCorrelation();
    };

    const toggleCollapse = () => {
        if (!correlation) return false;
        collapseEnabled = !collapseEnabled;
        updateButtons();
        refreshList?.();
        notify();
        return collapseEnabled;
    };

    const restore = (savedState) => {
        const savedCorrelation = savedState?.correlation || savedState;
        correlation = savedCorrelation?.groups ? clone(savedCorrelation) : null;
        enabled = Boolean(savedState?.enabled && correlation);
        collapseEnabled = Boolean(savedState?.collapseEnabled && correlation);
        updateButtons();
        updateVerifiedReadout();
        notify();
    };

    documentRef.getElementById("snap-correlate-btn")?.addEventListener("click", toggleSnapCorrelate);
    documentRef.getElementById("collapse-entities-btn")?.addEventListener("click", toggleCollapse);
    updateButtons();

    return {
        getState,
        getCorrelation: () => correlation,
        getAnomalies: () => correlation?.anomalies || [],
        getVerifiedCount,
        getPacketPresentation,
        getCollapsedHostKey,
        refreshVerifiedReadout: updateVerifiedReadout,
        isEnabled: () => enabled,
        isCollapseEnabled: () => collapseEnabled,
        onChange: (listener) => {
            if (typeof listener !== "function") return () => { };
            listeners.add(listener);
            return () => listeners.delete(listener);
        },
        restore,
        runCorrelation,
        toggleSnapCorrelate,
        toggleCollapse,
    };
}

module.exports = { createMachineCorrelationHelpers };