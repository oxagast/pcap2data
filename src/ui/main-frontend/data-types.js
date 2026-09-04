// Provides data-type detection and labeling helpers for packet and conversion views.

function createDataTypeHelpers({
    constants,
    state,
    getPacketInfoPayloadLength,
    setPrevNextButtonVisibility,
}) {
    function getPacketDataTypeItems(packetEntry) {
        const extraInfo = packetEntry?.["extra.info"] || {};
        const traits = extraInfo["Traits"] || {};
        const serverInfo = traits["Server Info"] || {};
        const networkData = traits["Network Data"] || {};
        let dataItems = Array.isArray(extraInfo["Data Types"])
            ? [...extraInfo["Data Types"]]
            : [];

        if (
            serverInfo["Encryption Data"] != "N/A"
            && serverInfo["Encryption Data"] != undefined
        ) {
            const sslDetails = serverInfo["Encryption Data"]?.["SSL Version"] ?? "Unknown";
            const protoName =
                networkData["Port Protocol"] ?? networkData["Port Protcol"] ?? "Unknown";
            dataItems = [];
            dataItems.push(sslDetails + " encrypted stream");
            dataItems.push(protoName + " protocol data");
        }

        return dataItems;
    }

    function normalizeProtocolToken(value) {
        return String(value ?? "")
            .trim()
            .toUpperCase()
            .replace(/[^A-Z0-9]/g, "");
    }

    function collectPacketProtocolTokens(packetEntry) {
        const packetInfo = packetEntry?.["packet.info"] || {};
        const extraInfo = packetEntry?.["extra.info"] || {};
        const traits = extraInfo["Traits"] || {};
        const networkData = traits["Network Data"] || {};
        const tokens = new Set();

        const pushToken = (value) => {
            if (value == null) return;
            if (Array.isArray(value)) {
                value.forEach((item) => pushToken(item));
                return;
            }
            const text = String(value).trim();
            if (!text) return;
            const normalizedWhole = normalizeProtocolToken(text);
            if (normalizedWhole) tokens.add(normalizedWhole);
            text.split(/[^A-Za-z0-9]+/).forEach((segment) => {
                const normalized = normalizeProtocolToken(segment);
                if (normalized) tokens.add(normalized);
            });
        };

        pushToken(packetInfo["packet.proto"] ?? packetInfo["Protocol"]);
        pushToken(packetInfo["packet.decoded_protocols"] ?? packetInfo["Decoded Protocols"]);
        pushToken(packetInfo["Link Control"]);
        pushToken(networkData["Port Protocol"]);
        pushToken(networkData["Port Protcol"]);
        pushToken(networkData["Port Description"]);

        return [...tokens];
    }

    function getMatchedHiddenDataTypeProtocol(packetEntry) {
        const protocolTokens = collectPacketProtocolTokens(packetEntry);
        for (const token of protocolTokens) {
            if (constants.hiddenProtocols.has(token)) {
                return token;
            }
            if (
                constants.hiddenProtocolPrefixes.some((prefix) =>
                    token.startsWith(prefix),
                )
            ) {
                return token;
            }
        }
        return "";
    }

    function hasLikelyFileLikeDataTypes(packetEntry, dataItems) {
        const extraInfo = packetEntry?.["extra.info"] || {};
        const traits = extraInfo["Traits"] || {};
        const characters = traits["Characters"] || {};
        const packetInfo = packetEntry?.["packet.info"] || {};
        const payloadLength = getPacketInfoPayloadLength(packetInfo);

        if (Number.isFinite(payloadLength) && payloadLength <= 0) {
            return false;
        }

        const charset = String(characters["Charset"] ?? "").trim().toLowerCase();
        if (charset && charset !== "unknown" && charset !== "n/a") {
            return true;
        }

        const mimeType = String(extraInfo["MIME Type"] ?? "")
            .trim()
            .toLowerCase();
        const usefulMimeHints = [
            "text/",
            "image/",
            "audio/",
            "video/",
            "application/json",
            "application/xml",
            "application/pdf",
            "application/zip",
            "application/gzip",
            "application/x-",
        ];
        if (usefulMimeHints.some((hint) => mimeType.startsWith(hint))) {
            return true;
        }

        const nonUsefulDataTypePatterns = [
            /^unknown\s*data\s*type$/i,
            /encrypted\s+stream/i,
            /protocol\s+data/i,
            /^unknown$/i,
            /^n\/a$/i,
        ];
        const hasUsefulDataType = dataItems.some((item) => {
            const normalized = String(item ?? "").trim();
            if (!normalized) return false;
            return !nonUsefulDataTypePatterns.some((pattern) => pattern.test(normalized));
        });

        return hasUsefulDataType;
    }

    function getDataTypesVisibilityState(packetEntry) {
        const dataItems = getPacketDataTypeItems(packetEntry);
        const hiddenProtocolToken = getMatchedHiddenDataTypeProtocol(packetEntry);
        const hiddenByProtocol = hiddenProtocolToken !== "";
        const likelyFileLikeData = hasLikelyFileLikeDataTypes(packetEntry, dataItems);
        const hiddenByHeuristic = !hiddenByProtocol && !likelyFileLikeData;
        const isOverridden =
            state.currentPacketKey != null
            && state.dataTypesOverridePacketKey === state.currentPacketKey;

        return {
            showPane: isOverridden || (!hiddenByProtocol && !hiddenByHeuristic ? true : false),
            reason: hiddenByProtocol
                ? `Hidden by default for ${hiddenProtocolToken} control / management traffic.Show it anyway to inspect encapsulated or tunneled payload guesses.`
                : hiddenByHeuristic
                    ? "Hidden by default because this packet has no strong file-like payload indicators. Show it anyway to inspect encapsulated or tunneled payload guesses."
                    : "",
        };
    }

    function applyDataTypesVisibility(visibilityState) {
        const dataTypesEl = document.getElementById("data-types");
        const dataTypesPaneEl = document.getElementById("dataTypesPane");
        const overrideWrapEl = document.getElementById("data-types-override-wrap");
        const overrideTextEl = document.getElementById("data-types-override-text");
        const overrideButtonEl = document.getElementById("data-types-override-btn");

        if (
            !dataTypesEl
            || !dataTypesPaneEl
            || !overrideWrapEl
            || !overrideTextEl
            || !overrideButtonEl
        ) {
            return;
        }

        dataTypesPaneEl.hidden = !visibilityState.showPane;
        overrideWrapEl.hidden = visibilityState.showPane;
        overrideButtonEl.hidden = visibilityState.showPane;
        overrideTextEl.textContent = visibilityState.reason;
        dataTypesEl.classList.toggle("data-types-collapsed", !visibilityState.showPane);
    }

    function populateDataTypes(packetList) {
        setPrevNextButtonVisibility(packetList, state.index);
        const typesListEl = document.getElementById("types-list");
        typesListEl.textContent = "";
        const mimeTypeEl = document.getElementById("mime-type");
        const encodingEl = document.getElementById("encoding");
        const languageEl = document.getElementById("language");
        encodingEl.textContent = "";
        languageEl.textContent = "";
        let encodingText = "";
        let languageText = "";
        const packetEntry = packetList?.[state.index] || {};
        const visibilityState = getDataTypesVisibilityState(packetEntry);
        applyDataTypesVisibility(visibilityState);
        const extraInfo = packetEntry["extra.info"] || {};
        const traits = extraInfo["Traits"] || {};
        const characters = traits["Characters"] || {};

        const encodingData = characters["Encoding"];
        if (encodingData === "Unavailable for high entropy data") {
            encodingText = "Unavailable for high entropy data";
        } else if (encodingData && typeof encodingData === "object") {
            encodingText = JSON.stringify(encodingData["encoding"] ?? "Unknown");
            languageText = JSON.stringify(encodingData["language"] ?? "Unknown");
        } else {
            encodingText = "Unknown";
            languageText = "Unknown";
        }

        const mimeTypeText = String(extraInfo["MIME Type"] ?? "Unknown");
        const dataItems = getPacketDataTypeItems(packetEntry);

        mimeTypeEl.textContent = "MIME type: " + mimeTypeText;
        encodingText = encodingText == "" ? "Unknown" : encodingText;
        if (encodingText !== undefined) {
            encodingEl.textContent =
                "Payload Encoding: " + encodingText.replace(/"/g, "");
        }
        if (languageText !== undefined) {
            languageEl.textContent =
                "Payload Language: " + languageText.replace(/"/g, "");
        }
        dataItems.forEach((item) => {
            const listItem = document.createElement("li");
            listItem.textContent = String(item ?? "Unknown");
            typesListEl.appendChild(listItem);
        });

        // Keep #active-recon bottom edge flush with #data-types,
        // and pin #data-types's top edge to the bottom of #protoInfo
        // so it grows/shrinks with the splitter just like the
        // right-hand panel does. Wrapped in try/catch because a
        // failure here would leave the loading screen stuck —
        // populateDataTypes is called on the hot packet-render path
        // and must never throw.
        try {
            const dataTypesEl = document.getElementById("data-types");
            const activeReconEl = document.getElementById("active-recon");
            const protoInfoEl = document.getElementById("protoInfo");
            const paneEl = document.getElementById("packetInfoPane");
            if (paneEl) {
                const paneRect = paneEl.getBoundingClientRect();
                if (dataTypesEl && activeReconEl) {
                    const dataTypesRect = dataTypesEl.getBoundingClientRect();
                    const bottomOffset = paneRect.bottom - dataTypesRect.bottom;
                    activeReconEl.style.bottom = Math.max(0, bottomOffset) + "px";
                }
                if (protoInfoEl) {
                    // The pane is the layout host (its CSS uses
                    // position: relative). The 10px gap below
                    // #protoInfo matches the data-types margin-top.
                    // We measure #protoInfo's bottom relative to
                    // the pane and add that gap so the two never
                    // overlap.
                    const protoRect = protoInfoEl.getBoundingClientRect();
                    const topOffset = protoRect.bottom - paneRect.top + 10;
                    paneEl.style.setProperty(
                        "--data-types-top",
                        Math.max(0, topOffset) + "px",
                    );
                }
            }
        } catch (syncError) {
            // Defensive: never let a layout sync error break the
            // packet-render path. The CSS fallback (top: 130px)
            // keeps the panel visible even if anchoring fails.
            if (typeof console !== "undefined" && console.warn) {
                console.warn("data-types sync failed:", syncError);
            }
        }
    }

    return {
        getPacketDataTypeItems,
        normalizeProtocolToken,
        collectPacketProtocolTokens,
        getMatchedHiddenDataTypeProtocol,
        hasLikelyFileLikeDataTypes,
        getDataTypesVisibilityState,
        applyDataTypesVisibility,
        populateDataTypes,
    };
}

module.exports = {
    createDataTypeHelpers,
};