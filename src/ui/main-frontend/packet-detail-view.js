// Packet detail rendering — small DOM helpers that back the hex/ASCII
// grid and the printable-character checks used by the "Data" workspace.
//
// This module was extracted from ``src/ui/main-frontend.js`` on the
// ``refactor/main-frontend-dead-code`` branch as the second slice of
// the renderer refactor. ``infoPanel`` itself is still in the
// orchestrator (it has dozens of cross-cutting dependencies on the
// session-level state and decoder tables); the helpers here are
// self-contained DOM utilities that the rest of the packet detail
// rendering pipeline can compose without closure access to the
// orchestrator.

function createPacketDetailViewHelpers() {
    // True when the given character code is printable ASCII (space
    // through ``~``). Used to decide whether a decoded byte is
    // safe to show in the ASCII column of the hex grid.
    function isPrintable(charCode) {
        return charCode >= 32 && charCode <= 126;
    }

    // Decodes a hex string to its ASCII representation. Non-printable
    // characters survive as control characters — the caller is
    // expected to gate on ``isPrintable`` when rendering.
    function hexToAscii(hex) {
        let decodedAscii = "";
        for (let i = 0; i < hex.length; i += 2) {
            decodedAscii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return decodedAscii;
    }

    // Returns ``str`` truncated to ``maxLength`` characters. Empty
    // inputs and inputs shorter than the cap pass through untouched.
    function truncate(str, maxLength) {
        if (str.length <= maxLength) return str;
        return str.slice(0, maxLength);
    }

    // Removes the "highlight" class from every ``.griditem`` element
    // in the hex grid. Called when the mouse leaves a cell so the
    // printable run stops being highlighted.
    function clearGridHighlights() {
        document
            .querySelectorAll(".griditem")
            .forEach((el) => el.classList.remove("highlight"));
    }

    // Populates the hex grid display (``#hexg``) and the ASCII
    // fade-in box (``#payloadascii``) for the given hex payload.
    // Each byte gets a ``.griditem`` div and a mouseenter handler
    // that shows the decoded ASCII run for that position.
    function popHexGrid(hex) {
        const safeHex = typeof hex === "string" ? hex : "";
        const payloadAsciiBox = document.getElementById("payloadascii");
        const hexGridContainer = document.getElementById("hexg");
        const hexOffsetDisplay = document.getElementById("asciiOffset");
        const asciiTextBox = document.getElementById("asciiText");
        if (payloadAsciiBox) {
            payloadAsciiBox.classList.remove("visible");
        }
        if (hexGridContainer) {
            hexGridContainer.textContent = "";
        }
        if (hexOffsetDisplay) {
            hexOffsetDisplay.textContent = "";
        }
        if (asciiTextBox) {
            asciiTextBox.textContent = "";
        }
        window.currentPrintableSequence = "";
        if (!safeHex) {
            return;
        }

        const decodedAscii = hexToAscii(safeHex);
        const hexPairs = safeHex.toUpperCase().match(/.{1,2}/g) || [];
        hexPairs.forEach((hexPair, byteIndex) => {
            const item = document.createElement("div");
            item.classList.add("griditem");
            item.textContent = hexPair;
            item.dataset.byteIndex = String(byteIndex);
            hexGridContainer.appendChild(item);
        });
        function getPrintableSequence(startIndex) {
            let result = "";
            for (let i = startIndex; i < decodedAscii.length; i++) {
                if (!isPrintable(decodedAscii.charCodeAt(i))) break;
                result += String.fromCharCode(decodedAscii.charCodeAt(i));
            }
            return result;
        }
        // Attach event listeners to each grid item
        document.querySelectorAll(".griditem").forEach((item, idx) => {
            item.addEventListener("mouseenter", (e) => {
                // box fade in
                payloadAsciiBox.style.top = e.clientY + 18 + "px";
                payloadAsciiBox.style.left = e.clientX + 18 + "px";
                payloadAsciiBox.classList.add("visible");
                asciiTextBox.innerHTML = "";
                const printable = getPrintableSequence(idx);
                window.currentPrintableSequence = printable;
                // adds only consecutive printable characters to the
                // decodedAscii box
                asciiTextBox.textContent += truncate(printable, 32);
                for (let i = 0; i < truncate(printable, 32).length; i++) {
                    const highlightedCell = document.querySelectorAll(".griditem")[idx + i];
                    highlightedCell.classList.add("highlight");
                }
                const hexLen = parseInt(truncate(printable, 32).length, 10)
                    .toString(16)
                    .padStart(2, "0")
                    .toUpperCase();
                const hexOffset = idx.toString(16).padStart(4, "0").toUpperCase();
                if (printable.length == 0) {
                    asciiTextBox.textContent = "0x" + item.textContent;
                }
                hexOffsetDisplay.textContent = "0x" + hexOffset + ":" + hexLen;
            });
        });
        // this fades the box back out and calls the grid clear func
        document.querySelectorAll(".griditem").forEach((item) => {
            item.addEventListener("mouseleave", () => {
                payloadAsciiBox.classList.remove("visible");
                clearGridHighlights();
            });
        });
    }

    return {
        isPrintable,
        hexToAscii,
        truncate,
        clearGridHighlights,
        popHexGrid,
    };
}

module.exports = {
    createPacketDetailViewHelpers,
};
