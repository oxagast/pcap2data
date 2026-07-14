function parseDataToolsInputWorker(format, rawInput) {
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
        for (let index = 0; index < normalized.length; index += 2) {
            bytes[index / 2] = parseInt(normalized.slice(index, index + 2), 16);
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
        for (let index = 0; index < normalized.length; index += 8) {
            bytes[index / 8] = parseInt(normalized.slice(index, index + 8), 2);
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
        for (let index = 0; index < decoded.length; index += 1) {
            bytes[index] = decoded.charCodeAt(index);
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

    return new TextEncoder().encode(rawInput);
}

self.onmessage = (event) => {
    const payload = event?.data || {};
    const id = Number(payload.id);
    const format = String(payload.format || "");
    const rawInput = String(payload.rawInput || "");

    try {
        const bytes = parseDataToolsInputWorker(format, rawInput);
        self.postMessage({ id, ok: true, bytes }, [bytes.buffer]);
    } catch (error) {
        self.postMessage({
            id,
            ok: false,
            error:
                error && typeof error === "object" && "message" in error
                    ? String(error.message || "data-tools-parse-worker-error")
                    : "data-tools-parse-worker-error",
        });
    }
};
