// Formats large Conv output views off the main thread for renderer responsiveness.

self.onmessage = (event) => {
    const payload = event?.data || {};
    const id = Number(payload.id);
    const kind = String(payload.kind || "");
    const rawBytes = payload.bytes;

    try {
        const bytes = rawBytes instanceof Uint8Array
            ? rawBytes
            : new Uint8Array(rawBytes || []);

        let value = "";
        switch (kind) {
            case "hex":
                value = Array.from(bytes, (byte) =>
                    byte.toString(16).padStart(2, "0").toUpperCase(),
                ).join(" ");
                break;
            case "binary":
                value = Array.from(bytes, (byte) =>
                    byte.toString(2).padStart(8, "0"),
                ).join(" ");
                break;
            case "decimal":
                value = Array.from(bytes, (byte) => String(byte)).join(" ");
                break;
            case "ascii":
                value = Array.from(bytes, (byte) =>
                    byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".",
                ).join("");
                break;
            case "base64": {
                let binary = "";
                const chunkSize = 0x8000;
                for (let index = 0; index < bytes.length; index += chunkSize) {
                    const chunk = bytes.subarray(index, index + chunkSize);
                    binary += String.fromCharCode(...chunk);
                }
                value = btoa(binary);
                break;
            }
            default:
                value = "";
                break;
        }

        self.postMessage({ id, ok: true, value });
    } catch (error) {
        self.postMessage({
            id,
            ok: false,
            error:
                error && typeof error === "object" && "message" in error
                    ? String(error.message || "data-tools-output-worker-error")
                    : "data-tools-output-worker-error",
        });
    }
};
