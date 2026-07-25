// JSON Conv decoder: parses {…} or […] payloads and returns a tree-friendly
// representation for the structured-tree renderer.

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

module.exports = { decodeJsonFromBytes };
