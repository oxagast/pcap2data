// XML Conv decoder: uses DOMParser in application/xml mode and rejects
// documents with a <parsererror>. Shares parseXmlElementToTreeObject with HTML.

const { parseXmlElementToTreeObject } = require("./xml-tree");

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

module.exports = { decodeXmlFromBytes };
