// YAML Conv decoder: minimal subset parser used to populate a data tree
// alongside the JSON/XML/HTML structured-tree render path.

const { parseSimpleYamlToObject } = require("./yaml-parser");

function decodeYamlFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const trimmed = rawText.trim();
    if (!trimmed) return null;

    const lines = rawText
        .split(/\r?\n/)
        .map((line) => line.replace(/\t/g, "  "))
        .filter((line) => line.trim() && !line.trimStart().startsWith("#"));
    if (!lines.length) return null;

    const hasDocMarker = /^---|^\.\.\./m.test(trimmed);
    const hasKeyValue = lines.some((line) => /^\s*[A-Za-z0-9_"'\-]+\s*:\s*.*$/.test(line));
    const hasList = lines.some((line) => /^\s*-\s+.+$/.test(line));
    if (!hasDocMarker && !hasKeyValue && !hasList) return null;

    const topLevelKeys = [];
    lines.forEach((line) => {
        const match = line.match(/^([A-Za-z0-9_"'\-]+)\s*:/);
        if (match && !line.startsWith(" ")) {
            topLevelKeys.push(match[1].replace(/^['"]|['"]$/g, ""));
        }
    });

    const treeData = parseSimpleYamlToObject(rawText);
    return {
        protocol: "YAML",
        fields: [
            { name: "Top-level keys", value: topLevelKeys.length ? topLevelKeys.join(", ") : "(none detected)" },
            { name: "Contains lists", value: hasList ? "Yes" : "No" },
            {
                name: "Preview",
                value: trimmed.length > 2000 ? `${trimmed.slice(0, 2000)}…` : trimmed,
            },
        ],
        treeData,
    };
}

module.exports = { decodeYamlFromBytes };
