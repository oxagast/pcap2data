// YAML Conv decoder: minimal subset parser used to populate a data tree
// alongside the JSON/XML/HTML structured-tree render path.
//
// The decoder is intentionally strict for auto-detection: YAML's syntax is
// extremely permissive (almost any text with a colon looks like a key-value
// pair), so merely finding a `key:` line is not enough to distinguish real
// YAML from arbitrary text files, config files, or even prose with colons.
// To avoid false positives, we require:
//
//   1. A YAML document marker (`---` or `...`) AND at least one key-value
//      pair or list item, OR
//   2. At least **two** top-level key-value pairs (a single `key:` is
//      insufficient evidence), OR
//   3. A top-level key-value pair with a nested list (`- item`), OR
//   4. A top-level key-value pair whose value is a nested mapping (indented
//      child key).
//
// This makes the decoder suitable for auto-detection without a "force" flag:
// plain text, INI files, and prose will typically have at most one
// colon-terminated line and no YAML structural markers.

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

    // Count top-level (unindented) key-value pairs. These are the strongest
    // structural signal for a real YAML document.
    const topLevelKeys = [];
    lines.forEach((line) => {
        const match = line.match(/^([A-Za-z0-9_"'\-]+)\s*:/);
        if (match && !line.startsWith(" ")) {
            topLevelKeys.push(match[1].replace(/^['"]|['"]$/g, ""));
        }
    });

    // Check for indented child mappings (nested YAML structure), which is
    // a stronger signal than a single flat key.
    const hasNestedMapping = lines.some((line) =>
        /^\s{2,}[A-Za-z0-9_"'\-]+\s*:/.test(line),
    );
    // Check for top-level list items (unindented `- item`).
    const hasTopLevelList = lines.some((line) => /^-\s+.+/.test(line));

    // Confidence gate: require strong structural evidence.
    // A single `key: value` line is NOT enough — too many plain text files
    // and config files have a colon. We require either a document marker
    // with at least one structural element, or multiple top-level keys,
    // or a nested mapping, or a top-level list with multiple items.
    const hasMultipleTopLevelKeys = topLevelKeys.length >= 2;
    const hasListItems = lines.filter((line) => /^\s*-\s+/.test(line)).length >= 2;
    const hasStructuralEvidence =
        hasMultipleTopLevelKeys ||
        hasNestedMapping ||
        hasListItems ||
        (hasDocMarker && (hasKeyValue || hasList || hasTopLevelList));

    if (!hasStructuralEvidence) return null;

    // Require the YAML parser to produce a non-null, non-string result.
    // A plain string (e.g. "hello: world" parsed as a string) means the
    // input isn't really a YAML mapping.
    const treeData = parseSimpleYamlToObject(rawText);
    if (treeData === null || treeData === undefined) return null;
    // If the parser returned a plain string or number, it's not structured
    // YAML — it's just text that happened to have a colon.
    if (typeof treeData === "string" || typeof treeData === "number") return null;

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
