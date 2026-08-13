// File: scripts/scan-clusters.js
// Survey helper: groups consecutive top-level function declarations in
// src/ui/main-frontend.js by proximity, so we can spot next extraction
// targets. Skips the factory call sites (line < 3450).
const fs = require("fs");
const path = require("path");
const txt = fs.readFileSync(
    path.join(__dirname, "..", "src", "ui", "main-frontend.js"),
    "utf8",
);
const lines = txt.split("\n");
const decls = [];
for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(
        /^(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/,
    );
    if (m) decls.push({ name: m[1], line: i + 1 });
}
let lastLine = 0;
let groups = [];
let currentGroup = [];
for (const d of decls) {
    if (d.line < 3450) continue;
    if (d.line - lastLine < 5 && currentGroup.length > 0) {
        currentGroup.push(d);
    } else {
        if (currentGroup.length > 0) groups.push(currentGroup);
        currentGroup = [d];
    }
    lastLine = d.line + 1;
}
if (currentGroup.length > 0) groups.push(currentGroup);
const summary = groups
    .map((g) => ({
        names: g.map((x) => x.name).join(", "),
        first: g[0].line,
        last: g[g.length - 1].line,
        size: g[g.length - 1].line - g[0].line,
    }))
    .sort((a, b) => b.size - a.size)
    .slice(0, 12);
for (const s of summary) {
    console.log(`${s.first}-${s.last} (${s.size}): ${s.names}`);
}
