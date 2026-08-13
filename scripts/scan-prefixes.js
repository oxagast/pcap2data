// File: scripts/scan-prefixes.js
// Survey helper: groups top-level function declarations in
// src/ui/main-frontend.js by their camelCase prefix, so we can spot
// next extraction targets.
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
console.log("Total top-level function decls:", decls.length);
console.log("");
const buckets = {};
for (const d of decls) {
    const m = d.name.match(/^([a-z]+)/);
    if (!m) continue;
    const prefix = m[1];
    if (!buckets[prefix]) buckets[prefix] = [];
    buckets[prefix].push(d);
}
const counts = Object.entries(buckets)
    .map(([p, fns]) => ({
        prefix: p,
        count: fns.length,
        first: fns[0].line,
        last: fns[fns.length - 1].line,
        span: fns[fns.length - 1].line - fns[0].line,
    }))
    .sort((a, b) => b.count - a.count);
console.log("Top 25 prefixes:");
for (const c of counts.slice(0, 25)) {
    console.log(
        `  ${c.prefix}: ${c.count} functions, lines ${c.first}-${c.last} (${c.span}-line span)`,
    );
}