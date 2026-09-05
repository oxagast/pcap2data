const fs = require("fs");
const path = require("path");

const source = fs.readFileSync(
  path.join(__dirname, "..", "src", "ui", "panels", "list-panel.js"),
  "utf8",
);

function extractFunctionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`Missing ${name}`);
  let depth = 0;
  let opened = false;
  for (let index = source.indexOf("{", start); index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
      opened = true;
    } else if (source[index] === "}") {
      depth -= 1;
      if (opened && depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`Unclosed ${name}`);
}

describe("List timestamp sorting", () => {
  test("preserves fractional-second ordering", () => {
    const context = {};
    new Function("context", `${extractFunctionSource("parseListTimestampMs")}; context.parseListTimestampMs = parseListTimestampMs;`)(context);
    expect(context.parseListTimestampMs("2026-09-05 12:00:00.123456"))
      .toBeLessThan(context.parseListTimestampMs("2026-09-05 12:00:00.123999"));
  });
});