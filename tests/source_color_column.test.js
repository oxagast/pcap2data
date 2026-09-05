const fs = require("fs");
const path = require("path");

describe("List source color column", () => {
  test("uses a dedicated cell instead of coloring complete rows", () => {
    const listSource = fs.readFileSync(
      path.join(__dirname, "..", "src", "ui", "panels", "list-panel.js"),
      "utf8",
    );
    const cssSource = fs.readFileSync(
      path.join(__dirname, "..", "src", "assets", "css", "style.css"),
      "utf8",
    );
    expect(listSource).toContain('key: "sourceColor"');
    expect(listSource).toContain("packet-list-source-color-swatch");
    expect(listSource).toContain("packet-list-source-color-cell");
    expect(listSource).toContain('document.createElement("canvas")');
    expect(listSource).toContain("getSourceState");
    expect(listSource).not.toContain("packet-list-source-colored");
    expect(cssSource).toContain("packet-list-source-color-swatch");
  });
});