const { normalizeSettings, DEFAULT_SETTINGS } = require("../src/settings");
const fs = require("fs");
const path = require("path");

describe("Merge source color settings", () => {
  test("provides six pastel colors and an enable toggle", () => {
    const settings = normalizeSettings({});
    expect(settings.merge.sourceColorCodingEnabled).toBe(true);
    expect(settings.merge.sourceColors).toHaveLength(6);
    expect(settings.merge.sourceColors.every((color) => /^#[0-9a-f]{6}$/i.test(color))).toBe(true);
    expect(DEFAULT_SETTINGS.merge.sourceColors).toHaveLength(6);
  });

  test("wires the Merge settings tab and randomized assignment path", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "..", "src", "ui", "main-frontend.js"),
      "utf8",
    );
    expect(source).toContain("SETTINGS_SUBTAB_MERGE");
    expect(source).toContain("assignNewSessionSourceColors");
    expect(source).toContain("sourceColorCodingEnabled");
    expect(source).toContain("remapSourceColorsForPaletteChange");
    expect(source).toContain("Source ${String.fromCharCode(65 + index)}");
  });
});