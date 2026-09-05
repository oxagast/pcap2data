const fs = require("fs");
const path = require("path");

describe("source filtering and bookmark identity", () => {
  test("frontend uses durable packet keys for current packets and source filters", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "..", "src", "ui", "main-frontend.js"),
      "utf8",
    );
    expect(source).toContain("currentPacketKey = getPacketKey(");
    expect(source).toContain("function isSourceFilterExpression");
    expect(source).toContain("capture.sourceSession");
  });

  test("filter backend recognizes source metadata aliases", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "..", "src", "filter.js"),
      "utf8",
    );
    expect(source).toContain("case 'capture-source-id':");
    expect(source).toContain("capture.sourceId");
  });
});