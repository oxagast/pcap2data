const fs = require("fs");
const path = require("path");

describe("source-qualified Target dropdown queries", () => {
  test("uses source and original host independently", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "..", "src", "ui", "main-frontend.js"),
      "utf8",
    );
    expect(source).toContain("return `source: ${sourceFilter} && (ip.src.addr: ${hostFilter} || ip.dst.addr: ${hostFilter})`");
    expect(source).toContain('const sourceHost = packetInfo["capture.sourceHost"] || host;');
    expect(source).toContain("const hostFilter = sanitizeFilterTerm(hostOption.sourceHost || \"\");");
  });
});