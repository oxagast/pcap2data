const fs = require("fs");
const path = require("path");

describe("VirusTotal Threat Intel presentation", () => {
    const projectRoot = path.join(__dirname, "..");
    const html = fs.readFileSync(path.join(projectRoot, "src/index.html"), "utf8");
    const frontend = fs.readFileSync(path.join(projectRoot, "src/ui/main-frontend.js"), "utf8");
    const panel = fs.readFileSync(path.join(projectRoot, "src/ui/panels/subnet-calculator-panel.js"), "utf8");
    const css = fs.readFileSync(path.join(projectRoot, "src/assets/css/style.css"), "utf8");

    test("hides IPSum and Tor cards and expands VirusTotal", () => {
        expect(html).toMatch(/id="subnet-ti-ipsum-card"[^>]*hidden/);
        expect(html).toMatch(/id="subnet-ti-tor-card"[^>]*hidden/);
        expect(html).toMatch(/class="[^"]*subnet-calc-card-wide[^"]*"[^>]*id="subnet-ti-ipsum-card"/);
        expect(html).toMatch(/class="[^"]*subnet-calc-card-wide[^"]*"[^>]*id="subnet-ti-tor-card"/);
        expect(html).toMatch(/class="[^"]*subnet-calc-card-wide[^"]*subnet-ti-virustotal-card/);
        expect(css).toContain("#conv-threat-intel-panel .subnet-ti-virustotal-card");
        expect(css).toContain("#conv-threat-intel-panel #subnet-ti-ipsum-card");
    });

    test("routes carved-file results through the Threat Intel renderer", () => {
        expect(frontend).toContain("function showVirusTotalResultInThreatIntel");
        expect(frontend).toContain("subnetCalculatorPanel.showVirusTotalResult(response, fileNameHint)");
        expect(panel).toContain("function showVirusTotalResult(virustotalResult, fileName = \"\")");
        expect(panel).toContain("showVirusTotalResult,");
    });

    test("persists separate file records and refreshes analysis IDs", () => {
        expect(panel).toContain("virustotalResults");
        expect(panel).toContain("VIRUS_TOTAL_POLL_INTERVAL_MS = 3 * 60 * 1000");
        expect(panel).toContain('lookupType = result.analysisId && !result.lookupValue ? "analysis" : "hash"');
        expect(panel).toContain("virustotalResults.push");
        expect(panel).toContain("virustotalResults: clonePlainData(virustotalResults, [])");
    });

    test("renders detailed file metadata, Sigma findings, and engine results", () => {
        expect(panel).toContain("VirusTotal File Metadata");
        expect(panel).toContain("Dataset Name ${index + 1}");
        expect(panel).toContain('"Technical File Details"');
        expect(panel).toContain('"Sigma Detections"');
        expect(panel).toContain('"Antivirus Engine Results"');
        expect(panel).toContain("sigma_analysis_results");
        expect(panel).toContain("last_analysis_results");
        expect(panel).not.toContain('vtAttributes.names.join(", ")');
        expect(panel).toContain("rawVtAttributes");
        expect(panel).toContain("result.raw?.data");
        expect(panel).toContain('"VirusTotal Overview"');
        expect(panel).toContain("...rawVtAttributes");
        expect(panel).not.toContain('name: "Community Votes"');
        expect(panel).toContain("value.slice(0, maxItems)");
    });

    test("limits normalized VirusTotal aliases at the backend boundary", () => {
        const backend = fs.readFileSync(path.join(projectRoot, "src/backend/snitch.py"), "utf8");
        expect(backend).toContain('attributes.get("names")[:3]');
    });
});
