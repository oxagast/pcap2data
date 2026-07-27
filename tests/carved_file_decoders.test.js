// Tests for the new "Load carved file into Decoders" Stats context-menu
// entry, including the file-extension-to-decoder-hint helper and the menu
// markup that the renderer relies on.

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

describe("Conv decoders: file-extension hint helper", () => {
    let mimeModule;
    beforeAll(() => {
        mimeModule = require(
            path.join(
                PROJECT_ROOT,
                "src/ui/decoders/conv/mime-maps.js",
            ),
        );
    });

    test("maps common image extensions to the matching decoder key", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("photo.jpg")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("photo.jpeg")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("icon.png")).toBe("png");
        expect(mimeModule.getProtoDecoderHintForFileName("anim.gif")).toBe("gif");
        expect(mimeModule.getProtoDecoderHintForFileName("pic.webp")).toBe("webp");
    });

    test("maps markup and structured-data extensions to their decoders", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("page.html")).toBe("html");
        expect(mimeModule.getProtoDecoderHintForFileName("page.htm")).toBe("html");
        expect(mimeModule.getProtoDecoderHintForFileName("data.json")).toBe("json");
        expect(mimeModule.getProtoDecoderHintForFileName("data.xml")).toBe("xml");
        expect(mimeModule.getProtoDecoderHintForFileName("config.yaml")).toBe("yaml");
        expect(mimeModule.getProtoDecoderHintForFileName("config.yml")).toBe("yaml");
    });

    test("maps plain-text extensions to the plaintext decoder", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("notes.txt")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("trace.log")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("data.csv")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("app.env")).toBe("plaintext");
    });

    test("uppercase and mixed-case extensions are normalized", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("PIC.JPG")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("Pic.JpG")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("DATA.YAML")).toBe("yaml");
    });

    test("strips directory paths before extracting the extension", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("/tmp/uploads/photo.png")).toBe("png");
        expect(mimeModule.getProtoDecoderHintForFileName("C:\\share\\data.json")).toBe("json");
    });

    test("returns an empty string for unknown / missing extensions", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("payload")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("payload.bin")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("archive.exe")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName(null)).toBe("");
    });

    test("ignores dotfiles and trailing-dot files", () => {
        expect(mimeModule.getProtoDecoderHintForFileName(".bashrc")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("file.")).toBe("");
    });

    test("only returns proto keys supported by the decoder dropdown", () => {
        // Sanity check: every entry in the extension map must be in the
        // supported-protos set. This catches typos where someone adds an
        // extension that points at a decoder key the dropdown does not
        // expose.
        const supported = mimeModule.SUPPORTED_DECODER_PROTOS;
        for (const [ext, proto] of Object.entries(mimeModule.FILE_EXTENSION_TO_PROTO)) {
            expect(supported.has(proto)).toBe(true);
            expect(typeof ext).toBe("string");
        }
    });
});

describe("Conv decoders: barrel re-exports include the new helpers", () => {
    let barrel;
    beforeAll(() => {
        barrel = require(
            path.join(PROJECT_ROOT, "src/ui/decoders/conv/index.js"),
        );
    });

    test("exposes getProtoDecoderHintForFileName", () => {
        expect(typeof barrel.getProtoDecoderHintForFileName).toBe("function");
    });

    test("exposes FILE_EXTENSION_TO_PROTO and SUPPORTED_DECODER_PROTOS", () => {
        expect(barrel.FILE_EXTENSION_TO_PROTO).toBeDefined();
        expect(barrel.SUPPORTED_DECODER_PROTOS).toBeDefined();
    });

    test("exposes extractFileExtension", () => {
        expect(typeof barrel.extractFileExtension).toBe("function");
        expect(barrel.extractFileExtension("data.json")).toBe("json");
        expect(barrel.extractFileExtension("archive.bin")).toBe("bin");
        expect(barrel.extractFileExtension("noext")).toBe("");
    });
});

describe("Convert context menu markup", () => {
    let markup;
    beforeAll(() => {
        markup = fs.readFileSync(
            path.join(
                PROJECT_ROOT,
                "src/ui/fragments/convert-context-menu.js",
            ),
            "utf8",
        );
    });

    test("declares the new carved-file decoders button", () => {
        expect(markup).toContain('id="ctx-load-carvable-decoders"');
        expect(markup).toContain("Load carved file into Decoders");
    });

    test("keeps the existing carved-file Extraction and VirusTotal buttons", () => {
        expect(markup).toContain('id="ctx-load-carvable-extraction"');
        expect(markup).toContain('id="ctx-load-carvable-virustotal"');
    });

    test("places the new button between Extraction and VirusTotal", () => {
        const extractionIdx = markup.indexOf('id="ctx-load-carvable-extraction"');
        const decodersIdx = markup.indexOf('id="ctx-load-carvable-decoders"');
        const virusTotalIdx = markup.indexOf('id="ctx-load-carvable-virustotal"');
        expect(extractionIdx).toBeGreaterThan(-1);
        expect(decodersIdx).toBeGreaterThan(extractionIdx);
        expect(virusTotalIdx).toBeGreaterThan(decodersIdx);
    });
});

describe("main-frontend.js: carved-file decoders wiring", () => {
    let mainFrontendSource;
    beforeAll(() => {
        mainFrontendSource = fs.readFileSync(
            path.join(PROJECT_ROOT, "src/ui/main-frontend.js"),
            "utf8",
        );
    });

    test("caches the new button in convertContextButtons", () => {
        // The lookup is created via getCachedElement, mirroring the
        // pattern of the existing extraction/virustotal buttons.
        expect(mainFrontendSource).toMatch(
            /loadCarvableDecoders:\s*getCachedElement\("ctx-load-carvable-decoders"\)/,
        );
    });

    test("toggles the new button's visibility alongside the other carvable entries", () => {
        // We do not pin a specific code shape; we just require that
        // hasStatsCarvableAction drives all three carvable buttons.
        const loadCarvableDecodersVisibility = mainFrontendSource.match(
            /convertContextButtons\.loadCarvableDecoders\.style\.display\s*=\s*hasStatsCarvableAction\s*\?\s*"block"\s*:\s*"none"/,
        );
        expect(loadCarvableDecodersVisibility).not.toBeNull();
    });

    test("wires a click handler that uses the file-extension helper", () => {
        // Verify the handler exists and references the new helper plus
        // the decoders subtab constant.
        const handlerBlock = mainFrontendSource.match(
            /convertContextButtons\.loadCarvableDecoders\.addEventListener\([\s\S]*?\n\}\);/,
        );
        expect(handlerBlock).not.toBeNull();
        const source = handlerBlock[0];
        expect(source).toContain("getProtoDecoderHintForFileName");
        expect(source).toContain("CONV_DECODES_SUBTAB");
        expect(source).toContain("data-tools-proto-select");
    });

    test("imports the new mime-maps helper", () => {
        expect(mainFrontendSource).toMatch(
            /require\(['"]\.\/decoders\/conv\/mime-maps['"]\)/,
        );
        expect(mainFrontendSource).toContain("getProtoDecoderHintForFileName");
        expect(mainFrontendSource).toContain("SUPPORTED_DECODER_PROTOS");
    });
});

describe("Docs: 'Load carved file into Decoders' is documented", () => {
    test("context-menu.md mentions the new entry", () => {
        const doc = fs.readFileSync(
            path.join(PROJECT_ROOT, "docs/context-menu.md"),
            "utf8",
        );
        expect(doc).toContain("Load carved file into Decoders");
    });

    test("RELEASE_NOTES.md mentions the new entry", () => {
        const notes = fs.readFileSync(
            path.join(PROJECT_ROOT, "RELEASE_NOTES.md"),
            "utf8",
        );
        expect(notes).toContain("Load carved file into Decoders");
    });
});
