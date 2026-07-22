const fs = require("fs");
const path = require("path");
const vm = require("vm");

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }
    let depth = 0;
    let cursor = bodyStart;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let escaped = false;

    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        const next = sourceText[cursor + 1];

        if (inLineComment) {
            if (char === "\n") inLineComment = false;
            cursor += 1;
            continue;
        }
        if (inBlockComment) {
            if (char === "*" && next === "/") {
                inBlockComment = false;
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate || inRegex) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === "\\") {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === "`") inTemplate = false;
            else if (inRegex && char === "/") inRegex = false;
            cursor += 1;
            continue;
        }

        if (char === "/" && next === "/") {
            inLineComment = true;
            cursor += 2;
            continue;
        }
        if (char === "/" && next === "*") {
            inBlockComment = true;
            cursor += 2;
            continue;
        }
        if (char === "'") {
            inSingleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '"') {
            inDoubleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === "`") {
            inTemplate = true;
            cursor += 1;
            continue;
        }
        if (char === "/") {
            const prev = sourceText[cursor - 1];
            if (!prev || /[=(:,!&|?{};\s]/.test(prev)) {
                inRegex = true;
                cursor += 1;
                continue;
            }
        }

        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function extractConstantSource(sourceText, constantName) {
    const startToken = `const ${constantName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find constant ${constantName}`);
    }
    const bracketStart = sourceText.indexOf("[", startIndex);
    const braceStart = sourceText.indexOf("{", startIndex);
    let bodyStart = -1;
    let openChar = "";
    let closeChar = "";
    if (bracketStart !== -1 && braceStart !== -1) {
        if (bracketStart < braceStart) {
            bodyStart = bracketStart;
            openChar = "[";
            closeChar = "]";
        } else {
            bodyStart = braceStart;
            openChar = "{";
            closeChar = "}";
        }
    } else if (bracketStart !== -1) {
        bodyStart = bracketStart;
        openChar = "[";
        closeChar = "]";
    } else if (braceStart !== -1) {
        bodyStart = braceStart;
        openChar = "{";
        closeChar = "}";
    }
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${constantName}`);
    }
    let depth = 0;
    let cursor = bodyStart;
    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        if (char === openChar) depth += 1;
        if (char === closeChar) {
            depth -= 1;
            if (depth === 0) {
                let end = cursor + 1;
                while (sourceText[end] === ")") {
                    end += 1;
                }
                return sourceText.slice(startIndex, end);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse constant ${constantName}`);
}

function loadHintFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, "utf8");
    const functionNames = [
        "getPacketProtocolDecoderHint",
        "autoDetectProtoFromBytes",
    ];
    const extractedSource = [
        extractConstantSource(sourceText, "PROTOCOL_DECODER_HINTS"),
        extractConstantSource(sourceText, "PORT_DECODER_HINTS"),
        extractConstantSource(sourceText, "MIME_TO_PROTO"),
        ...functionNames.map((functionName) =>
            extractFunctionSource(sourceText, functionName),
        ),
    ].join("\n\n");

    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        normalizeSmbDecoderBytes: alwaysNull,
        decodeJsonFromBytes: alwaysNull,
        decodeXmlFromBytes: alwaysNull,
        decodeBsonFromBytes: alwaysNull,
        decodeMessagePackFromBytes: alwaysNull,
        decodeProtobufFromBytes: alwaysNull,
        decodeBerFromBytes: alwaysNull,
        decodeDerFromBytes: alwaysNull,
        decodeYamlFromBytes: alwaysNull,
        decodeLdapFromBytes: alwaysNull,
        decodeSmppFromBytes: alwaysNull,
        decodeSoulseekFromBytes: alwaysNull,
        decodeBittorrentFromBytes: alwaysNull,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        getPacketProtocolDecoderHint: context.getPacketProtocolDecoderHint,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

describe("Conv decoder packet metadata hints", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const decoderFiles = [
        path.join(projectRoot, "src/ui/panels/data-tools-panel.js"),
        path.join(projectRoot, "src/ui/main-frontend.js"),
    ];

    test.each(decoderFiles)(
        "extracts application protocol and port hints from a packet in %s",
        (filePath) => {
            const { getPacketProtocolDecoderHint } = loadHintFunctions(filePath);
            const packet = {
                "packet.info": {
                    "packet.proto": "TCP",
                    TCP: {
                        "tcp.dst.port": 5060,
                        "tcp.src.port": 12345,
                    },
                },
                "extra.info": {
                    "application.proto": "SIP",
                },
            };
            expect(getPacketProtocolDecoderHint(packet)).toEqual({
                protocolHint: "sip",
                portHint: "sip",
            });
        },
    );

    test.each(decoderFiles)(
        "falls back to port hint when application protocol is not matched in %s",
        (filePath) => {
            const { getPacketProtocolDecoderHint } = loadHintFunctions(filePath);
            const packet = {
                "packet.info": {
                    "packet.proto": "TCP",
                    TCP: {
                        "tcp.dst.port": 445,
                        "tcp.src.port": 54321,
                    },
                },
                "extra.info": {},
            };
            expect(getPacketProtocolDecoderHint(packet)).toEqual({
                protocolHint: null,
                portHint: "smb",
            });
        },
    );

    test.each(decoderFiles)(
        "autoDetectProtoFromBytes prefers protocolHint over portHint and heuristics in %s",
        (filePath) => {
            const { autoDetectProtoFromBytes } = loadHintFunctions(filePath);
            const bytes = new TextEncoder().encode("GET / HTTP/1.1\r\n");
            expect(
                autoDetectProtoFromBytes(bytes, { protocolHint: "smtp" }),
            ).toBe("smtp");
            expect(
                autoDetectProtoFromBytes(bytes, { portHint: "ftp" }),
            ).toBe("ftp");
            expect(autoDetectProtoFromBytes(bytes, {})).toBe("http");
        },
    );
});
