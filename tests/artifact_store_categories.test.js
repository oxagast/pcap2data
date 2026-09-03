// Tests for the Artifact Store category taxonomy and filtering logic.
// These tests extract the pure functions/constants from keystore-panel.js
// via source-scanning (same pattern as smb_keystore_helpers.test.js) so
// they can run in Jest without a DOM, Electron, or import.meta support.

const fs = require("fs");
const path = require("path");

const panelSource = fs.readFileSync(
    path.join(__dirname, "..", "src", "ui", "panels", "keystore-panel.js"),
    "utf8",
);

function extractConstValue(constName) {
    const startToken = `const ${constName} = `;
    const startIndex = panelSource.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find const ${constName}`);
    }
    const valueStart = startIndex + startToken.length;
    // Read until the next semicolon at depth 0 (handle strings/brackets).
    let depth = 0;
    let inString = false;
    let stringChar = "";
    for (let cursor = valueStart; cursor < panelSource.length; cursor += 1) {
        const char = panelSource[cursor];
        if (inString) {
            if (char === stringChar && panelSource[cursor - 1] !== "\\") inString = false;
            continue;
        }
        if (char === '"' || char === "'" || char === "`") {
            inString = true;
            stringChar = char;
            continue;
        }
        if (char === "{" || char === "[" || char === "(") depth += 1;
        if (char === "}" || char === "]" || char === ")") depth -= 1;
        if (char === ";" && depth === 0) {
            const valueText = panelSource.slice(valueStart, cursor).trim();
            return eval(valueText);
        }
    }
    throw new Error(`Could not parse const ${constName}`);
}

const ARTIFACT_CATEGORY_ALL = extractConstValue("ARTIFACT_CATEGORY_ALL");
const ARTIFACT_CATEGORY_SECRETS = extractConstValue("ARTIFACT_CATEGORY_SECRETS");
const ARTIFACT_CATEGORY_ITEMS = extractConstValue("ARTIFACT_CATEGORY_ITEMS");
const ARTIFACT_CATEGORY_FILES = extractConstValue("ARTIFACT_CATEGORY_FILES");
const ARTIFACT_CATEGORY_MISC = extractConstValue("ARTIFACT_CATEGORY_MISC");

function extractConstArrayRaw(constName) {
    const startToken = `const ${constName} = [`;
    const startIndex = panelSource.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find const ${constName}`);
    }
    const bracketStart = panelSource.indexOf("[", startIndex);
    let depth = 0;
    for (let cursor = bracketStart; cursor < panelSource.length; cursor += 1) {
        const char = panelSource[cursor];
        if (char === "[") depth += 1;
        if (char === "]") {
            depth -= 1;
            if (depth === 0) {
                return panelSource.slice(bracketStart, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse const ${constName}`);
}

function extractConstObjectRaw(constName) {
    const startToken = `const ${constName} = {`;
    const startIndex = panelSource.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find const ${constName}`);
    }
    const braceStart = panelSource.indexOf("{", startIndex);
    let depth = 0;
    for (let cursor = braceStart; cursor < panelSource.length; cursor += 1) {
        const char = panelSource[cursor];
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return panelSource.slice(braceStart, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse const ${constName}`);
}

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    let depth = 0;
    for (let cursor = bodyStart; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

const ARTIFACT_CATEGORIES = eval(
    `(function(ARTIFACT_CATEGORY_ALL, ARTIFACT_CATEGORY_SECRETS, ARTIFACT_CATEGORY_ITEMS, ARTIFACT_CATEGORY_FILES, ARTIFACT_CATEGORY_MISC) {
    return ${extractConstArrayRaw("ARTIFACT_CATEGORIES")};
  })(${JSON.stringify(ARTIFACT_CATEGORY_ALL)}, ${JSON.stringify(ARTIFACT_CATEGORY_SECRETS)}, ${JSON.stringify(ARTIFACT_CATEGORY_ITEMS)}, ${JSON.stringify(ARTIFACT_CATEGORY_FILES)}, ${JSON.stringify(ARTIFACT_CATEGORY_MISC)})`,
);
const ARTIFACT_TYPE_TO_CATEGORY = eval(
    `(function(ARTIFACT_CATEGORY_ALL, ARTIFACT_CATEGORY_SECRETS, ARTIFACT_CATEGORY_ITEMS, ARTIFACT_CATEGORY_FILES, ARTIFACT_CATEGORY_MISC) {
    return ${extractConstObjectRaw("ARTIFACT_TYPE_TO_CATEGORY")};
  })(${JSON.stringify(ARTIFACT_CATEGORY_ALL)}, ${JSON.stringify(ARTIFACT_CATEGORY_SECRETS)}, ${JSON.stringify(ARTIFACT_CATEGORY_ITEMS)}, ${JSON.stringify(ARTIFACT_CATEGORY_FILES)}, ${JSON.stringify(ARTIFACT_CATEGORY_MISC)})`,
);

// Build categoryForType from the extracted function source + the extracted map.
const categoryForTypeFn = new Function(
    "ARTIFACT_TYPE_TO_CATEGORY",
    "ARTIFACT_CATEGORY_MISC",
    `${extractFunctionSource(panelSource, "categoryForType")} return categoryForType;`,
);
const categoryForType = categoryForTypeFn(
    ARTIFACT_TYPE_TO_CATEGORY,
    ARTIFACT_CATEGORY_MISC,
);

describe("Artifact Store category taxonomy", () => {
    test("ARTIFACT_CATEGORIES includes all expected categories", () => {
        expect(ARTIFACT_CATEGORIES).toEqual([
            "all",
            "secrets",
            "items",
            "files",
            "misc",
        ]);
    });

    test("categoryForType maps secrets correctly", () => {
        const secretTypes = [
            "secret",
            "password",
            "private-key",
            "cookie",
            "aws-access-key",
            "aws-secret-key",
            "github-token",
            "discord-token",
            "jwt-token",
            "oauth-token",
            "api-token",
            "azure-key",
            "gcp-key",
            "gcp-service-account-key",
            "gcp-oauth-token",
        ];
        secretTypes.forEach((type) => {
            expect(categoryForType(type)).toBe("secrets");
        });
    });

    test("categoryForType maps items correctly", () => {
        const itemTypes = ["certificate", "email", "url", "uri"];
        itemTypes.forEach((type) => {
            expect(categoryForType(type)).toBe("items");
        });
    });

    test("categoryForType maps file to files", () => {
        expect(categoryForType("file")).toBe("files");
    });

    test("categoryForType maps goodie to misc", () => {
        expect(categoryForType("goodie")).toBe("misc");
    });

    test("categoryForType falls back to misc for unknown types", () => {
        expect(categoryForType("unknown-type")).toBe("misc");
        expect(categoryForType("")).toBe("misc");
        expect(categoryForType(null)).toBe("misc");
        expect(categoryForType(undefined)).toBe("misc");
    });

    test("categoryForType is case-insensitive", () => {
        expect(categoryForType("SECRET")).toBe("secrets");
        expect(categoryForType("Certificate")).toBe("items");
        expect(categoryForType("FILE")).toBe("files");
    });
});

describe("Artifact Store module exports", () => {
    test("module exports category constants and categoryForType (source-level)", () => {
        // We can't require() the panel module directly because it uses
        // import.meta.url in a Worker constructor. Instead, verify the
        // module.exports block contains the expected symbols.
        const exportsStart = panelSource.indexOf("module.exports = {");
        const exportsEnd = panelSource.indexOf("};", exportsStart);
        const exportsBlock = panelSource.slice(exportsStart, exportsEnd);
        expect(exportsBlock).toContain("ARTIFACT_CATEGORIES");
        expect(exportsBlock).toContain("ARTIFACT_CATEGORY_ALL");
        expect(exportsBlock).toContain("ARTIFACT_CATEGORY_SECRETS");
        expect(exportsBlock).toContain("ARTIFACT_CATEGORY_ITEMS");
        expect(exportsBlock).toContain("ARTIFACT_CATEGORY_FILES");
        expect(exportsBlock).toContain("ARTIFACT_CATEGORY_MISC");
        expect(exportsBlock).toContain("categoryForType");
    });

    test("module still exports keystore constants (internal naming preserved)", () => {
        const exportsStart = panelSource.indexOf("module.exports = {");
        const exportsEnd = panelSource.indexOf("};", exportsStart);
        const exportsBlock = panelSource.slice(exportsStart, exportsEnd);
        expect(exportsBlock).toContain("id: \"keystore\"");
        expect(exportsBlock).toContain("CRYPT_KEYSTORE_MODE_SESSION");
        expect(exportsBlock).toContain("CRYPT_KEYSTORE_MODE_PERSISTENT");
        expect(exportsBlock).toContain("SESSION_KEYCHAIN_LABEL");
        expect(exportsBlock).toContain("createKeystorePanel");
    });
});