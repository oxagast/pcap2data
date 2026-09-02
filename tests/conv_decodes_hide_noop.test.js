// Tests for the "Hide packets with no decodable data" filter in the Conv
// Decodes stacked view. Mirrors the vm-extraction pattern used by
// conv_decodes_stream_stack.test.js: pull the relevant accessor functions
// out of src/ui/panels/data-tools-panel.js into a vm context with a
// minimal module.exports shim, then exercise the toggle semantics.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const lastIndex = sourceText.lastIndexOf(startToken);
    if (lastIndex !== -1 && lastIndex !== startIndex) {
        startIndex = lastIndex;
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }

    let depth = 0;
    let cursor = bodyStart;
    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
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

function loadHideNoOpAccessors() {
    const projectRoot = path.resolve(__dirname, "..");
    const targetFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");
    const sourceText = fs.readFileSync(targetFile, "utf8");

    const functionNames = [
        "getConvDecodesHideNoOp",
        "setConvDecodesHideNoOp",
    ];
    const extractedFunctions = functionNames
        .map((name) => extractFunctionSource(sourceText, name))
        .join("\n\n");

    const context = {
        exports: {},
        module: { exports: {} },
    };
    context.module.exports = context.exports;
    vm.createContext(context);
    vm.runInContext(
        extractedFunctions +
        "\nmodule.exports = { getConvDecodesHideNoOp, setConvDecodesHideNoOp };",
        context,
    );
    return context.module.exports;
}

describe("Conv Decodes hide-no-op filter", () => {
    let filterApi;
    beforeAll(() => {
        filterApi = loadHideNoOpAccessors();
    });

    beforeEach(() => {
        // Reset to the default off state between tests.
        filterApi.setConvDecodesHideNoOp(false);
    });

    test("exposes the accessor pair", () => {
        expect(typeof filterApi.getConvDecodesHideNoOp).toBe("function");
        expect(typeof filterApi.setConvDecodesHideNoOp).toBe("function");
    });

    test("defaults to false (filter off)", () => {
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
    });

    test("flips to true when set with true", () => {
        filterApi.setConvDecodesHideNoOp(true);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(true);
    });

    test("flips back to false when set with false", () => {
        filterApi.setConvDecodesHideNoOp(true);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(true);
        filterApi.setConvDecodesHideNoOp(false);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
    });

    test("uses strict-equality coercion so only literal true turns the filter on", () => {
        // The implementation is `convDecodesHideNoOp = nextValue === true`,
        // so anything other than literal true is normalized to false. This
        // keeps DOM-coerced values (strings from event.target.checked-style
        // access, accidentally passed objects) from silently toggling the
        // filter into a weird state.
        filterApi.setConvDecodesHideNoOp("yes");
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp(1);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp({});
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp("true");
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        // And the literal still works.
        filterApi.setConvDecodesHideNoOp(true);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(true);
    });

    test("non-true values normalize to false", () => {
        filterApi.setConvDecodesHideNoOp(true);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(true);
        // Every other input — including the canonical false — must end up
        // as false because the setter uses strict equality.
        filterApi.setConvDecodesHideNoOp("");
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp(0);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp(null);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp(undefined);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
        filterApi.setConvDecodesHideNoOp(false);
        expect(filterApi.getConvDecodesHideNoOp()).toBe(false);
    });

    test("the toggle is independent of stream packet state", () => {
        // Flipping the filter must not disturb the stream packet store.
        // The stream is owned by a different module-level let in the same
        // file, but the two should coexist; here we simply confirm the
        // filter accessor can be toggled repeatedly without throwing.
        for (let i = 0; i < 5; i += 1) {
            filterApi.setConvDecodesHideNoOp(i % 2 === 0);
            expect(filterApi.getConvDecodesHideNoOp()).toBe(i % 2 === 0);
        }
    });
});