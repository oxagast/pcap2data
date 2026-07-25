// Shared YAML scalar / key-value / object parser used by the YAML Conv decoder.

function parseSimpleYamlScalar(valueText) {
    const text = String(valueText || "").trim();
    if (text === "") return "";
    if (/^(true|false)$/i.test(text)) return /^true$/i.test(text);
    if (/^(null|~)$/i.test(text)) return null;
    if (/^[+-]?\d+$/.test(text)) {
        const parsedInt = Number.parseInt(text, 10);
        if (Number.isFinite(parsedInt)) return parsedInt;
    }
    if (/^[+-]?(?:\d+\.\d+|\d+\.\d*|\.\d+)$/.test(text)) {
        const parsedFloat = Number.parseFloat(text);
        if (Number.isFinite(parsedFloat)) return parsedFloat;
    }
    if (
        (text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))
    ) {
        return text.slice(1, -1);
    }
    return text;
}

function parseSimpleYamlKeyValue(content) {
    const separatorIndex = content.indexOf(":");
    if (separatorIndex <= 0) return null;
    const key = content.slice(0, separatorIndex).trim().replace(/^['"]|['"]$/g, "");
    if (!key) return null;
    const rawValue = content.slice(separatorIndex + 1);
    const hasInlineValue = rawValue.trim().length > 0;
    return {
        key,
        hasInlineValue,
        value: hasInlineValue ? parseSimpleYamlScalar(rawValue) : null,
    };
}

function parseSimpleYamlToObject(rawText) {
    if (typeof rawText !== "string") return null;
    const sourceLines = rawText.split(/\r?\n/);
    const lines = sourceLines
        .map((line) => line.replace(/\t/g, "  "))
        .filter((line) => {
            const trimmed = line.trim();
            return (
                trimmed &&
                !trimmed.startsWith("#") &&
                trimmed !== "---" &&
                trimmed !== "..."
            );
        })
        .map((line) => ({
            indent: (line.match(/^\s*/) || [""])[0].length,
            content: line.trim(),
        }));
    if (!lines.length) return null;

    function parseBlock(startIndex, expectedIndent) {
        if (startIndex >= lines.length) return { value: null, nextIndex: startIndex };

        const startsWithList = lines[startIndex].content.startsWith("-");
        if (startsWithList) {
            const resultList = [];
            let index = startIndex;
            while (index < lines.length) {
                const line = lines[index];
                if (line.indent < expectedIndent || !line.content.startsWith("-")) break;
                if (line.indent > expectedIndent) {
                    index += 1;
                    continue;
                }

                const itemText = line.content.replace(/^-\s?/, "").trim();
                if (!itemText) {
                    const nextLine = lines[index + 1];
                    if (nextLine && nextLine.indent > line.indent) {
                        const nested = parseBlock(index + 1, nextLine.indent);
                        resultList.push(nested.value);
                        index = nested.nextIndex;
                        continue;
                    }
                    resultList.push(null);
                    index += 1;
                    continue;
                }

                const maybeKv = parseSimpleYamlKeyValue(itemText);
                if (maybeKv) {
                    const itemObject = { [maybeKv.key]: maybeKv.value };
                    if (!maybeKv.hasInlineValue) {
                        const nextLine = lines[index + 1];
                        if (nextLine && nextLine.indent > line.indent) {
                            const nested = parseBlock(index + 1, nextLine.indent);
                            itemObject[maybeKv.key] = nested.value;
                            index = nested.nextIndex;
                        } else {
                            index += 1;
                        }
                    } else {
                        index += 1;
                    }

                    while (index < lines.length && lines[index].indent > line.indent) {
                        const siblingLine = lines[index];
                        if (siblingLine.content.startsWith("-")) break;
                        const siblingKv = parseSimpleYamlKeyValue(siblingLine.content);
                        if (!siblingKv) break;
                        if (!siblingKv.hasInlineValue) {
                            const nestedLine = lines[index + 1];
                            if (nestedLine && nestedLine.indent > siblingLine.indent) {
                                const nested = parseBlock(index + 1, nestedLine.indent);
                                itemObject[siblingKv.key] = nested.value;
                                index = nested.nextIndex;
                            } else {
                                itemObject[siblingKv.key] = null;
                                index += 1;
                            }
                        } else {
                            itemObject[siblingKv.key] = siblingKv.value;
                            index += 1;
                        }
                    }

                    resultList.push(itemObject);
                    continue;
                }

                resultList.push(parseSimpleYamlScalar(itemText));
                index += 1;
            }

            return {
                value: resultList,
                nextIndex: index,
            };
        }

        const resultObject = {};
        let index = startIndex;
        while (index < lines.length) {
            const line = lines[index];
            if (line.indent < expectedIndent) break;
            if (line.indent > expectedIndent) {
                index += 1;
                continue;
            }
            if (line.content.startsWith("-")) break;

            const maybeKv = parseSimpleYamlKeyValue(line.content);
            if (!maybeKv) {
                index += 1;
                continue;
            }

            if (maybeKv.hasInlineValue) {
                resultObject[maybeKv.key] = maybeKv.value;
                index += 1;
                continue;
            }

            const nextLine = lines[index + 1];
            if (nextLine && nextLine.indent > line.indent) {
                const nested = parseBlock(index + 1, nextLine.indent);
                resultObject[maybeKv.key] = nested.value;
                index = nested.nextIndex;
            } else {
                resultObject[maybeKv.key] = null;
                index += 1;
            }
        }

        return {
            value: resultObject,
            nextIndex: index,
        };
    }

    const parsed = parseBlock(0, lines[0].indent).value;
    return parsed;
}

module.exports = {
    parseSimpleYamlScalar,
    parseSimpleYamlKeyValue,
    parseSimpleYamlToObject,
};
