// HTML Conv decoder: parses text/html, requires at least one common HTML marker
// (DOCTYPE, <html>, <head>, <body>, <title>, <meta>, etc.) to avoid false
// positives on XML/SVG/MathML, then emits a structured tree.

const { parseXmlElementToTreeObject } = require("./xml-tree");

function decodeHtmlFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
    if (!rawText) return null;
    if (!rawText.startsWith("<")) return null;

    try {
        const parser = new DOMParser();
        const htmlDoc = parser.parseFromString(rawText, "text/html");
        const documentChildren = Array.from(htmlDoc.documentElement?.children || []);
        // Require at least one of the common HTML markers so we don't false-positive
        // on arbitrary XML / SVG / mathML that happen to start with '<'.
        const loweredHead = rawText.slice(0, 4096).toLowerCase();
        const looksLikeHtml =
            loweredHead.includes("<!doctype html") ||
            loweredHead.includes("<html") ||
            documentChildren.some((el) => String(el?.tagName || "").toLowerCase() === "head") ||
            documentChildren.some((el) => String(el?.tagName || "").toLowerCase() === "body") ||
            loweredHead.includes("<head") ||
            loweredHead.includes("<body") ||
            loweredHead.includes("<title") ||
            loweredHead.includes("<meta ") ||
            loweredHead.includes("<link ") ||
            loweredHead.includes("<script") ||
            loweredHead.includes("<style") ||
            loweredHead.includes("<div") ||
            loweredHead.includes("<p ") ||
            loweredHead.includes("<p>") ||
            loweredHead.includes("<span") ||
            loweredHead.includes("<a ");
        if (!looksLikeHtml) return null;

        const rootTag = htmlDoc.documentElement?.tagName || "(none)";
        const childCount = htmlDoc.documentElement?.childElementCount || 0;
        const attrs = Array.from(htmlDoc.documentElement?.attributes || []).map(
            (attr) => `${attr.name}=${JSON.stringify(attr.value)}`,
        );

        const titleElement = htmlDoc.querySelector("title");
        const titleText = titleElement ? titleElement.textContent.trim() : "";

        const headElement = htmlDoc.querySelector("head");
        const metaTags = headElement
            ? Array.from(headElement.querySelectorAll("meta"))
                .slice(0, 25)
                .map((meta) => {
                    const name = meta.getAttribute("name") || meta.getAttribute("http-equiv") || meta.getAttribute("property");
                    const content = meta.getAttribute("content");
                    if (name && content !== null) return `${name}=${JSON.stringify(content)}`;
                    if (content !== null) return JSON.stringify(content);
                    return null;
                })
                .filter(Boolean)
            : [];

        const treeData = {
            [rootTag]: parseXmlElementToTreeObject(htmlDoc.documentElement, 0),
        };

        const fields = [
            { name: "Document Type", value: `<!DOCTYPE ${htmlDoc.doctype?.name || "html"}>` },
            { name: "Root Element", value: rootTag },
            { name: "Child Elements", value: String(childCount) },
            { name: "Root Attributes", value: attrs.length ? attrs.join(", ") : "(none)" },
        ];
        if (titleText) fields.push({ name: "Title", value: titleText });
        if (metaTags.length) fields.push({ name: "Meta Tags", value: metaTags.join(", ") });
        fields.push({
            name: "Preview",
            value: rawText.length > 2000 ? `${rawText.slice(0, 2000)}…` : rawText,
        });
        return { protocol: "HTML", fields, treeData };
    } catch {
        return null;
    }
}

module.exports = { decodeHtmlFromBytes };
