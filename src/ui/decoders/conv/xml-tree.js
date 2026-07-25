// Shared helpers for the XML/HTML/JSON/YAML structured tree renderer.
// Used by data-tools-panel.js, protocol-decoding.js, and the main frontend.

function parseXmlElementToTreeObject(element, depth = 0) {
    if (!(element instanceof Element)) return null;
    if (depth > 40) return "[max-depth]";

    const nodeObject = {};
    const attributes = Array.from(element.attributes || []);
    if (attributes.length) {
        nodeObject["@attributes"] = {};
        attributes.forEach((attr) => {
            nodeObject["@attributes"][attr.name] = attr.value;
        });
    }

    const textNodes = Array.from(element.childNodes || [])
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => (node.textContent || "").trim())
        .filter(Boolean);
    if (textNodes.length) {
        nodeObject["#text"] = textNodes.join(" ");
    }

    const childElements = Array.from(element.children || []);
    childElements.forEach((child) => {
        const childValue = parseXmlElementToTreeObject(child, depth + 1);
        if (nodeObject[child.tagName] === undefined) {
            nodeObject[child.tagName] = childValue;
            return;
        }
        if (!Array.isArray(nodeObject[child.tagName])) {
            nodeObject[child.tagName] = [nodeObject[child.tagName]];
        }
        nodeObject[child.tagName].push(childValue);
    });

    if (!Object.keys(nodeObject).length) return "";
    return nodeObject;
}

function formatDataTreeLeafValue(value) {
    if (value === null) return "null";
    if (value === undefined) return "undefined";
    if (typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return JSON.stringify(value);
}

function getDataTreeBranchSummary(value) {
    if (Array.isArray(value)) return `[${value.length}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).length}}`;
    return "";
}

function createDataTreeNode(label, value, depth = 0) {
    const isBranch =
        Array.isArray(value) || (value !== null && typeof value === "object");

    if (!isBranch) {
        const leaf = document.createElement("div");
        leaf.className = "data-tools-tree-leaf";

        const keySpan = document.createElement("span");
        keySpan.className = "data-tools-tree-key";
        keySpan.textContent = `${label}: `;

        const valueSpan = document.createElement("span");
        valueSpan.className = "data-tools-tree-value";
        valueSpan.textContent = formatDataTreeLeafValue(value);

        leaf.appendChild(keySpan);
        leaf.appendChild(valueSpan);
        return leaf;
    }

    const details = document.createElement("details");
    details.className = "data-tools-tree-branch";
    details.open = depth < 2;

    const summary = document.createElement("summary");
    summary.className = "data-tools-tree-summary";

    const keySpan = document.createElement("span");
    keySpan.className = "data-tools-tree-key";
    keySpan.textContent = label;

    const metaSpan = document.createElement("span");
    metaSpan.className = "data-tools-tree-meta";
    metaSpan.textContent = ` ${getDataTreeBranchSummary(value)}`;

    summary.appendChild(keySpan);
    summary.appendChild(metaSpan);
    details.appendChild(summary);

    const children = document.createElement("div");
    children.className = "data-tools-tree-children";
    if (Array.isArray(value)) {
        value.forEach((item, index) => {
            children.appendChild(createDataTreeNode(`[${index}]`, item, depth + 1));
        });
        if (!value.length) {
            children.appendChild(createDataTreeNode("(empty)", "", depth + 1));
        }
    } else {
        const keys = Object.keys(value);
        keys.forEach((key) => {
            children.appendChild(createDataTreeNode(key, value[key], depth + 1));
        });
        if (!keys.length) {
            children.appendChild(createDataTreeNode("(empty)", "", depth + 1));
        }
    }
    details.appendChild(children);
    return details;
}

function renderStructuredDecoderTree(protoOutput, result) {
    if (!protoOutput || !result || !result.treeData) return false;
    const treeFormats = new Set(["JSON", "XML", "HTML", "YAML"]);
    if (!treeFormats.has(result.protocol)) return false;

    const wrapper = document.createElement("div");
    wrapper.className = "data-tools-structured-tree";

    const title = document.createElement("div");
    title.className = "data-tools-tree-title";
    title.textContent = `${result.protocol} Data Tree`;
    wrapper.appendChild(title);

    const treeRoot = createDataTreeNode("root", result.treeData, 0);
    wrapper.appendChild(treeRoot);
    protoOutput.appendChild(wrapper);
    return true;
}

module.exports = {
    parseXmlElementToTreeObject,
    formatDataTreeLeafValue,
    getDataTreeBranchSummary,
    createDataTreeNode,
    renderStructuredDecoderTree,
};
