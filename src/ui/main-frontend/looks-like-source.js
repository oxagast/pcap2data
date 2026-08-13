// filepath: src/ui/main-frontend/looks-like-source.js
//
// Source-language detection helpers and the data-type guess machinery
// that consumes them. The `looksLike*Source` helpers are pure regex
// predicates; `addStructuredTextTypeGuesses` and `guessReadableTextLanguage`
// pipe a candidate text blob through them and the language stopword table
// to label likely programming languages and natural languages.
//
// Extracted from `src/ui/main-frontend.js` so the orchestrator can stay
// focused on wiring. No renderer state is touched — these helpers are
// pure functions of their inputs.
//
// External dependency: `isLikelyReadableText` (passed in by the caller
// because it lives in the orchestrator and is also used by `inferMimeType`).

// Constants used by `addStructuredTextTypeGuesses` for URL / URI / filename
// matching. Defined locally because they are only referenced here.
const DATA_TYPE_GUESS_URL_RE =
    /\b(?:(?:https?|ftp|file|ws|wss):\/\/|mailto:)[^\s<>"']+/i;
const DATA_TYPE_GUESS_URI_RE = /\b[a-z][a-z0-9+.-]{1,31}:[^\s<>"']+/i;
const DATA_TYPE_GUESS_FILENAME_EXTENSIONS = [
    "txt",
    "log",
    "cfg",
    "conf",
    "ini",
    "json",
    "xml",
    "htm",
    "html",
    "js",
    "jsx",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "css",
    "scss",
    "less",
    "py",
    "rb",
    "php",
    "pl",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "sql",
    "c",
    "cc",
    "cpp",
    "h",
    "hpp",
    "java",
    "go",
    "rs",
    "swift",
    "kt",
    "m",
    "mm",
    "cs",
    "yaml",
    "yml",
    "toml",
    "md",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "csv",
    "tsv",
    "zip",
    "tar",
    "gz",
    "bz2",
    "xz",
    "7z",
    "rar",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "pcap",
    "pcapng",
    "bin",
];
const DATA_TYPE_GUESS_FILENAME_EXTENSION_PATTERN =
    DATA_TYPE_GUESS_FILENAME_EXTENSIONS.map((extension) =>
        extension.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    ).join("|");
const DATA_TYPE_GUESS_FILENAME_RE = new RegExp(
    String.raw`(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\.{0,2}[\\/])?(?:[\w @()+,\-]+[\\/])*[\w @()+,\-]+\.(?:${DATA_TYPE_GUESS_FILENAME_EXTENSION_PATTERN})(?=$|[\s"')\]}:,;.!?])`,
    "i",
);
const DATA_TYPE_GUESS_CSS_BLOCK_MAX_CHARS = 600;

// Natural-language stopword tables used by `guessReadableTextLanguage`.
const DATA_TOOLS_LANGUAGE_MIN_LETTERS = 24;
const DATA_TOOLS_LANGUAGE_MIN_STOPWORD_MATCHES = 3;
const DATA_TOOLS_LANGUAGE_HIGH_CONFIDENCE_STOPWORD_MATCHES = 6;
const DATA_TOOLS_LANGUAGE_STOPWORDS = {
    English: ["the", "and", "with", "that", "this", "from", "have"],
    Spanish: ["que", "para", "una", "por", "como", "los", "las", "del", "con"],
    French: ["une", "pour", "avec", "dans", "des", "est", "pas", "sur", "les"],
    German: ["und", "der", "die", "das", "nicht", "mit", "ist", "ein", "den"],
    Portuguese: ["que", "para", "com", "uma", "não", "por", "dos", "das", "está"],
    Italian: ["che", "per", "con", "una", "non", "della", "sono", "degli"],
};

// Handles looks like html source.
function looksLikeHtmlSource(text) {
    return (
        /<!doctype\s+html/i.test(text) ||
        /<html\b/i.test(text) ||
        /<(?:head|body|title|script|style|div|span|p|a|form|table)\b/i.test(text)
    );
}

// Handles looks like xml source.
function looksLikeXmlSource(text) {
    return (
        /^<\?xml\b/i.test(text) ||
        (/^<[\w:-]+(?:\s+[^>]*)?>/.test(text) && /<\/[\w:-]+>\s*$/.test(text))
    );
}

// Handles looks like css source.
function looksLikeCssSource(text) {
    if (
        /@(?:media|import|supports|font-face)\b/i.test(text) ||
        /--[\w-]+\s*:/.test(text)
    ) {
        return true;
    }
    const blockStart = text.indexOf("{");
    const blockEnd = blockStart >= 0 ? text.indexOf("}", blockStart + 1) : -1;
    if (
        blockStart < 0 ||
        blockEnd < 0 ||
        blockEnd - blockStart > DATA_TYPE_GUESS_CSS_BLOCK_MAX_CHARS
    ) {
        return false;
    }
    const selector = text.slice(0, blockStart).trim();
    const blockBody = text.slice(blockStart + 1, blockEnd);
    return (
        /[#.]?[A-Za-z][\w-]*(?:\s*[>+~]\s*[#.]?[A-Za-z][\w-]*)*$/.test(selector) &&
        /(?:^|[;\s])[\w-]+\s*:\s*[^;{}]+;?/.test(blockBody)
    );
}

// Handles looks like java script source.
function looksLikeJavaScriptSource(text) {
    return (
        /\b(?:const|let|var|function|export|import|async|await|document|window|console)\b/.test(
            text,
        ) || /=>/.test(text)
    );
}

// Handles looks like python source.
function looksLikePythonSource(text) {
    return (
        /^\s*#!\/(?:usr\/bin\/env\s+)?python\d*\b/m.test(text) ||
        /\bdef\s+\w+\s*\(/.test(text) ||
        /\bclass\s+\w+\s*[:(]/.test(text) ||
        /\bimport\s+\w+/.test(text)
    );
}

// Handles looks like shell source.
function looksLikeShellSource(text) {
    return (
        /^\s*#!\/(?:usr\/bin\/env\s+)?(?:bash|sh|zsh|fish)\b/m.test(text) ||
        (/\b(?:echo|export|grep|awk|sed|fi|done|then)\b/.test(text) &&
            /\$\w+/.test(text))
    );
}

// Handles looks like power shell source.
function looksLikePowerShellSource(text) {
    return /\b(?:Get-|Set-|Write-Host|New-Object|Param\s*\(|\$env:)\b/i.test(
        text,
    );
}

// Handles looks like sql source.
function looksLikeSqlSource(text) {
    return /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b/i.test(
        text,
    );
}

// Handles looks like php source.
function looksLikePhpSource(text) {
    return /<\?php\b/i.test(text);
}

// Handles looks like go source.
function looksLikeGoSource(text) {
    return /\bpackage\s+\w+\b/.test(text) && /\bfunc\s+\w+\s*\(/.test(text);
}

// Handles looks like rust source.
function looksLikeRustSource(text) {
    return (
        /\bfn\s+\w+\s*\(/.test(text) && /\b(?:let\s+mut|impl|use\s+\w)/.test(text)
    );
}

// Handles looks like java or csharp source.
function looksLikeJavaOrCSharpSource(text) {
    return (
        /\b(?:public|private|protected)\s+(?:class|static|void)\b/.test(text) ||
        /\bSystem\.out\.println\b/.test(text) ||
        /\busing\s+System\b/.test(text)
    );
}

// Handles looks like yaml source.
function looksLikeYamlSource(text) {
    return (
        /^\s*[A-Za-z0-9_.-]+\s*:\s+\S+/m.test(text) &&
        !/[{};]/.test(text) &&
        !/<[A-Za-z]/.test(text)
    );
}

// Handles looks like any source code.
function looksLikeAnySourceCode(text) {
    return (
        looksLikeHtmlSource(text) ||
        looksLikeXmlSource(text) ||
        looksLikeCssSource(text) ||
        looksLikeJavaScriptSource(text) ||
        looksLikePythonSource(text) ||
        looksLikeShellSource(text) ||
        looksLikePowerShellSource(text) ||
        looksLikeSqlSource(text) ||
        looksLikePhpSource(text) ||
        looksLikeGoSource(text) ||
        looksLikeRustSource(text) ||
        looksLikeJavaOrCSharpSource(text) ||
        looksLikeYamlSource(text)
    );
}

// Handles add data type guess candidate.
function addDataTypeGuessCandidate(candidateScores, label, score) {
    const currentScore = candidateScores.get(label) || 0;
    if (score > currentScore) {
        candidateScores.set(label, score);
    }
}

// Handles add structured text type guesses.
function addStructuredTextTypeGuesses(inputText, candidateScores) {
    const text = String(inputText || "");
    const trimmed = text.trim();
    if (!trimmed) return;

    if (DATA_TYPE_GUESS_URL_RE.test(text) || DATA_TYPE_GUESS_URI_RE.test(text)) {
        addDataTypeGuessCandidate(candidateScores, "URL / Link", 92);
    }
    if (DATA_TYPE_GUESS_FILENAME_RE.test(text)) {
        addDataTypeGuessCandidate(candidateScores, "Filename / File Path", 88);
    }
    if (looksLikeHtmlSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "HTML Source Code", 94);
    }
    if (looksLikeCssSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "CSS Stylesheet", 91);
    }
    if (looksLikeJavaScriptSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "JavaScript Source Code", 90);
    }
    if (looksLikeXmlSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "XML / Markup Source Code", 86);
    }
    if (looksLikePythonSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "Python Source Code", 88);
    }
    if (looksLikeShellSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "Shell Script", 85);
    }
    if (looksLikePowerShellSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "PowerShell Script", 86);
    }
    if (looksLikeSqlSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "SQL Source Code", 87);
    }
    if (looksLikePhpSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "PHP Source Code", 86);
    }
    if (looksLikeGoSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "Go Source Code", 86);
    }
    if (looksLikeRustSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "Rust Source Code", 84);
    }
    if (looksLikeJavaOrCSharpSource(trimmed)) {
        addDataTypeGuessCandidate(candidateScores, "Java / C# Source Code", 82);
    }
    if (
        !looksLikeAnySourceCode(trimmed) &&
        /[{}();<>]/.test(trimmed) &&
        /\b(?:if|for|while|return|class|function|const|let|var|def|fn|SELECT|echo)\b/.test(
            trimmed,
        )
    ) {
        addDataTypeGuessCandidate(candidateScores, "Programming Source Code", 72);
    }
}

// Handles guess readable text language. The external readability check
// is injected so the orchestrator's `isLikelyReadableText` (also used by
// `inferMimeType`) can be reused here without crossing module boundaries.
function guessReadableTextLanguage(text, bytes, readableChecker) {
    const normalized = String(text || "").trim();
    if (!readableChecker(normalized, bytes)) return null;
    if (looksLikeAnySourceCode(normalized)) {
        return null;
    }

    if (/[\u3040-\u30ff]/.test(normalized)) {
        return { label: "Japanese", confidence: "High" };
    }
    if (/[\uac00-\ud7af]/.test(normalized)) {
        return { label: "Korean", confidence: "High" };
    }
    if (/[\u0600-\u06ff]/.test(normalized)) {
        return { label: "Arabic", confidence: "High" };
    }
    if (/[\u0590-\u05ff]/.test(normalized)) {
        return { label: "Hebrew", confidence: "High" };
    }
    if (/[\u0370-\u03ff]/.test(normalized)) {
        return { label: "Greek", confidence: "High" };
    }
    if (/[\u4e00-\u9fff]/.test(normalized)) {
        const hasJapaneseKana = /[\u3040-\u30ff]/.test(normalized);
        return { label: "Chinese", confidence: hasJapaneseKana ? "Low" : "Medium" };
    }

    const letterTokens = normalized.toLowerCase().match(/\p{L}+/gu) || [];
    const joinedLetters = letterTokens.join("");
    if (joinedLetters.length < DATA_TOOLS_LANGUAGE_MIN_LETTERS) return null;

    const cyrillicCount = (joinedLetters.match(/[\u0400-\u04ff]/g) || []).length;
    if (cyrillicCount / joinedLetters.length >= 0.4) {
        return {
            label: "Russian",
            confidence:
                cyrillicCount / joinedLetters.length >= 0.8 ? "High" : "Medium",
        };
    }

    let bestLabel = "";
    let bestScore = 0;
    Object.entries(DATA_TOOLS_LANGUAGE_STOPWORDS).forEach(
        ([label, stopwords]) => {
            const stopwordSet = new Set(stopwords);
            const score = letterTokens.reduce(
                (total, token) => total + (stopwordSet.has(token) ? 1 : 0),
                0,
            );
            if (score > bestScore) {
                bestLabel = label;
                bestScore = score;
            }
        },
    );

    if (bestScore >= DATA_TOOLS_LANGUAGE_MIN_STOPWORD_MATCHES) {
        return {
            label: bestLabel,
            confidence:
                bestScore >= DATA_TOOLS_LANGUAGE_HIGH_CONFIDENCE_STOPWORD_MATCHES
                    ? "High"
                    : "Medium",
        };
    }

    return null;
}

function createLooksLikeSourceHelpers({ isLikelyReadableText }) {
    return {
        looksLikeHtmlSource,
        looksLikeXmlSource,
        looksLikeCssSource,
        looksLikeJavaScriptSource,
        looksLikePythonSource,
        looksLikeShellSource,
        looksLikePowerShellSource,
        looksLikeSqlSource,
        looksLikePhpSource,
        looksLikeGoSource,
        looksLikeRustSource,
        looksLikeJavaOrCSharpSource,
        looksLikeYamlSource,
        looksLikeAnySourceCode,
        addDataTypeGuessCandidate,
        addStructuredTextTypeGuesses,
        guessReadableTextLanguage: function (text, bytes) {
            return guessReadableTextLanguage(text, bytes, isLikelyReadableText);
        },
    };
}

module.exports = {
    createLooksLikeSourceHelpers,
};
