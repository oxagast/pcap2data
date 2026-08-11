// Settings → Themes subtab helpers (theme loading, application, preview,
// online catalog, and Paddle-backed checkout flow).
//
// This module was extracted from src/ui/main-frontend.js (see the
// `refactor/main-frontend-dead-code` branch's commits for the diff).
// It is wired up by the renderer orchestrator with ``createThemesCatalogHelpers``
// which returns the public helpers and accepts a small ``state`` object
// containing the four outside-owned arrays/sets whose identities must be
// preserved across re-renders (the settings form reads them directly).

function createThemesCatalogHelpers({
    state,
    getCurrentSettings,
    DEFAULT_SETTINGS,
}) {
    const FALLBACK_THEME_ID = "snitchbitch";

    // Inside-block state owned by the factory. These are encapsulated here
    // because they're only read/written by theme helpers.
    let themesCatalogEntries = [];
    let themesCatalogIsSandbox = false;
    let themesCatalogPaddleEnv = null;
    let themesCatalogLoading = false;
    let themesPreviewObjectUrl = null;
    let themesPreviewInFlight = 0;
    const themesEmbeddedPreviewCache = new Map();

    // Handles sanitize theme id.
    function sanitizeThemeId(value, fallback = FALLBACK_THEME_ID) {
        if (typeof value !== "string") return fallback;
        const normalized = value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
        return normalized || fallback;
    }

    // Returns theme select element.
    function getThemeSelectElement() {
        return document.getElementById("settings-themes-select");
    }

    // Returns llm model select element.
    function getLlmModelSelectElement() {
        return document.getElementById("settings-llm-model");
    }

    // Returns configured ollama models.
    function getConfiguredOllamaModels() {
        if (Array.isArray(state.availableOllamaModels) && state.availableOllamaModels.length > 0) {
            return state.availableOllamaModels.map((entry) => ({ ...entry }));
        }
        return [{
            value: DEFAULT_SETTINGS.llm.ollamaModel,
            label: DEFAULT_SETTINGS.llm.ollamaModel,
        }];
    }

    // Normalizes ollama model entry.
    function normalizeOllamaModelEntry(rawValue) {
        if (typeof rawValue === "string") {
            const normalized = rawValue.trim();
            if (!normalized || normalized.startsWith("#")) return null;
            return {
                value: normalized,
                label: normalized,
            };
        }

        if (!rawValue || typeof rawValue !== "object") return null;

        const value =
            typeof rawValue.value === "string" && rawValue.value.trim()
                ? rawValue.value.trim()
                : typeof rawValue.name === "string" && rawValue.name.trim()
                    ? rawValue.name.trim()
                    : typeof rawValue.model === "string" && rawValue.model.trim()
                        ? rawValue.model.trim()
                        : "";
        if (!value || value.startsWith("#")) return null;

        const label =
            typeof rawValue.label === "string" && rawValue.label.trim()
                ? rawValue.label.trim()
                : value;

        return { value, label };
    }

    async function loadAvailableOllamaModels() {
        if (!window.modelsapi || typeof window.modelsapi.getOllamaModels !== "function") {
            state.availableOllamaModels = [{
                value: DEFAULT_SETTINGS.llm.ollamaModel,
                label: DEFAULT_SETTINGS.llm.ollamaModel,
            }];
            renderLlmModelOptions(getCurrentSettings()?.llm?.ollamaModel || DEFAULT_SETTINGS.llm.ollamaModel);
            return state.availableOllamaModels;
        }

        try {
            const models = await window.modelsapi.getOllamaModels();
            state.availableOllamaModels = Array.isArray(models)
                ? models
                    .map((entry) => normalizeOllamaModelEntry(entry))
                    .filter(Boolean)
                : [];
        } catch (error) {
            console.warn("Unable to load available Ollama models:", error);
            state.availableOllamaModels = [];
        }

        if (state.availableOllamaModels.length === 0) {
            state.availableOllamaModels = [{
                value: DEFAULT_SETTINGS.llm.ollamaModel,
                label: DEFAULT_SETTINGS.llm.ollamaModel,
            }];
        }

        renderLlmModelOptions(getCurrentSettings()?.llm?.ollamaModel || DEFAULT_SETTINGS.llm.ollamaModel);
        return [...state.availableOllamaModels];
    }

    // Returns ollama model dropdown options.
    function getOllamaModelDropdownOptions() {
        return getConfiguredOllamaModels().map((modelEntry) => ({
            value: modelEntry.value,
            label: modelEntry.label,
        }));
    }

    // Renders llm model options.
    function renderLlmModelOptions(selectedModelValue = "") {
        const modelSelectEl = getLlmModelSelectElement();
        if (!modelSelectEl) return;

        const normalizedSelectedValue =
            typeof selectedModelValue === "string" && selectedModelValue.trim()
                ? selectedModelValue.trim()
                : DEFAULT_SETTINGS.llm.ollamaModel;
        const optionDefinitions = getOllamaModelDropdownOptions();
        const hasSelectedValue = optionDefinitions.some(
            (option) => option.value === normalizedSelectedValue,
        );

        if (!hasSelectedValue) {
            optionDefinitions.unshift({
                value: normalizedSelectedValue,
                label: `${normalizedSelectedValue} (Custom)`,
            });
        }

        modelSelectEl.innerHTML = "";
        optionDefinitions.forEach((optionDefinition) => {
            const optionEl = document.createElement("option");
            optionEl.value = optionDefinition.value;
            optionEl.textContent = optionDefinition.label;
            modelSelectEl.appendChild(optionEl);
        });

        modelSelectEl.value = normalizedSelectedValue;
    }

    // Returns theme by id from list.
    function getThemeByIdFromList(themeId) {
        const normalizedId = sanitizeThemeId(themeId, FALLBACK_THEME_ID);
        return state.availableThemes.find((theme) => sanitizeThemeId(theme.id, "") === normalizedId) || null;
    }

    // Returns theme source suffix.
    function getThemeSourceSuffix(theme) {
        if (!theme || !theme.hasUserBundledDiff) return "";
        return theme.sourceKind === "user" ? " [User Modified]" : " [Bundled]";
    }

    // Handles update selected theme source note.
    function updateSelectedThemeSourceNote(themeId) {
        const noteEl = document.getElementById("settings-themes-source-note");
        if (!noteEl) return;
        const theme = getThemeByIdFromList(themeId);
        if (!theme || !theme.hasUserBundledDiff) {
            noteEl.textContent = "";
            noteEl.hidden = true;
            return;
        }

        const sourceLabel = theme.sourceKind === "user" ? "User Modified" : "Bundled";
        noteEl.textContent = `Selected source for this theme ID: ${sourceLabel}.`;
        noteEl.hidden = false;
    }

    // Renders theme options.
    function renderThemeOptions() {
        const themeSelectEl = getThemeSelectElement();
        if (!themeSelectEl) return;
        const currentValue = sanitizeThemeId(themeSelectEl.value, FALLBACK_THEME_ID);
        const settingsThemeId = sanitizeThemeId(
            getCurrentSettings()?.general?.themeId,
            FALLBACK_THEME_ID,
        );
        const selectedThemeId = state.availableThemes.some((theme) => theme.id === settingsThemeId)
            ? settingsThemeId
            : currentValue;

        themeSelectEl.innerHTML = "";
        state.availableThemes.forEach((theme) => {
            const option = document.createElement("option");
            option.value = theme.id;
            option.textContent = `${theme.name}${getThemeSourceSuffix(theme)}`;
            themeSelectEl.appendChild(option);
        });

        if (themeSelectEl.options.length > 0) {
            themeSelectEl.value = selectedThemeId || FALLBACK_THEME_ID;
        }
        updateSelectedThemeSourceNote(themeSelectEl.value);
    }

    function parseHexColorToRgb(colorValue) {
        if (typeof colorValue !== "string") return null;
        const normalized = colorValue.trim().toLowerCase();
        const hexMatch = normalized.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
        if (!hexMatch) return null;
        const hexBody = hexMatch[1];
        const expanded = hexBody.length === 3
            ? hexBody.split("").map((part) => `${part}${part}`).join("")
            : hexBody;
        const red = parseInt(expanded.slice(0, 2), 16);
        const green = parseInt(expanded.slice(2, 4), 16);
        const blue = parseInt(expanded.slice(4, 6), 16);
        if ([red, green, blue].some((value) => Number.isNaN(value))) return null;
        return { red, green, blue };
    }

    function toLinearSrgb(value) {
        const normalized = value / 255;
        if (normalized <= 0.04045) {
            return normalized / 12.92;
        }
        return ((normalized + 0.055) / 1.055) ** 2.4;
    }

    function getRelativeLuminanceFromRgb({ red, green, blue }) {
        const linearRed = toLinearSrgb(red);
        const linearGreen = toLinearSrgb(green);
        const linearBlue = toLinearSrgb(blue);
        return (0.2126 * linearRed) + (0.7152 * linearGreen) + (0.0722 * linearBlue);
    }

    function resolveSettingsAboutTerminalColorToken(themeVariables, tokenName, fallbackValue = "") {
        if (!themeVariables || typeof themeVariables !== "object") return fallbackValue;
        const raw = themeVariables[tokenName];
        if (typeof raw !== "string" || !raw.trim()) return fallbackValue;
        return raw.trim();
    }

    function resolveThemeBgColorToken(themeVariables) {
        if (!themeVariables || typeof themeVariables !== "object") return "";
        const candidateTokens = ["--app-bg", "--surface-0", "--surface-1", "--input-bg-color"];
        for (const tokenName of candidateTokens) {
            const tokenValue = resolveSettingsAboutTerminalColorToken(themeVariables, tokenName, "");
            if (tokenValue) return tokenValue;
        }
        return "";
    }

    function isThemeLight(themeVariables) {
        const backgroundToken = resolveThemeBgColorToken(themeVariables);
        const parsedBackground = parseHexColorToRgb(backgroundToken);
        if (!parsedBackground) return false;
        return getRelativeLuminanceFromRgb(parsedBackground) >= 0.5;
    }

    function applyThemeDropdownColors(theme) {
        const rootStyle = document.documentElement.style;
        const themeVariables = theme && typeof theme === "object" ? theme.variables : null;
        const lightTheme = isThemeLight(themeVariables);
        const dropdownBackgroundColor = lightTheme ? "#ffffff" : "#000000";
        const dropdownTextColor = lightTheme ? "#000000" : "#ffffff";

        rootStyle.setProperty("--dropdown-bg-color", dropdownBackgroundColor);
        rootStyle.setProperty("--dropdown-text-color", dropdownTextColor);
    }

    function applySettingsAboutTerminalTheme(theme) {
        const rootStyle = document.documentElement.style;
        const themeVariables = theme && typeof theme === "object" ? theme.variables : null;
        const fallbackTextColor = "#e6e6e6";

        const borderAndTextColor =
            resolveSettingsAboutTerminalColorToken(themeVariables, "--color-5", "")
            || resolveSettingsAboutTerminalColorToken(themeVariables, "--header-text-color", "")
            || fallbackTextColor;

        const parsedTextColor = parseHexColorToRgb(borderAndTextColor);
        const textLuminance = parsedTextColor
            ? getRelativeLuminanceFromRgb(parsedTextColor)
            : 0.8;

        // Keep terminal background strictly black/white while maximizing contrast.
        const terminalBackgroundColor = textLuminance >= 0.5 ? "#000000" : "#ffffff";

        rootStyle.setProperty("--settings-about-terminal-bg", terminalBackgroundColor);
        rootStyle.setProperty("--settings-about-terminal-fg", borderAndTextColor);
        rootStyle.setProperty("--settings-about-terminal-border", borderAndTextColor);
    }

    // Applies theme variables.
    function applyThemeVariables(theme) {
        const rootStyle = document.documentElement.style;
        if (state.appliedThemeVariableNames.size > 0) {
            state.appliedThemeVariableNames.forEach((variableName) => {
                rootStyle.removeProperty(variableName);
            });
            state.appliedThemeVariableNames = new Set();
        }
        if (!theme || !theme.variables || typeof theme.variables !== "object") return;

        Object.entries(theme.variables).forEach(([variableName, variableValue]) => {
            if (!String(variableName).startsWith("--")) return;
            if (typeof variableValue !== "string" || !variableValue.trim()) return;
            rootStyle.setProperty(variableName, String(variableValue));
            state.appliedThemeVariableNames.add(String(variableName));
        });

        applyThemeDropdownColors(theme);
        applySettingsAboutTerminalTheme(theme);
    }

    // Applies theme quit button character.
    function applyThemeQuitButtonCharacter(theme) {
        const closeBtn = document.getElementById("close-btn");
        if (!closeBtn) return;
        const configuredCharacter =
            theme && typeof theme.quitButtonCharacter === "string"
                ? theme.quitButtonCharacter.trim()
                : "";
        closeBtn.textContent = configuredCharacter || "\u00D7";
    }

    // Returns app logo element.
    function getAppLogoElement() {
        return document.getElementById("app-logo") || document.querySelector(".logo-cont img");
    }

    // Returns theme backdrop element.
    function getThemeBackdropElement() {
        return document.getElementById("theme-backdrop");
    }

    // Builds theme embedded image data uri.
    function buildThemeEmbeddedImageDataUri(imageConfig) {
        if (!imageConfig || typeof imageConfig !== "object") return null;
        const formatRaw = typeof imageConfig.format === "string"
            ? imageConfig.format.trim().toLowerCase()
            : "";
        const format = formatRaw === "jpeg" ? "jpg" : formatRaw;
        const normalizedBase64 = typeof imageConfig.base64 === "string"
            ? imageConfig.base64.replace(/^data:image\/(png|jpeg|jpg);base64,/i, "").replace(/\s+/g, "")
            : "";
        if ((format !== "png" && format !== "jpg") || !normalizedBase64) {
            return null;
        }

        const mime = format === "png" ? "image/png" : "image/jpeg";
        return `data:${mime};base64,${normalizedBase64}`;
    }

    // Applies theme logo.
    function applyThemeLogo(theme) {
        const logoEl = getAppLogoElement();
        if (!logoEl) return;

        if (!state.defaultThemeLogoSrc) {
            state.defaultThemeLogoSrc = logoEl.getAttribute("src") || "../assets/images/logo.webp";
        }

        const logoImage = theme && typeof theme === "object" ? theme.logoImage : null;
        const logoDataUri = buildThemeEmbeddedImageDataUri(logoImage);
        if (!logoDataUri) {
            logoEl.src = state.defaultThemeLogoSrc;
            return;
        }

        logoEl.src = logoDataUri;
    }

    // Applies theme backdrop image.
    function applyThemeBackdropImage(theme) {
        const backdropEl = getThemeBackdropElement();
        if (!backdropEl) return;

        const backdropImage = theme && typeof theme === "object" ? theme.backdropImage : null;
        const backdropDataUri = buildThemeEmbeddedImageDataUri(backdropImage);
        if (!backdropDataUri) {
            backdropEl.style.removeProperty("background-image");
            backdropEl.classList.remove("has-image");
            return;
        }

        backdropEl.style.setProperty("background-image", `url(${backdropDataUri})`);
        backdropEl.classList.add("has-image");
    }

    async function applyThemeById(themeId) {
        const normalizedThemeId = sanitizeThemeId(themeId, FALLBACK_THEME_ID);
        if (!window.themeapi || typeof window.themeapi.get !== "function") {
            applyThemeVariables(null);
            applyThemeLogo(null);
            applyThemeBackdropImage(null);
            applyThemeQuitButtonCharacter(null);
            document.documentElement.dataset.themeId = normalizedThemeId;
            return normalizedThemeId;
        }
        try {
            const theme = await window.themeapi.get(normalizedThemeId);
            if (!theme) return normalizedThemeId;
            applyThemeVariables(theme);
            applyThemeLogo(theme);
            applyThemeBackdropImage(theme);
            applyThemeQuitButtonCharacter(theme);
            document.documentElement.dataset.themeId = theme.id;
            return theme.id;
        } catch (error) {
            console.warn("Unable to apply selected theme:", error);
            return normalizedThemeId;
        }
    }

    async function loadAvailableThemes() {
        if (!window.themeapi || typeof window.themeapi.list !== "function") {
            state.availableThemes = [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
            renderThemeOptions();
            return state.availableThemes;
        }

        try {
            const themeList = await window.themeapi.list();
            state.availableThemes = Array.isArray(themeList) && themeList.length > 0
                ? themeList
                : [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
        } catch (error) {
            console.warn("Unable to load available themes:", error);
            state.availableThemes = [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
        }
        renderThemeOptions();
        return state.availableThemes;
    }

    // Updates theme directory hint.
    async function updateThemeDirectoryHint() {
        const hintEl = document.getElementById("settings-themes-directory-hint");
        if (!hintEl || !window.themeapi || typeof window.themeapi.getThemesDirectory !== "function") {
            return;
        }
        try {
            const themesDir = await window.themeapi.getThemesDirectory();
            if (themesDir) {
                hintEl.textContent = `Add custom theme JSON files in ${themesDir} and restart or reopen Settings.`;
            }
        } catch (error) {
            console.warn("Unable to resolve themes directory:", error);
        }
    }

    function getThemesPreviewElement() {
        return document.getElementById("settings-themes-preview");
    }

    function getThemesPreviewFallbackElement() {
        return document.getElementById("settings-themes-preview-fallback");
    }

    function getThemesCatalogListElement() {
        return document.getElementById("settings-themes-catalog-list");
    }

    function getThemesCatalogStatusElement() {
        return document.getElementById("settings-themes-catalog-status");
    }

    function setThemesCatalogStatus(message, { isError = false } = {}) {
        const statusEl = getThemesCatalogStatusElement();
        if (!statusEl) return;
        statusEl.textContent = String(message || "");
        statusEl.style.color = isError ? "#ff9090" : "";
    }

    function getThemesCatalogSandboxBannerElement() {
        return document.getElementById("settings-themes-catalog-sandbox-banner");
    }

    // Show or hide the sandbox warning banner above the catalog list. The
    // catalog server signals sandbox mode via either ``paddleEnv: "sandbox"``
    // (preferred) or the legacy ``sandbox: true`` boolean; either is enough.
    // Unknown / production responses hide the banner.
    function setThemesCatalogSandboxBanner({ paddleEnv, sandbox } = {}) {
        const bannerEl = getThemesCatalogSandboxBannerElement();
        if (!bannerEl) return;
        const isSandboxEnv = typeof paddleEnv === "string" && paddleEnv.trim().toLowerCase() === "sandbox";
        const isSandboxBool = sandbox === true;
        const isSandbox = isSandboxEnv || isSandboxBool;
        themesCatalogIsSandbox = isSandbox;
        themesCatalogPaddleEnv = typeof paddleEnv === "string" && paddleEnv.trim()
            ? paddleEnv.trim().toLowerCase()
            : (isSandbox ? "sandbox" : null);
        if (!isSandbox) {
            bannerEl.hidden = true;
            bannerEl.textContent = "";
            return;
        }
        bannerEl.hidden = false;
        bannerEl.textContent =
            "Sandbox mode: the theme catalog is connected to Paddle's sandbox "
            + "environment. Purchases will not be charged and no real licenses "
            + "will be issued.";
    }

    function clearThemesPreviewObjectUrl() {
        if (themesPreviewObjectUrl) {
            try {
                URL.revokeObjectURL(themesPreviewObjectUrl);
            } catch (_error) {
                // ignore
            }
            themesPreviewObjectUrl = null;
        }
    }

    function resetThemesPreview() {
        clearThemesPreviewObjectUrl();
        const previewEl = getThemesPreviewElement();
        const fallbackEl = getThemesPreviewFallbackElement();
        if (previewEl) {
            previewEl.style.removeProperty("background-image");
            previewEl.hidden = true;
        }
        if (fallbackEl) {
            fallbackEl.hidden = false;
        }
    }

    function showThemesPreviewFromDataUri(dataUri) {
        const previewEl = getThemesPreviewElement();
        const fallbackEl = getThemesPreviewFallbackElement();
        if (!previewEl || !fallbackEl) return;
        if (!dataUri) {
            resetThemesPreview();
            return;
        }
        previewEl.style.setProperty("background-image", `url(${dataUri})`);
        previewEl.hidden = false;
        fallbackEl.hidden = true;
    }

    function buildThemesPreviewDataUri(themeConfig) {
        if (!themeConfig) return null;
        // --- catalog-side shape: a raw "data:image/...;base64,..." string ---
        if (typeof themeConfig === "string") {
            if (/^data:image\/(png|jpeg|jpg);base64,[A-Za-z0-9+/=]+$/i.test(themeConfig)) {
                return themeConfig;
            }
            return null;
        }
        if (typeof themeConfig !== "object") return null;
        // --- new shape: a "data:image/...;base64,..." string in `.dataUri` ---
        if (typeof themeConfig.dataUri === "string" && themeConfig.dataUri) {
            if (/^data:image\/(png|jpeg|jpg);base64,[A-Za-z0-9+/=]+$/i.test(themeConfig.dataUri)) {
                return themeConfig.dataUri;
            }
        }
        // --- legacy shape: {format, base64} object ---
        const formatRaw = typeof themeConfig.format === "string"
            ? themeConfig.format.trim().toLowerCase()
            : "";
        const format = formatRaw === "jpeg" ? "jpg" : formatRaw;
        if (format !== "png" && format !== "jpg") return null;
        const rawBase64 = typeof themeConfig.base64 === "string"
            ? themeConfig.base64
            : typeof themeConfig.data === "string"
                ? themeConfig.data
                : "";
        if (!rawBase64) return null;
        const mime = format === "png" ? "image/png" : "image/jpeg";
        const base64 = rawBase64
            .replace(/^data:image\/(png|jpeg|jpg);base64,/i, "")
            .replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/=]+$/.test(base64)) return null;
        return `data:${mime};base64,${base64}`;
    }

    function getThemeEmbeddedPreviewDataUri(theme) {
        if (!theme || typeof theme !== "object") return null;
        if (themesEmbeddedPreviewCache.has(theme.id)) {
            return themesEmbeddedPreviewCache.get(theme.id) || null;
        }
        const dataUri = buildThemesPreviewDataUri(theme.previewImage);
        themesEmbeddedPreviewCache.set(theme.id, dataUri || "");
        return dataUri;
    }

    async function fetchThemesPreviewFromUrl(previewUrl) {
        if (!window.themeapi || typeof window.themeapi.fetchPreview !== "function") {
            return null;
        }
        const requestToken = ++themesPreviewInFlight;
        try {
            const result = await window.themeapi.fetchPreview({ url: previewUrl });
            if (requestToken !== themesPreviewInFlight) {
                // A newer request superseded us; discard this one to avoid races.
                if (result && result.dataUri && result.dataUri.startsWith("blob:")) {
                    try {
                        URL.revokeObjectURL(result.dataUri);
                    } catch (_e) {
                        // ignore
                    }
                }
                return null;
            }
            if (result && typeof result.dataUri === "string" && result.dataUri) {
                // Revoke any prior blob URL before adopting the new one.
                if (themesPreviewObjectUrl) {
                    try {
                        URL.revokeObjectURL(themesPreviewObjectUrl);
                    } catch (_e) {
                        // ignore
                    }
                }
                if (result.dataUri.startsWith("blob:")) {
                    themesPreviewObjectUrl = result.dataUri;
                }
                return result.dataUri;
            }
            return null;
        } catch (error) {
            console.warn("Unable to fetch theme preview:", error);
            return null;
        }
    }

    async function refreshThemesPreviewForSelected() {
        const themeSelectEl = getThemeSelectElement();
        if (!themeSelectEl) return;
        const selectedId = sanitizeThemeId(themeSelectEl.value, FALLBACK_THEME_ID);
        const theme = getThemeByIdFromList(selectedId);
        if (!theme) {
            resetThemesPreview();
            return;
        }
        const embeddedDataUri = getThemeEmbeddedPreviewDataUri(theme);
        if (embeddedDataUri) {
            showThemesPreviewFromDataUri(embeddedDataUri);
            return;
        }
        const previewUrl = typeof theme.previewUrl === "string" ? theme.previewUrl.trim() : "";
        if (previewUrl) {
            resetThemesPreview();
            const dataUri = await fetchThemesPreviewFromUrl(previewUrl);
            if (dataUri) {
                showThemesPreviewFromDataUri(dataUri);
            } else {
                resetThemesPreview();
            }
            return;
        }
        resetThemesPreview();
    }

    function renderThemesCatalog() {
        const listEl = getThemesCatalogListElement();
        if (!listEl) return;
        listEl.innerHTML = "";
        if (!Array.isArray(themesCatalogEntries) || themesCatalogEntries.length === 0) {
            return;
        }
        themesCatalogEntries.forEach((entry) => {
            if (!entry || typeof entry !== "object") return;
            const cardEl = document.createElement("div");
            cardEl.className = "settings-themes-catalog-card";
            cardEl.setAttribute("role", "listitem");

            const nameEl = document.createElement("div");
            nameEl.className = "settings-themes-catalog-name";
            nameEl.textContent = String(entry.name || entry.id || "Theme");
            cardEl.appendChild(nameEl);

            if (entry.description) {
                const descEl = document.createElement("div");
                descEl.className = "settings-themes-catalog-desc";
                descEl.textContent = String(entry.description);
                cardEl.appendChild(descEl);
            }

            const priceEl = document.createElement("div");
            priceEl.className = "settings-themes-catalog-price";
            const priceLabel = typeof entry.priceLabel === "string" && entry.priceLabel.trim()
                ? entry.priceLabel.trim()
                : (typeof entry.priceCents === "number" && entry.priceCents > 0
                    ? `$${(entry.priceCents / 100).toFixed(2)}`
                    : "Free / included");
            priceEl.textContent = priceLabel;
            cardEl.appendChild(priceEl);

            const statusEl = document.createElement("div");
            statusEl.className = "settings-themes-catalog-status";
            if (entry.owned) {
                statusEl.textContent = "Owned";
                statusEl.style.color = "#7be58a";
            } else if (entry.installed) {
                statusEl.textContent = "Installed (not licensed)";
                statusEl.style.color = "#ffcf6b";
            } else {
                statusEl.textContent = "Available for purchase";
                statusEl.style.color = "";
            }
            cardEl.appendChild(statusEl);

            const actionsEl = document.createElement("div");
            actionsEl.className = "settings-actions-row";
            actionsEl.style.marginTop = "0.4rem";

            const previewBtn = document.createElement("button");
            previewBtn.type = "button";
            previewBtn.textContent = "Preview";
            previewBtn.addEventListener("click", () => {
                showThemesPreviewFromDataUri(buildThemesPreviewDataUri(entry.previewImage));
            });
            actionsEl.appendChild(previewBtn);

            const buyBtn = document.createElement("button");
            buyBtn.type = "button";
            buyBtn.textContent = entry.owned ? "Open in Browser" : "Buy";
            buyBtn.disabled = !entry.owned && !entry.checkoutUrl;
            buyBtn.addEventListener("click", () => {
                void startThemeCheckout(entry);
            });
            actionsEl.appendChild(buyBtn);

            cardEl.appendChild(actionsEl);
            listEl.appendChild(cardEl);
        });
    }

    // True when the catalog is idle (not mid-fetch) and we have no entries
    // loaded yet. The orchestrator uses this to decide whether to auto-fetch
    // on first open of the Themes subtab. Encapsulated as a helper so the
    // closure-private ``themesCatalogLoading`` / ``themesCatalogEntries``
    // identifiers do not leak across the factory boundary.
    function isThemesCatalogReady() {
        return !themesCatalogLoading
            && Array.isArray(themesCatalogEntries)
            && themesCatalogEntries.length === 0;
    }

    async function refreshThemesCatalog({ force = false } = {}) {
        if (!window.themeapi || typeof window.themeapi.listCatalog !== "function") {
            setThemesCatalogStatus("Online theme catalog is not available in this build.", { isError: true });
            return;
        }
        if (themesCatalogLoading && !force) return;
        themesCatalogLoading = true;
        setThemesCatalogStatus("Loading catalog...");
        try {
            const result = await window.themeapi.listCatalog({ force });
            themesCatalogEntries = Array.isArray(result?.entries) ? result.entries : [];
            // Update the sandbox banner whenever we get a fresh catalog response.
            // We read both signals (paddleEnv string and sandbox boolean) so we
            // don't break if the server only emits one.
            setThemesCatalogSandboxBanner({
                paddleEnv: result?.paddleEnv,
                sandbox: result?.sandbox,
            });
            if (result && result.success === false) {
                // The main process already produced a human-readable error
                // message (e.g. "Could not reach theme server… change to https://…
                // and try again"). Surface it verbatim instead of the generic
                // "no themes" line, which was hiding protocol-mismatch bugs.
                setThemesCatalogStatus(
                    result.error
                        ? `Unable to load theme catalog: ${result.error}`
                        : "Unable to load theme catalog.",
                    { isError: true },
                );
            } else {
                setThemesCatalogStatus(
                    themesCatalogEntries.length === 0
                        ? "No themes are available for purchase right now."
                        : `Loaded ${themesCatalogEntries.length} theme(s).`,
                );
            }
            renderThemesCatalog();
        } catch (error) {
            console.warn("Unable to load theme catalog:", error);
            setThemesCatalogStatus(
                `Unable to load theme catalog: ${error?.message || error || "unknown error"}`,
                { isError: true },
            );
        } finally {
            themesCatalogLoading = false;
        }
    }

    // Subscribe once to the main-process deeplink channel so a
    // ``packetsnitch://checkout-success?...`` click in the user's browser
    // automatically reconciles licenses and refreshes the catalog without
    // the user having to manually click "Check License".
    if (window.themeapi && typeof window.themeapi.onCheckoutSuccessDeeplink === "function") {
        window.themeapi.onCheckoutSuccessDeeplink(async (payload) => {
            try {
                const themeId = String(payload?.themeId || "").trim();
                const unlocked = Array.isArray(payload?.unlockedThemeIds)
                    ? payload.unlockedThemeIds
                    : [];
                const errorText = payload?.error ? String(payload.error) : "";
                if (errorText) {
                    setThemesCatalogStatus(
                        `Deeplink received, but license reconcile failed: ${errorText}. You can click "Check License" to retry.`,
                        { isError: true },
                    );
                } else if (unlocked.length > 0) {
                    const unlockedList = unlocked.join(", ");
                    setThemesCatalogStatus(
                        themeId && unlocked.includes(themeId)
                            ? `Theme "${themeId}" unlocked via deeplink. Reloading...`
                            : `Unlocked ${unlocked.length} theme(s) via deeplink: ${unlockedList}. Reloading...`,
                    );
                    await loadAvailableThemes();
                    await refreshThemesPreviewForSelected();
                    // Re-fetch the catalog so newly-licensed themes show as "owned".
                    try {
                        await refreshThemesCatalog({ force: false });
                    } catch (_e) {
                        // ignore — the catalog is a best-effort refresh
                    }
                } else {
                    setThemesCatalogStatus(
                        "Deeplink received, but no new licenses were granted yet. Paddle may still be processing the payment. You can click \"Check License\" to retry.",
                    );
                }
            } catch (error) {
                console.warn("Deeplink handler failed:", error);
                setThemesCatalogStatus(
                    `Deeplink handler failed: ${error?.message || error || "unknown error"}`,
                    { isError: true },
                );
            }
        });
    }

    async function startThemeCheckout(catalogEntry) {
        if (!catalogEntry || typeof catalogEntry !== "object") return;
        if (!window.themeapi || typeof window.themeapi.startCheckout !== "function") {
            setThemesCatalogStatus("Checkout is not available in this build.", { isError: true });
            return;
        }
        if (catalogEntry.owned && catalogEntry.licenseUrl) {
            try {
                await window.themeapi.openExternalUrl(catalogEntry.licenseUrl);
            } catch (_e) {
                // ignore
            }
            return;
        }
        setThemesCatalogStatus(
            themesCatalogIsSandbox
                ? "Opening checkout in your default browser. Sandbox mode is active — no real payment will be taken."
                : "Opening checkout in your default browser...",
        );
        try {
            const result = await window.themeapi.startCheckout({
                themeId: catalogEntry.id,
                checkoutUrl: catalogEntry.checkoutUrl || "",
            });
            if (result?.success) {
                setThemesCatalogStatus(
                    result.openedExternally
                        ? "Checkout opened in your default browser. After completing payment, click Check License to refresh."
                        : "Checkout is ready. After completing payment, click Check License to refresh.",
                );
            } else {
                setThemesCatalogStatus(
                    `Unable to start checkout: ${result?.error || "unknown error"}`,
                    { isError: true },
                );
            }
        } catch (error) {
            setThemesCatalogStatus(
                `Unable to start checkout: ${error?.message || error || "unknown error"}`,
                { isError: true },
            );
        }
    }

    async function checkThemesLicense() {
        if (!window.themeapi || typeof window.themeapi.refreshLicenses !== "function") {
            setThemesCatalogStatus("License check is not available in this build.", { isError: true });
            return;
        }
        setThemesCatalogStatus("Checking license for this install...");
        try {
            const result = await window.themeapi.refreshLicenses();
            const unlocked = Array.isArray(result?.unlockedThemeIds)
                ? result.unlockedThemeIds
                : [];
            // License reconcile also surfaces the server's Paddle environment,
            // so refresh the sandbox banner in case the catalog fetch has been
            // delayed or the user clicked Check License first.
            setThemesCatalogSandboxBanner({
                paddleEnv: result?.paddleEnv,
                sandbox: result?.sandbox,
            });
            setThemesCatalogStatus(
                unlocked.length === 0
                    ? "No new themes unlocked for this install yet."
                    : `Unlocked ${unlocked.length} theme(s): ${unlocked.join(", ")}. Reloading...`,
            );
            if (unlocked.length > 0) {
                await loadAvailableThemes();
                await refreshThemesPreviewForSelected();
                await refreshThemesCatalog({ force: true });
            }
        } catch (error) {
            setThemesCatalogStatus(
                `Unable to check license: ${error?.message || error || "unknown error"}`,
                { isError: true },
            );
        }
    }

    function bindThemesSubtabEvents() {
        const refreshBtn = document.getElementById("settings-themes-refresh-catalog-btn");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                void refreshThemesCatalog({ force: true });
            });
        }
        const checkLicenseBtn = document.getElementById("settings-themes-check-license-btn");
        if (checkLicenseBtn) {
            checkLicenseBtn.addEventListener("click", () => {
                void checkThemesLicense();
            });
        }
        const selectEl = getThemeSelectElement();
        if (selectEl) {
            selectEl.addEventListener("change", () => {
                void refreshThemesPreviewForSelected();
            });
        }
    }

    return {
        // Public helpers consumed by the renderer orchestrator and the
        // settings form. Each one mirrors the original top-level function
        // it replaced; call sites that previously invoked the bare
        // function name now go through ``themesHelpers.X(...)``.
        sanitizeThemeId,
        getThemeSelectElement,
        getThemeByIdFromList,
        getThemeSourceSuffix,
        updateSelectedThemeSourceNote,
        renderThemeOptions,
        getConfiguredOllamaModels,
        getOllamaModelDropdownOptions,
        renderLlmModelOptions,
        loadAvailableOllamaModels,
        parseHexColorToRgb,
        isThemeLight,
        applyThemeDropdownColors,
        applySettingsAboutTerminalTheme,
        applyThemeVariables,
        applyThemeQuitButtonCharacter,
        getAppLogoElement,
        applyThemeLogo,
        applyThemeBackdropImage,
        applyThemeById,
        loadAvailableThemes,
        updateThemeDirectoryHint,
        getThemesPreviewElement,
        getThemesPreviewFallbackElement,
        getThemesCatalogListElement,
        getThemesCatalogStatusElement,
        setThemesCatalogStatus,
        getThemesCatalogSandboxBannerElement,
        setThemesCatalogSandboxBanner,
        clearThemesPreviewObjectUrl,
        resetThemesPreview,
        showThemesPreviewFromDataUri,
        buildThemesPreviewDataUri,
        getThemeEmbeddedPreviewDataUri,
        fetchThemesPreviewFromUrl,
        refreshThemesPreviewForSelected,
        renderThemesCatalog,
        refreshThemesCatalog,
        isThemesCatalogReady,
        startThemeCheckout,
        checkThemesLicense,
        bindThemesSubtabEvents,

        // Constants the settings form also references directly.
        FALLBACK_THEME_ID,
    };
}

module.exports = {
    createThemesCatalogHelpers,
};