// Release-notes/about extraction. Owns the GitHub release check,
// version comparison, "settings about" typewriter readout, and
// download-button state for the Settings → About pane. The factory
// takes a state object (for the 10 release-cluster module-level
// vars) plus a handful of orchestrator callbacks and constants
// (release URLs, identity strings, settings tab helpers, the
// external-URL opener). See main-frontend.js for the
// ``releaseNotesState`` getter/setter bridge that keeps the
// orchestrator's identifier-style access in lockstep with the
// factory.

function createReleaseNotesHelpers({
    state,
    PACKETSNITCH_VERSION,
    PACKETSNITCH_RELEASES_API_URL,
    PACKETSNITCH_RELEASES_LATEST_API_URL,
    PACKETSNITCH_RELEASES_PAGE_URL,
    PACKETSNITCH_AUTHOR_NAME,
    PACKETSNITCH_TERMINAL_IDENTITY,
    getCurrentSettings,
    setSettingsSubtab,
    showSettingsWorkspace,
    openExternalUrl,
}) {
function normalizeReleaseVersionToken(value) {
  if (typeof value !== "string") return "";
  return value
    .trim()
    .toLowerCase()
    .replace(/^v+/, "")
    .replace(/^packetsnitch[-_\s]*/i, "");
}

function getReleaseVersionToken(release) {
  if (!release || typeof release !== "object") return "";
  const candidateValues = [release.tag_name, release.name];
  for (const candidate of candidateValues) {
    if (typeof candidate === "string" && candidate.trim()) {
      const normalized = normalizeReleaseVersionToken(candidate);
      if (normalized) return normalized;
    }
  }
  return "";
}

function compareReleaseVersionTokens(leftValue, rightValue) {
  const leftToken = normalizeReleaseVersionToken(leftValue);
  const rightToken = normalizeReleaseVersionToken(rightValue);
  const leftParts = leftToken.match(/\d+|[a-z]+/g) || [];
  const rightParts = rightToken.match(/\d+|[a-z]+/g) || [];
  const maxLength = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < maxLength; index += 1) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (typeof leftPart === "undefined" && typeof rightPart === "undefined") {
      return 0;
    }
    if (typeof leftPart === "undefined") {
      return -1;
    }
    if (typeof rightPart === "undefined") {
      return 1;
    }

    const leftIsNumber = /^\d+$/.test(leftPart);
    const rightIsNumber = /^\d+$/.test(rightPart);
    if (leftIsNumber && rightIsNumber) {
      const numericDiff = Number.parseInt(leftPart, 10) - Number.parseInt(rightPart, 10);
      if (numericDiff !== 0) {
        return numericDiff;
      }
      continue;
    }
    if (leftIsNumber !== rightIsNumber) {
      return leftIsNumber ? 1 : -1;
    }

    const lexicalDiff = leftPart.localeCompare(rightPart);
    if (lexicalDiff !== 0) {
      return lexicalDiff;
    }
  }

  return 0;
}

async function detectLinuxReleasePackageFamily(runtimePlatform = "") {
  const normalizedRuntimePlatform = String(runtimePlatform || "").trim().toLowerCase();
  const platformName = normalizedRuntimePlatform || await detectRuntimePlatform();
  if (platformName !== "linux") {
    return "";
  }
  if (state.cachedLinuxReleasePackageFamily !== null) {
    return state.cachedLinuxReleasePackageFamily;
  }

  if (!window.browserapi || typeof window.browserapi.getLinuxReleasePackageFamily !== "function") {
    state.cachedLinuxReleasePackageFamily = "";
    return state.cachedLinuxReleasePackageFamily;
  }

  try {
    const response = await window.browserapi.getLinuxReleasePackageFamily();
    const family = typeof response?.family === "string" ? response.family.trim().toLowerCase() : "";
    state.cachedLinuxReleasePackageFamily = family === "debian" || family === "redhat" ? family : "";
  } catch (_error) {
    state.cachedLinuxReleasePackageFamily = "";
  }
  return state.cachedLinuxReleasePackageFamily;
}

async function detectRuntimePlatform() {
  if (state.cachedRuntimePlatform) {
    return state.cachedRuntimePlatform;
  }

  if (window.browserapi && typeof window.browserapi.getRuntimePlatform === "function") {
    try {
      const response = await window.browserapi.getRuntimePlatform();
      const runtimePlatform = typeof response?.platform === "string"
        ? response.platform.trim().toLowerCase()
        : "";
      if (runtimePlatform) {
        state.cachedRuntimePlatform = runtimePlatform;
        return state.cachedRuntimePlatform;
      }
    } catch (_error) {
      // Fall back to local process metadata below.
    }
  }

  state.cachedRuntimePlatform = typeof process !== "undefined" && typeof process.platform === "string"
    ? process.platform
    : "";
  return state.cachedRuntimePlatform;
}

function getReleaseDownloadAssetPreferences(
  platformName = (typeof process !== "undefined" ? process.platform : ""),
  linuxPackageFamily = "",
) {
  switch (platformName) {
    case "win32":
      return [".exe"];
    case "darwin":
      return [".dmg", ".pkg", ".zip"];
    case "linux": {
      if (linuxPackageFamily === "debian") {
        return [".deb", ".rpm", ".appimage", ".tar.gz", ".tgz", ".zip"];
      }
      if (linuxPackageFamily === "redhat") {
        return [".rpm", ".deb", ".appimage", ".tar.gz", ".tgz", ".zip"];
      }
      return [".deb", ".rpm", ".appimage", ".tar.gz", ".tgz", ".zip"];
    }
    default:
      return [".zip", ".tar.gz", ".tgz"];
  }
}

function selectReleaseDownloadAsset(release, { linuxPackageFamily = "", runtimePlatform = "" } = {}) {
  if (!release || typeof release !== "object") return null;
  const assets = Array.isArray(release.assets) ? release.assets : [];
  if (assets.length === 0) return null;
  const platformName = runtimePlatform
    || (typeof process !== "undefined" ? process.platform : "");
  const preferences = getReleaseDownloadAssetPreferences(platformName, linuxPackageFamily);
  const normalizedAssets = assets.filter((asset) => asset && typeof asset === "object");

  const assetMatchesSuffix = (asset, suffix) => {
    const suffixLower = String(suffix || "").toLowerCase();
    const suffixRegex = new RegExp(`${suffixLower.replace(/\./g, "\\.")}(?:$|[?#])`, "i");
    const assetName = String(asset?.name || "").trim().toLowerCase();
    const assetUrl = String(asset?.browser_download_url || "").trim().toLowerCase();
    return suffixRegex.test(assetName) || suffixRegex.test(assetUrl);
  };

  for (const preferredSuffix of preferences) {
    const matchedAsset = normalizedAssets.find((asset) => {
      return assetMatchesSuffix(asset, preferredSuffix);
    });
    if (matchedAsset?.browser_download_url) {
      return matchedAsset;
    }
  }

  // For Windows we should only offer the executable package.
  if (platformName === "win32") {
    return null;
  }

  if (platformName === "linux" && linuxPackageFamily === "redhat") {
    const bestNonDebAsset = normalizedAssets.find(
      (asset) => typeof asset.browser_download_url === "string"
        && asset.browser_download_url.trim()
        && !assetMatchesSuffix(asset, ".deb"),
    );
    if (bestNonDebAsset) {
      return bestNonDebAsset;
    }
  }

  if (platformName === "linux" && linuxPackageFamily === "debian") {
    const bestNonRpmAsset = normalizedAssets.find(
      (asset) => typeof asset.browser_download_url === "string"
        && asset.browser_download_url.trim()
        && !assetMatchesSuffix(asset, ".rpm"),
    );
    if (bestNonRpmAsset) {
      return bestNonRpmAsset;
    }
  }

  return normalizedAssets.find((asset) => typeof asset.browser_download_url === "string" && asset.browser_download_url.trim()) || null;
}

function buildReleaseDownloadInfo(
  release,
  runningVersion,
  { linuxPackageFamily = "", runtimePlatform = "" } = {},
) {
  const latestReleaseVersion = getReleaseVersionToken(release);
  const newVersionAvailable = compareReleaseVersionTokens(latestReleaseVersion, runningVersion) > 0;
  if (!newVersionAvailable) {
    return {
      newVersionAvailable: false,
      downloadUrl: "",
      downloadAssetName: "",
    };
  }

  const selectedAsset = selectReleaseDownloadAsset(release, {
    linuxPackageFamily,
    runtimePlatform,
  });
  return {
    newVersionAvailable: Boolean(selectedAsset?.browser_download_url),
    downloadUrl: typeof selectedAsset?.browser_download_url === "string"
      ? selectedAsset.browser_download_url.trim()
      : "",
    downloadAssetName: typeof selectedAsset?.name === "string" ? selectedAsset.name.trim() : "",
  };
}

function shouldCheckForNewReleasesOnStartup() {
  return Boolean(getCurrentSettings()?.general?.checkForNewReleasesOnStartup);
}

async function maybeShowSettingsAboutForNewRelease() {
  state.startupReleaseCheckHandled = true;
  if (!shouldCheckForNewReleasesOnStartup()) {
    if (state.resolveStartupReleaseCheckPromise) {
      state.resolveStartupReleaseCheckPromise(false);
      state.resolveStartupReleaseCheckPromise = null;
    }
    return false;
  }

  const releaseInfo = await loadSettingsAboutReleaseInfo({ forceRefresh: true });
  const newVersionAvailable = Boolean(releaseInfo?.downloadInfo?.newVersionAvailable);
  if (!newVersionAvailable) {
    if (state.resolveStartupReleaseCheckPromise) {
      state.resolveStartupReleaseCheckPromise(false);
      state.resolveStartupReleaseCheckPromise = null;
    }
    return false;
  }

  showSettingsWorkspace();
  setSettingsSubtab(SETTINGS_SUBTAB_ABOUT);
  if (state.resolveStartupReleaseCheckPromise) {
    state.resolveStartupReleaseCheckPromise(true);
    state.resolveStartupReleaseCheckPromise = null;
  }
  return true;
}

function syncSettingsAboutDownloadButton() {
  const downloadButtonEl = document.getElementById("settings-about-download-btn");
  if (!downloadButtonEl) return;

  const downloadUrl = state.settingsAboutDownloadButtonUrl || "";
  const visible = Boolean(downloadUrl);
  downloadButtonEl.hidden = !visible;
  downloadButtonEl.disabled = !visible;
  downloadButtonEl.setAttribute("aria-hidden", visible ? "false" : "true");
  downloadButtonEl.dataset.downloadUrl = downloadUrl;
  downloadButtonEl.title = visible ? "Download the latest PacketSnitch release for this OS" : "";
}

function setSettingsAboutDownloadButtonState(downloadInfo = {}) {
  state.settingsAboutDownloadButtonUrl =
    typeof downloadInfo.downloadUrl === "string" && downloadInfo.downloadUrl.trim()
      ? downloadInfo.downloadUrl.trim()
      : "";
  syncSettingsAboutDownloadButton();
}

async function openSettingsAboutDownloadUrl() {
  const downloadUrl = state.settingsAboutDownloadButtonUrl;
  if (!downloadUrl || !window.browserapi || typeof window.browserapi.openExternalUrl !== "function") {
    return;
  }

  try {
    await window.browserapi.openExternalUrl(downloadUrl);
  } catch (error) {
    console.warn("Unable to open PacketSnitch release download URL:", error);
  }
}

function normalizeReleaseNotesForTerminal(bodyText) {
  if (typeof bodyText !== "string" || !bodyText.trim()) {
    return "No release notes were provided for this release.";
  }
  const normalizedNewlines = bodyText.replace(/\r\n/g, "\n");

  // Strip HTML tags/content wrappers (e.g. <img ...>, <a ...>, <br>) from release text.
  let plainText = normalizedNewlines.replace(/<[^>]*>/g, " ");

  // Remove fenced code blocks and inline code markers.
  plainText = plainText.replace(/```[\s\S]*?```/g, " ");
  plainText = plainText.replace(/`([^`]+)`/g, "$1");

  // Convert common markdown links/images to plain text.
  plainText = plainText.replace(/!\[[^\]]*\]\([^\)]*\)/g, " ");
  plainText = plainText.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, "$1");

  // Remove markdown heading/quote/list markers and emphasis syntax.
  plainText = plainText.replace(/^\s{0,3}#{1,6}\s*/gm, "");
  plainText = plainText.replace(/^\s{0,3}>\s?/gm, "");
  plainText = plainText.replace(/^\s*[-*+]\s+/gm, "");
  plainText = plainText.replace(/^\s*\d+\.\s+/gm, "");
  plainText = plainText.replace(/\*\*([^*]+)\*\*/g, "$1");
  plainText = plainText.replace(/__([^_]+)__/g, "$1");
  plainText = plainText.replace(/\*([^*]+)\*/g, "$1");
  plainText = plainText.replace(/_([^_]+)_/g, "$1");
  plainText = plainText.replace(/~~([^~]+)~~/g, "$1");
  plainText = plainText.replace(/^\s*[-*_]{3,}\s*$/gm, "");

  // Normalize whitespace for terminal display.
  plainText = plainText
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();

  return plainText || "No release notes were provided for this release.";
}

function buildSettingsAboutTerminalReadout({
  runningVersion,
  latestReleaseVersion,
  latestReleaseNotes,
  latestReleaseUrl,
  fetchError = "",
}) {
  const lines = [];
  lines.push("                          _       _ _");
  lines.push("  _____  ____ _ ___ _ __ | | ___ (_) |_ ___   ___ ___  _ __ ___");
  lines.push(" / _ \\\\ \/ / _` / __| '_ \\| |/ _ \\| | __/ __| / __/ _ \\| '_ ` _ \\");
  lines.push("| (_) >  < (_| \\__ \\ |_) | | (_) | | |_\\__ \\| (_| (_) | | | | | |");
  lines.push(" \\___/_/\\_\\__,_|___/ .__/|_|\\___/|_|\\__|___(_)___\\___/|_| |_| |_|");
  lines.push("                   |_|          Welcome to the oxsploits network.");
  lines.push("");
  lines.push(`${PACKETSNITCH_TERMINAL_IDENTITY}:~$ cat packetsnitch.txt`);
  lines.push("PacketSnitch: A feature rich network packet capture and analysis tool built in Python and NodeJS/Electron.");
  lines.push(`Author: ${PACKETSNITCH_AUTHOR_NAME}`);
  lines.push(`Running PacketSnitch version: ${runningVersion || "Unknown"}`);
  lines.push(`Latest release version: ${latestReleaseVersion || "Unavailable"}`);
  lines.push(`Release source: ${PACKETSNITCH_RELEASES_PAGE_URL}`);
  lines.push("");
  lines.push("=== Latest Release Notes ===");

  if (fetchError) {
    lines.push(`Unable to fetch releases: ${fetchError}`);
    lines.push("Showing local app metadata only.");
  } else {
    lines.push(`Release URL: ${latestReleaseUrl || PACKETSNITCH_RELEASES_PAGE_URL}`);
    lines.push("");
    lines.push(latestReleaseNotes || "No release notes available.");
  }

  return `${lines.join("\n")}\n`;
}

function clearSettingsAboutTypewriterTimeout() {
  if (state.settingsAboutTypewriterTimeoutId !== null) {
    clearTimeout(state.settingsAboutTypewriterTimeoutId);
    state.settingsAboutTypewriterTimeoutId = null;
  }
}

function renderSettingsAboutTerminalReadout(readoutText, { animateCommand = false } = {}) {
  const outputEl = document.getElementById("settings-about-terminal-output");
  if (!outputEl) return;

  const fullText = String(readoutText || "");
  state.settingsAboutTypewriterToken += 1;
  const activeToken = state.settingsAboutTypewriterToken;
  clearSettingsAboutTypewriterTimeout();

  if (!animateCommand) {
    outputEl.textContent = fullText;
    return;
  }

  const allLines = fullText.split("\n");
  const commandLineIndex = allLines.findIndex((line) => line.includes(":~$ "));
  if (commandLineIndex === -1) {
    outputEl.textContent = fullText;
    return;
  }

  const commandLine = allLines[commandLineIndex] || "";
  const preCommandOutput = allLines.slice(0, commandLineIndex).join("\n");
  const postCommandOutput = allLines.slice(commandLineIndex + 1).join("\n");
  const preCommandText = preCommandOutput ? `${preCommandOutput}\n` : "";
  const trailingText = postCommandOutput ? `\n${postCommandOutput}` : "";

  if (!commandLine) {
    outputEl.textContent = fullText;
    return;
  }

  const promptMarker = "$ ";
  const promptIndex = commandLine.indexOf(promptMarker);
  const hasPrompt = promptIndex !== -1;
  const promptText = hasPrompt
    ? commandLine.slice(0, promptIndex + promptMarker.length)
    : "";
  const typedCommandText = hasPrompt
    ? commandLine.slice(promptIndex + promptMarker.length)
    : commandLine;

  outputEl.textContent = `${preCommandText}${promptText}`;
  let cursor = 0;
  const charDelayMs = 30;
  const preTypeDelayMs = 1000;
  const preReturnDelayMs = 500;

  const typeNextCharacter = () => {
    if (activeToken !== state.settingsAboutTypewriterToken) return;

    if (cursor < typedCommandText.length) {
      outputEl.textContent += typedCommandText[cursor];
      cursor += 1;
      state.settingsAboutTypewriterTimeoutId = setTimeout(typeNextCharacter, charDelayMs);
      return;
    }

    state.settingsAboutTypewriterTimeoutId = setTimeout(() => {
      if (activeToken !== state.settingsAboutTypewriterToken) return;
      outputEl.textContent = `${preCommandText}${commandLine}${trailingText}`;
      state.settingsAboutTypewriterTimeoutId = null;
    }, preReturnDelayMs);
  };

  state.settingsAboutTypewriterTimeoutId = setTimeout(typeNextCharacter, preTypeDelayMs);
}

async function loadSettingsAboutReleaseInfo({ forceRefresh = false } = {}) {
  const runningVersion = String(psVer || "").trim() || "Unknown";
  if (!forceRefresh && state.cachedSettingsAboutReleaseInfo) {
    setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
    renderSettingsAboutTerminalReadout(
      buildSettingsAboutTerminalReadout(state.cachedSettingsAboutReleaseInfo),
      { animateCommand: true },
    );
    return state.cachedSettingsAboutReleaseInfo;
  }

  if (state.settingsAboutReleaseInfoLoadPromise && !forceRefresh) {
    await state.settingsAboutReleaseInfoLoadPromise;
    if (state.cachedSettingsAboutReleaseInfo) {
      setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
      renderSettingsAboutTerminalReadout(
        buildSettingsAboutTerminalReadout(state.cachedSettingsAboutReleaseInfo),
        { animateCommand: true },
      );
    }
    return state.cachedSettingsAboutReleaseInfo;
  }

  renderSettingsAboutTerminalReadout(
    buildSettingsAboutTerminalReadout({
      runningVersion,
      latestReleaseVersion: "Loading...",
      latestReleaseNotes: "Fetching latest release metadata from GitHub...",
      latestReleaseUrl: PACKETSNITCH_RELEASES_PAGE_URL,
    }),
    { animateCommand: false },
  );

  const loadPromise = (async () => {
    try {
      const githubHeaders = {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      };

      let latestRelease = null;

      // Prefer the dedicated latest-release endpoint for reliability.
      try {
        const latestResponse = await fetch(PACKETSNITCH_RELEASES_LATEST_API_URL, {
          headers: githubHeaders,
        });
        if (!latestResponse.ok) {
          throw new Error(`GitHub latest endpoint returned HTTP ${latestResponse.status}`);
        }
        const latestPayload = await latestResponse.json();
        if (latestPayload && typeof latestPayload === "object" && !latestPayload.draft) {
          latestRelease = latestPayload;
        }
      } catch (latestEndpointError) {
        // Fall through to releases list endpoint.
      }

      if (!latestRelease) {
        const releasesResponse = await fetch(PACKETSNITCH_RELEASES_API_URL, {
          headers: githubHeaders,
        });
        if (!releasesResponse.ok) {
          throw new Error(`GitHub releases endpoint returned HTTP ${releasesResponse.status}`);
        }
        const payload = await releasesResponse.json();
        const releases = Array.isArray(payload)
          ? payload.filter((release) => release && typeof release === "object" && !release.draft)
          : [];
        latestRelease = releases.find((release) => !release.prerelease) || releases[0] || null;
      }

      if (!latestRelease) {
        throw new Error("No releases returned by GitHub API");
      }

      const runtimePlatform = await detectRuntimePlatform();
      const linuxPackageFamily = runtimePlatform === "linux"
        ? await detectLinuxReleasePackageFamily(runtimePlatform)
        : "";

      state.cachedSettingsAboutReleaseInfo = {
        runningVersion,
        latestReleaseVersion: getReleaseVersionToken(latestRelease) || "Unavailable",
        latestReleaseNotes: normalizeReleaseNotesForTerminal(latestRelease?.body),
        latestReleaseUrl:
          typeof latestRelease?.html_url === "string" && latestRelease.html_url.trim()
            ? latestRelease.html_url.trim()
            : PACKETSNITCH_RELEASES_PAGE_URL,
        downloadInfo: buildReleaseDownloadInfo(latestRelease, runningVersion, {
          linuxPackageFamily,
          runtimePlatform,
        }),
        fetchError: "",
      };
    } catch (error) {
      const errorMessage =
        error && typeof error.message === "string" && error.message.trim()
          ? error.message.trim()
          : String(error || "Unknown error");
      state.cachedSettingsAboutReleaseInfo = {
        runningVersion,
        latestReleaseVersion: "Lookup failed",
        latestReleaseNotes:
          "Unable to retrieve release notes from GitHub right now.\n"
          + "Use the Refresh release notes button to retry.",
        latestReleaseUrl: PACKETSNITCH_RELEASES_PAGE_URL,
        downloadInfo: {
          newVersionAvailable: false,
          downloadUrl: "",
          downloadAssetName: "",
        },
        fetchError: errorMessage,
      };
      console.warn("Unable to load PacketSnitch release metadata:", error);
    }
    setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
    renderSettingsAboutTerminalReadout(
      buildSettingsAboutTerminalReadout(state.cachedSettingsAboutReleaseInfo),
      { animateCommand: true },
    );
    return state.cachedSettingsAboutReleaseInfo;
  })();

  state.settingsAboutReleaseInfoLoadPromise = loadPromise;
  try {
    return await loadPromise;
  } finally {
    if (state.settingsAboutReleaseInfoLoadPromise === loadPromise) {
      state.settingsAboutReleaseInfoLoadPromise = null;
    }
  }
}


    return {
        normalizeReleaseVersionToken,
        getReleaseVersionToken,
        compareReleaseVersionTokens,
        detectLinuxReleasePackageFamily,
        detectRuntimePlatform,
        getReleaseDownloadAssetPreferences,
        selectReleaseDownloadAsset,
        buildReleaseDownloadInfo,
        shouldCheckForNewReleasesOnStartup,
        maybeShowSettingsAboutForNewRelease,
        syncSettingsAboutDownloadButton,
        setSettingsAboutDownloadButtonState,
        openSettingsAboutDownloadUrl,
        normalizeReleaseNotesForTerminal,
        buildSettingsAboutTerminalReadout,
        clearSettingsAboutTypewriterTimeout,
        renderSettingsAboutTerminalReadout,
        loadSettingsAboutReleaseInfo,
    };
}

module.exports = {
    createReleaseNotesHelpers,
};
