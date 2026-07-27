// Controls the startup install and environment-check screen shown before the main UI.

// Shows install screen.
function showInstallScreen(installInfo, documentRef) {
  const screen = documentRef.getElementById("install-screen");
  if (!screen) return;

  documentRef.getElementById("install-version").textContent =
    "Version " + installInfo.version;

  const fileList = documentRef.getElementById("install-file-list");
  fileList.innerHTML = "";
  installInfo.installedFiles.forEach((file) => {
    const item = documentRef.createElement("li");
    item.className = file.exists ? "install-file-ok" : "install-file-missing";
    item.textContent = (file.exists ? "\u2713 " : "\u2717 ") + file.name;
    if (!file.exists) {
      item.title = "Not found at: " + file.path;
    }
    fileList.appendChild(item);
  });

  const ollamaStatus = documentRef.getElementById("install-ollama-status");
  if (!installInfo.ollamaInstalled) {
    ollamaStatus.textContent =
      "\u26a0 Ollama is not installed. LLM packet summarisation will be unavailable. Install Ollama from https://ollama.com to enable this feature.";
    ollamaStatus.className = "install-warning";
  } else {
    ollamaStatus.textContent =
      "\u2713 Ollama is installed. LLM summarisation is available.";
    ollamaStatus.className = "install-ok";
  }

  screen.style.display = "flex";
}

// Returns true when the consent overlay is currently visible.
function isConsentOverlayVisible(documentRef) {
  const overlay = documentRef.getElementById("metrics-consent-overlay");
  return Boolean(overlay) && !overlay.hidden;
}

// Hides the consent overlay (used by the buttons and by tests).
function hideConsentOverlay(documentRef) {
  const overlay = documentRef.getElementById("metrics-consent-overlay");
  if (overlay) {
    overlay.hidden = true;
  }
}

// Shows the consent overlay if the user has not been asked yet and we
// are not in a test environment. Safe to call multiple times.
function maybeShowConsentOverlay({ documentRef, metrics }) {
  if (!documentRef) return false;
  const overlay = documentRef.getElementById("metrics-consent-overlay");
  if (!overlay) return false;
  if (isConsentOverlayVisible(documentRef)) return true;
  if (!metrics || typeof metrics.getConsentStatus !== "function") {
    return false;
  }
  if (metrics.getConsentStatus() !== "first-run") {
    return false;
  }
  overlay.hidden = false;
  return true;
}

// Initializes install screen.
function initializeInstallScreen({ installapi, documentRef, metrics }) {
  if (installapi) {
    installapi.checkFirstRun().then((installInfo) => {
      if (installInfo && installInfo.isFirstRun) {
        showInstallScreen(installInfo, documentRef);
        return;
      }
      // No install screen on this launch (already dismissed, or
      // there is no install flow at all). Still surface the
      // first-run consent prompt if the user has never answered it
      // on this install. The overlay is hidden by default and we
      // only un-hide it when the snapshot says we are on a clean
      // install.
      maybeShowConsentOverlay({ documentRef, metrics });
    });
  } else {
    // No install api (e.g. test harness). Still try the consent
    // overlay so a clean config without a first-run install flag
    // still surfaces the prompt.
    maybeShowConsentOverlay({ documentRef, metrics });
  }

  const installContinueBtn = documentRef.getElementById("install-continue-btn");
  if (!installContinueBtn) return;

  installContinueBtn.addEventListener("click", () => {
    if (installapi) {
      installapi.dismissFirstRun().then(() => {
        documentRef.getElementById("install-screen").style.display = "none";
        // After the install screen is dismissed, surface the first-run
        // consent prompt (if the user has not answered it yet). The
        // overlay blocks the rest of the UI so the user has to make an
        // explicit decision before continuing.
        if (window.__PACKETSNITCH_METRICS__ && typeof window.__PACKETSNITCH_METRICS__.recordConsent === "function") {
          maybeShowConsentOverlay({
            documentRef,
            metrics: window.__PACKETSNITCH_METRICS__,
          });
        }
      });
    } else {
      documentRef.getElementById("install-screen").style.display = "none";
      if (window.__PACKETSNITCH_METRICS__ && typeof window.__PACKETSNITCH_METRICS__.recordConsent === "function") {
        maybeShowConsentOverlay({
          documentRef,
          metrics: window.__PACKETSNITCH_METRICS__,
        });
      }
    }
  });

  // Wire the consent overlay's buttons. Either choice dismisses the
  // overlay and records the decision via ``metrics.recordConsent``,
  // which writes ``metricsConsentAsked``, ``metricsEnabled`` and
  // (on opt-in) a fresh install id to settings.json in one shot.
  const consentAcceptBtn = documentRef.getElementById("metrics-consent-accept");
  const consentDeclineBtn = documentRef.getElementById("metrics-consent-decline");
  const handleConsentChoice = (enabled) => {
    if (window.__PACKETSNITCH_METRICS__ && typeof window.__PACKETSNITCH_METRICS__.recordConsent === "function") {
      try {
        window.__PACKETSNITCH_METRICS__.recordConsent(Boolean(enabled));
      } catch (_error) {
        // ignore: the user can still change their mind in Settings
      }
    }
    hideConsentOverlay(documentRef);
  };
  if (consentAcceptBtn) {
    consentAcceptBtn.addEventListener("click", () => handleConsentChoice(true));
  }
  if (consentDeclineBtn) {
    consentDeclineBtn.addEventListener("click", () => handleConsentChoice(false));
  }
}

module.exports = {
  initializeInstallScreen,
};
