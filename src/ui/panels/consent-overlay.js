// First-run metrics consent overlay helpers.
//
// Extracted from ``src/ui/panels/install-screen.js`` after the install
// screen itself was retired in favour of the native install summary
// dialog (see the ``process.exit`` / PowerShell MessageBox path).
// The consent overlay is the only fragment of that file that remains
// useful in the renderer: it gates the first opt-in prompt for
// anonymous diagnostic data on a clean ``~/.config`` directory and
// is hidden once the user makes a decision.
//
// The install screen (``#install-screen``) used to call
// ``maybeShowConsentOverlay`` after the user dismissed it, which is
// why the two lived in the same file. They no longer share any state,
// so the consent overlay now lives on its own and the install screen
// has been removed entirely from the renderer.

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

// True only when the metrics module has been seeded with a settings
// snapshot. Until the renderer has finished its initial
// ``loadPersistedSettings()`` call this is false and we must NOT
// prompt the user: the persisted ``privacy.metricsConsentAsked`` flag
// has not been read yet and the overlay would re-appear on every
// launch even after the user answered.
function isMetricsSnapshotReady(metrics) {
    return Boolean(
        metrics && typeof metrics.hasSettingsSnapshot === "function"
            ? metrics.hasSettingsSnapshot()
            : (metrics && metrics.settingsSnapshot && typeof metrics.settingsSnapshot === "object"),
    );
}

// Shows the consent overlay if the user has not been asked yet and we
// are not in a test environment. Safe to call multiple times. The
// overlay is only un-hidden when the metrics snapshot has been pushed,
// so we never prompt a user who has already answered the question on a
// previous run (the persisted ``metricsConsentAsked`` flag is the
// canonical signal).
function maybeShowConsentOverlay({ documentRef, metrics }) {
    if (!documentRef) return false;
    const overlay = documentRef.getElementById("metrics-consent-overlay");
    if (!overlay) return false;
    if (isConsentOverlayVisible(documentRef)) return true;
    if (!metrics || typeof metrics.getConsentStatus !== "function") {
        return false;
    }
    if (!isMetricsSnapshotReady(metrics)) {
        // The renderer's persisted settings haven't been pushed into the
        // metrics module yet. Re-evaluate as soon as they arrive so we do
        // not pester users who already answered the question.
        if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
            const retry = () => {
                try {
                    maybeShowConsentOverlay({ documentRef, metrics });
                } catch (_error) {
                    // ignore: best-effort retry
                }
            };
            window.addEventListener(
                "packetsnitch:settings-updated",
                () => {
                    window.removeEventListener("packetsnitch:settings-updated", retry);
                    retry();
                },
                { once: true },
            );
        }
        return false;
    }
    if (metrics.getConsentStatus() !== "first-run") {
        return false;
    }
    overlay.hidden = false;
    return true;
}

// Wires the consent overlay's accept/decline buttons and surfaces
// the first-run prompt. Safe to call multiple times — the button
// listeners are idempotent and the overlay state is checked before
// every show.
//
// ``installapi`` is accepted for source compatibility with the old
// ``initializeInstallScreen`` signature but ignored: with the native
// install summary dialog in place there is no longer a "first run
// after install" concept in the renderer — the renderer is the same
// code path on every launch and the consent overlay is gated only
// on the persisted ``metricsConsentAsked`` flag.
function initializeConsentOverlay({ installapi, documentRef, metrics }) {
    void installapi;
    const consentAcceptBtn = documentRef.getElementById("metrics-consent-accept");
    const consentDeclineBtn = documentRef.getElementById("metrics-consent-decline");
    const handleConsentChoice = (enabled) => {
        if (metrics && typeof metrics.recordConsent === "function") {
            try {
                metrics.recordConsent(Boolean(enabled));
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
    maybeShowConsentOverlay({ documentRef, metrics });
}

module.exports = {
    initializeConsentOverlay,
    maybeShowConsentOverlay,
    isConsentOverlayVisible,
    hideConsentOverlay,
    isMetricsSnapshotReady,
};