// Controls the Summary workspace UI and capture overview rendering.

const SUMMARY_LOADING_MARKUP =
  '<span id="loaderdots" class="loading" role="status" aria-live="polite">Loading</span>';

// Creates summary panel.
function createSummaryPanel({
  documentRef,
  getJsonCapture,
  setActiveMainTab,
  mainTabSummary,
  statusUpdate,
  fileLoaded,
}) {
  function showSummary() {
    setActiveMainTab(mainTabSummary);
    statusUpdate("Status: Displaying capture analysis summary");
    const jsonCapture = getJsonCapture();
    if (jsonCapture === "" || jsonCapture === null || jsonCapture === undefined) {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      return;
    }

    documentRef.getElementById("packetInfoPane").style.display = "none";
    documentRef.getElementById("packetPayloadPane").style.display = "none";
    documentRef.getElementById("prev-btn").style.display = "none";
    documentRef.getElementById("next-btn").style.display = "none";
    documentRef.getElementById("stats_box").style.display = "none";
    documentRef.getElementById("data_tools_box").style.display = "none";
    documentRef.getElementById("crypt_box").style.display = "none";
    documentRef.getElementById("keystore_box").style.display = "none";
    documentRef.getElementById("settings_box").style.display = "none";
    documentRef.getElementById("list_box").style.display = "none";
    documentRef.getElementById("notes_box").style.display = "none";
    documentRef.getElementById("rightside").style.display = "none";
    documentRef.getElementById("summary_box").style.display = "block";
    fileLoaded(true);
  }

  function showSummaryLoading() {
    const summaryContentEl = documentRef.getElementById("summary_content");
    if (!summaryContentEl) return;
    summaryContentEl.innerHTML = SUMMARY_LOADING_MARKUP;
  }

  function clearSummaryContent() {
    const summaryContentEl = documentRef.getElementById("summary_content");
    if (!summaryContentEl) return;
    summaryContentEl.textContent = "";
  }

  const summaryBtnEl = documentRef.getElementById("summary-btn");
  if (summaryBtnEl) {
    summaryBtnEl.addEventListener("click", showSummary);
  }

  // The "Save as HTML" and "Save as PDF" header buttons let the analyst
  // export the Summary report without going through the right-click
  // context menu. They piggy-back on the existing context-menu save
  // pipeline (markdown / text / html share the same path; PDF has its
  // own IPC).
  //
  // The dispatcher lives in main-frontend.js. Webpack wraps every
  // module in a closure, so a bare `function saveSummaryFromHeaderButton`
  // declaration there is invisible to this module's click-handler
  // closures (the `typeof saveSummaryFromHeaderButton === "function"`
  // guard silently returned false and the click no-op'd). main-frontend
  // publishes the dispatcher on globalThis.__PACKETSNITCH_SUMMARY_EXPORT__,
  // so we read it from there at click-time instead. We re-resolve on
  // each click because main-frontend finishes evaluating after this
  // panel's listeners are wired (see src/front.js's import order).
  const summarySaveHtmlBtnEl = documentRef.getElementById("summary-save-html-btn");
  if (summarySaveHtmlBtnEl) {
    summarySaveHtmlBtnEl.addEventListener("click", () => {
      const exportBridge =
        typeof globalThis !== "undefined" &&
          globalThis.__PACKETSNITCH_SUMMARY_EXPORT__
          ? globalThis.__PACKETSNITCH_SUMMARY_EXPORT__
          : typeof window !== "undefined" && window.__PACKETSNITCH_SUMMARY_EXPORT__
            ? window.__PACKETSNITCH_SUMMARY_EXPORT__
            : null;
      const dispatcher =
        exportBridge && typeof exportBridge.saveSummaryFromHeaderButton === "function"
          ? exportBridge.saveSummaryFromHeaderButton
          : null;
      if (dispatcher) {
        void dispatcher("html");
      }
    });
  }
  const summarySavePdfBtnEl = documentRef.getElementById("summary-save-pdf-btn");
  if (summarySavePdfBtnEl) {
    summarySavePdfBtnEl.addEventListener("click", () => {
      const exportBridge =
        typeof globalThis !== "undefined" &&
          globalThis.__PACKETSNITCH_SUMMARY_EXPORT__
          ? globalThis.__PACKETSNITCH_SUMMARY_EXPORT__
          : typeof window !== "undefined" && window.__PACKETSNITCH_SUMMARY_EXPORT__
            ? window.__PACKETSNITCH_SUMMARY_EXPORT__
            : null;
      const dispatcher =
        exportBridge && typeof exportBridge.saveSummaryFromHeaderButton === "function"
          ? exportBridge.saveSummaryFromHeaderButton
          : null;
      if (dispatcher) {
        void dispatcher("pdf");
      }
    });
  }

  return {
    showSummary,
    showSummaryLoading,
    clearSummaryContent,
  };
}

module.exports = { createSummaryPanel };
