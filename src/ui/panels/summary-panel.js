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

  return {
    showSummary,
    showSummaryLoading,
    clearSummaryContent,
  };
}

module.exports = { createSummaryPanel };
