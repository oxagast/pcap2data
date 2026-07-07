
const threadName = "Data";

function createDataPanel(options) {
  const {
    constants,
    documentRef,
    statusUpdate,
    writeLogEntry,
    doError,
    getIsFileLoaded,
    getJsonCapture,
    getHostFilterValue,
    getHostsList,
    getFilterInputValue,
    getFilteredPackets,
    getPacketsForHost,
    setActiveMainTab,
    handlePacketNavigation,
    getIndex,
  } = options;
  const { MAIN_TAB_DATA } = constants;

  function logCurrentPacketDisplay(action) {
    const packetsForHost = getPacketsForHost();
    const index = getIndex();
    if (!packetsForHost || !packetsForHost[index]) return;
    // Packet navigation is frequent during incremental updates; avoid flooding activity log.
    void action;
  }

  function initializeDataView() {
    setActiveMainTab(MAIN_TAB_DATA);
    statusUpdate(`Status: Displaying packet information for ${getHostFilterValue()}`);
    if (getJsonCapture() == "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      writeLogEntry(`[${threadName}] No file loaded when attempting to display data view`);
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    documentRef.getElementById("prev-btn").style.display = "block";
    documentRef.getElementById("next-btn").style.display = "block";
    documentRef.getElementById("welcome").style.display = "none";
    if (documentRef.getElementById("host_filter").value == "") {
      documentRef.getElementById("host_filter").value = getHostsList()[0];
    }

    const hasActiveFilterQuery = getFilterInputValue().trim() !== "";
    const filteredPackets = getFilteredPackets();
    const packetsForHost = getPacketsForHost();
    const shouldReuseFilteredPackets =
      Array.isArray(filteredPackets) &&
      (hasActiveFilterQuery || packetsForHost === filteredPackets);
    void handlePacketNavigation(
      shouldReuseFilteredPackets ? "filtered" : "first-load",
    );
  }

  function showPreviousPacket() {
    statusUpdate("Status: Displaying capture analysis summary");
    if (!getIsFileLoaded()) {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      writeLogEntry(`[${threadName}] No file loaded when attempting to display previous packet`);
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    const packetsForHost = getPacketsForHost();
    if (!Array.isArray(packetsForHost) || packetsForHost.length === 0) {
      statusUpdate("Status: No packet information found for this host");
      writeLogEntry(`[${threadName}] No packet information found for this host when attempting to display previous packet`);
      doError("No packet information found for this host!");
      return;
    }
    void handlePacketNavigation("prev");
  }

  function showNextPacket() {
    statusUpdate("Status: Displaying capture analysis summary");
    if (!getIsFileLoaded()) {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    const packetsForHost = getPacketsForHost();
    if (!Array.isArray(packetsForHost) || packetsForHost.length === 0) {
      statusUpdate("Status: No packet information found for this host");
      doError("No packet information found for this host!");
      return;
    }
    void handlePacketNavigation("next");
  }

  function bindDataPanelEvents() {
    documentRef.getElementById("data-btn").addEventListener("click", () => {
      if (!getIsFileLoaded()) {
        doError("Please upload a JSON file before accessing host data.");
        return;
      }
      initializeDataView();
    });

    documentRef
      .getElementById("prev-btn")
      .addEventListener("click", showPreviousPacket);
    documentRef.getElementById("next-btn").addEventListener("click", showNextPacket);
  }

  return {
    initializeDataView,
    bindDataPanelEvents,
    logCurrentPacketDisplay,
  };
}

module.exports = {
  createDataPanel,
};
