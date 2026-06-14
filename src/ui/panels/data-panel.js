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
    setIndex,
    setActivePacketCursor,
    setCurrentIp,
    setCurrentPacketKey,
    getCurrentPacketKey,
    syncBookmarkDropdown,
    infoPanel,
    popHexGrid,
    populateDataTypes,
  } = options;
  const { MAIN_TAB_DATA } = constants;

  function logCurrentPacketDisplay(action) {
    const packetsForHost = getPacketsForHost();
    const index = getIndex();
    if (!packetsForHost || !packetsForHost[index]) return;
    const packetInfo = packetsForHost[index]["Packet Info"];
    const selectedHost = getHostFilterValue() || "Unknown host";
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "Unknown source";
    const destinationIp =
      packetInfo?.["IP"]?.["Destination IP"] || "Unknown destination";
    const packetIndex = packetInfo?.["Index"] ?? index;
    const packetTimestamp = packetInfo?.["Packet Timestamp"] || "Unknown time";
    writeLogEntry(
      `Displayed packet action=${action} host=${selectedHost} packet=${packetIndex} source=${sourceIp} destination=${destinationIp} timeframe=${packetTimestamp}`,
    );
  }

  function initializeDataView() {
    setActiveMainTab(MAIN_TAB_DATA);
    statusUpdate(`Status: Displaying packet information for ${getHostFilterValue()}`);
    if (getJsonCapture() == "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    documentRef.getElementById("prev-btn").style.display = "block";
    documentRef.getElementById("next-btn").style.display = "block";
    documentRef.getElementById("welcome").style.display = "none";
    if (documentRef.getElementById("host_filter").value == "") {
      documentRef.getElementById("host_filter").value = getHostsList()[1];
    }

    const hasActiveFilterQuery = getFilterInputValue().trim() !== "";
    const filteredPackets = getFilteredPackets();
    const packetsForHost = getPacketsForHost();
    const shouldReuseFilteredPackets =
      Array.isArray(filteredPackets) &&
      (hasActiveFilterQuery || packetsForHost === filteredPackets);
    handlePacketNavigation(shouldReuseFilteredPackets ? "filtered" : "first-load");
  }

  function showPreviousPacket() {
    statusUpdate("Status: Displaying capture analysis summary");
    if (!getIsFileLoaded()) {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    let index = Number.parseInt(getIndex(), 10);
    if (!Number.isInteger(index) || index < 0) index = 0;
    const packetsForHost = getPacketsForHost();
    if (!Array.isArray(packetsForHost) || packetsForHost.length === 0) {
      statusUpdate("Status: No packet information found for this host");
      doError("No packet information found for this host!");
      return;
    }
    if (index > 0) {
      index -= 1;
      setIndex(index);
      setActivePacketCursor(index);

      const packetInfo = packetsForHost[index]?.["Packet Info"];
      if (!packetInfo) {
        statusUpdate("Status: Packet data is unavailable for this entry");
        doError("Packet data is unavailable for this entry!");
        return;
      }
      const currentIp = packetInfo?.["IP"]?.["Source IP"] || "Unknown";
      const currentPacketKey =
        currentIp + ":" + (packetInfo?.["Index"] ?? index);
      setCurrentIp(currentIp);
      setCurrentPacketKey(currentPacketKey);
      syncBookmarkDropdown(currentPacketKey);
      infoPanel(packetsForHost);
      popHexGrid(
        packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"] || "",
      );
      populateDataTypes(packetsForHost);
      logCurrentPacketDisplay("prev");
    }
  }

  function showNextPacket() {
    statusUpdate("Status: Displaying capture analysis summary");
    if (!getIsFileLoaded()) {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("No file loaded! Upload one of JSON or PCAP first!");
      return;
    }
    let index = Number.parseInt(getIndex(), 10);
    if (!Number.isInteger(index) || index < 0) index = 0;
    const packetsForHost = getPacketsForHost();
    if (!Array.isArray(packetsForHost) || packetsForHost.length === 0) {
      statusUpdate("Status: No packet information found for this host");
      doError("No packet information found for this host!");
      return;
    }
    if (index < packetsForHost.length - 1) {
      index += 1;
      setIndex(index);
      setActivePacketCursor(index);
      const packetInfo = packetsForHost[index]?.["Packet Info"];
      if (!packetInfo) {
        statusUpdate("Status: Packet data is unavailable for this entry");
        doError("Packet data is unavailable for this entry!");
        return;
      }
      const currentIp = packetInfo?.["IP"]?.["Source IP"] || "Unknown";
      const currentPacketKey =
        currentIp + ":" + (packetInfo?.["Index"] ?? index);
      setCurrentIp(currentIp);
      setCurrentPacketKey(currentPacketKey);
    }
    syncBookmarkDropdown(getCurrentPacketKey());
    const activePacketInfo = packetsForHost[index]?.["Packet Info"];
    if (!activePacketInfo) {
      statusUpdate("Status: Packet data is unavailable for this entry");
      doError("Packet data is unavailable for this entry!");
      return;
    }
    infoPanel(packetsForHost);
    popHexGrid(
      activePacketInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"] || "",
    );
    populateDataTypes(packetsForHost);
    logCurrentPacketDisplay("next");
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
