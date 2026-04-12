const { filterPackets } = require("./filter");
// Global variables for DOM elements and state
let packets = {}; // Stores parsed packet data from JSON
let json_cap = ""; // Stringified JSON capture for pretty display
let final_summary = ""; // Stores the summary section from JSON
const status = document.getElementById("status"); // Status bar element
let hosts = ["0.0.0.0"]; // List of hosts found in capture
let host_filter = document.getElementById("host_filter"); // Host filter dropdown
let packetsForHost = []; // Packets for the currently selected host
let index = 0; // Navigation index for packets
let bookmarkList = []; // List of bookmarks (host:packet index)
let bookmark = {}; // Current bookmark object
let filteredPackets;
let curPacket;
let startTime;
popHexGrid("00".repeat(256));
// Set up file upload handler for JSON capture
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      startTime = performance.now();
      statusUpdate("Processing file: " + file.name);
      processFile(file);
    }
  });

document
  .getElementById("pcap-filename")
  .addEventListener("click", function (event) {
    window.getfileapi.selectFile().then((filePath) => {
      if (filePath) {
        window.fsize
          .getFSize()
          .then((fileSize) => {
            // Update the UI with the file size
            const fSizeInKB = (fileSize / 1024).toFixed(2);
            document.getElementById("pcap-size").textContent =
              `PCAP size: ${fSizeInKB}kb`;
          })
          .catch((error) => {
            // Handle any errors (e.g., file not found)
            console.error("Error fetching file size:", error);
          });

        runSnitch(filePath);
      }
    });
  });

function isValidJSON(str) {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
}

function fileLoaded(loaded) {
  if (loaded) {
    const retTime = performance.now();
    document.getElementById("load-time").textContent =
      "Load time: " + ((retTime - startTime) / 1000).toFixed(2) + " seconds";
    document.getElementById("filterStr").disabled = false;
    document.getElementById("tab-btns").style.opacity = "1";
    document.getElementById("prev-btn").style.opacity = "1";
    document.getElementById("next-btn").style.opacity = "1";
    document.getElementById("json-lab").style.display = "none";
    document.getElementById("pcap-lab").style.display = "none";
  } else {
    document.getElementById("json-lab").style.display = "block";
    document.getElementById("pcap-lab").style.display = "block";
  }
}

/**
 * Reads and parses the JSON file, updates UI and state.
 */
function processFile(file) {
  const reader = new FileReader();
  reader.onload = (event) => {
    if (isValidJSON(event.target.result) == false) {
      console.log("Invalid JSON file");
      doError("Invalid JSON file, please upload a valid JSON capture!");
      fileLoaded(false);
      return;
    }
    fileLoaded(true);
    document.getElementById("error-container").style.display = "none";
    packets = JSON.parse(event.target.result);
    json_cap = JSON.stringify(packets, null, 2);
    final_summary = packets["Final Summary"];
    if (final_summary == undefined) {
      doError("Final Summary not found in JSON!");
      statusUpdate("Status: Error: Final Summary not found in JSON.");
      return;
    }
    document.getElementById("target_hosts").hidden = false;
    document.getElementById("summary-btn").style.display = "block";
    // Populate host dropdown with hosts from JSON
    for (const host in packets["Host"]) {
      if (!hosts.includes(host)) {
        hosts.push(host);
        const targets_list = document.getElementById("target_hosts");
        const newhost = document.createElement("option");
        newhost.textContent = host;
        newhost.value = host;
        targets_list.appendChild(newhost);

        writeSummary();
        initializeDataView();
      }
    }
  };
  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
    doError("Error reading file!");
  };
  reader.readAsText(file);
}

/**
 * Updates the status bar with a message, then resets after 6 seconds.
 */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "Status: Ready";
  }, 6000);
}

// Update host filter when a new host is selected from dropdown
document.getElementById("target_hosts").addEventListener("change", function () {
  const selected = document.getElementById("target_hosts").value;
  if (host_filter.value !== selected) {
    host_filter.value = selected;
  }
});

document.getElementById("target_hosts").addEventListener("click", function () {
  handlePacketNavigation("first-load");
});

// Show summary when summary button is clicked
document.getElementById("summary-btn").addEventListener("click", function () {
  writeSummary();
});

// Displays the summary section from the loaded JSON.

function writeSummary() {
  statusUpdate("Status: Displaying capture analysis summary");
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_content").textContent = final_summary;
    document.getElementById("summary_box").style.display = "block";
    fileLoaded(true);
  }
}

// Show host data when data button is clicked
document.getElementById("data-btn").addEventListener("click", function () {
  initializeDataView();
});

function initializeDataView() {
  statusUpdate(
    "Status: Displaying packet information for " + host_filter.value,
  );
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    doError("No file loaded! Upload one of JSON or PCAP first!");
  } else {
    document.getElementById("prev-btn").style.display = "block";
    document.getElementById("next-btn").style.display = "block";
    document.getElementById("welcome").style.display = "none";
    if (document.getElementById("host_filter").value == "") {
      document.getElementById("host_filter").value = hosts[1];
    }

    handlePacketNavigation("first-load");
  }
}

// Navigation for previous packet
document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  if (index > 1) {
    index--;

    const sourceIP = packetsForHost[index]["Packet Info"]["IP"]["Source IP"];
    curPacket = sourceIP + ":" + packetsForHost[index]["Packet Info"]["Index"];
    infoPanel(packetsForHost);
    popHexGrid(
      packetsForHost[index]["Packet Info"]["Raw data"]["Payload"][
        "Hex Encoded"
      ],
    );
    populateDataTypes(packetsForHost);
  }
});

// Navigation for next packet
document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  if (index < packetsForHost.length - 1) {
    index++;
    const sourceIP = packetsForHost[index]["Packet Info"]["IP"]["Source IP"];
    curPacket = sourceIP + ":" + packetsForHost[index]["Packet Info"]["Index"];
  }
  infoPanel(packetsForHost);
  popHexGrid(
    packetsForHost[index]["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"],
  );
  populateDataTypes(packetsForHost);
});

// Handle bookmark selection from dropdown
document
  .getElementById("selectBookmark")
  .addEventListener("click", function () {
    const bookmarkParts = document.getElementById("selectBookmark").value.split(":");
    const host = bookmarkParts[0];
    index = bookmarkParts[1];
    packetsForHost = packets["Host"][host];
    bookmark["Host"] = host;
    bookmark["Packet"] = index;
    host_filter.value = host;
    if (host == undefined || index == undefined) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
    } else {
      document.getElementById("target_hosts").value = host;
    }
    handlePacketNavigation("bookmark", bookmark);
  });

// Add current packet as a bookmark
document.getElementById("setBookmark").addEventListener("click", function () {
  if (!bookmarkList.includes(curPacket)) {
    if (curPacket != undefined) {
      bookmarkList.push(curPacket);
      document
        .getElementById("selectBookmark")
        .appendChild(new Option(curPacket, curPacket));
    }
  }
});

// returns the total number of packets in the entire capture
function totalPacketCount() {
  let totalPackets = 0;
  if (packets["Host"] != undefined) {
    for (const host in packets["Host"]) {
      totalPackets += packets["Host"][host].length;
    }
  } else {
    return 0;
  }
  return totalPackets;
}

/**
 * Handles navigation between packets (next, prev, bookmark, first-load).
 * Updates UI and packet info accordingly.
 */
function handlePacketNavigation(btn, bookmark) {
  document.getElementById("loading-container").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("welcome").style.display = "none";
  showAllData();

  document.getElementById("total-packets").innerHTML =
    "Total Packets: " + totalPacketCount();
  index = 1;
  if (btn === undefined) {
    handlePacketNavigation("first-load");
  }
  let currentPackets = packets["Host"][host_filter.value];
  if (btn === "filtered") {
    document.getElementById("filter-returned").textContent =
      "Filtered Packets: " + filteredPackets.length;
    currentPackets = filteredPackets;
  }

  if (btn === "bookmark") {
    if (bookmark["Host"] == undefined || bookmark["Packet"] == undefined) {
      statusUpdate("Status: Invalid bookmark data, reverting to first packet");
      doError("Invalid bookmark data, missing host or packet index!");
      handlePacketNavigation("first-load");
    } else {
      index = bookmark["Packet"] - 1;

      statusUpdate(
        "Navigating to bookmark: " +
          bookmark["Host"] +
          " packet " +
          bookmark["Packet"],
      );
    }
  }
  if (!currentPackets || currentPackets.length === 0) {
    statusUpdate("Status: No packets");
    return;
  }
  if (currentPackets != undefined && (currentPackets.length == 0 || currentPackets[0] == undefined)) {
    statusUpdate("Status: No packet information found for this host");
    document.getElementById("main").innerHTML = "Please select a json file!";
  }
  if (currentPackets == undefined || currentPackets[index] == undefined) {
    statusUpdate("Status: No packet information found for this host");
    doError("No packet information found for this host!");
    return;
  } else {
    const sourceIP = currentPackets[index]["Packet Info"]["IP"]["Source IP"];
    curPacket = sourceIP + ":" + currentPackets[index]["Packet Info"]["Index"];
    console.log(currentPackets[index]);
    const hexPayload = currentPackets[index]["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"];
    infoPanel(currentPackets);
    popHexGrid(hexPayload);
    populateDataTypes(currentPackets);
  }
}

function populateDataTypes(packetList) {
  const dataTypesList = document.getElementById("types-list");
  dataTypesList.textContent = "";
  const mimeTypeEl = document.getElementById("mime-type");
  const encodingEl = document.getElementById("encoding");
  const languageEl = document.getElementById("language");
  encodingEl.textContent = "";
  languageEl.textContent = "";
  let encoding = "";
  let lang = "";
  packetsForHost = packetList;
  const packetExtraInfo = packetsForHost[index]["Extra Info"];
  const packetTraits = packetExtraInfo["Traits"];
  const charTraits = packetTraits["Characters"];
  if (
    charTraits["Encoding]"] ==
    "Unavailble for high entropy data"
  ) {
    encoding = JSON.parse(JSON.stringify(charTraits["Encoding"]));
  } else {
    encoding = JSON.stringify(charTraits["Encoding"]["encoding"]);
    lang = JSON.stringify(charTraits["Encoding"]["language"]);
  }

  const mimeType = JSON.parse(JSON.stringify(packetExtraInfo["MIME Type"]));
  let dataItems = JSON.parse(JSON.stringify(packetExtraInfo["Data Types"]));
  const encData = packetTraits["Server Info"]["Encryption Data"];
  if (encData != "N/A" && encData != undefined) {
    const sslVersion = encData["SSL Version"];
    const protocol = packetTraits["Network Data"]["Port Protcol"];
    dataItems = [];
    dataItems.push(sslVersion + " encrypted stream");
    dataItems.push(protocol + " protocol data");
  }

  mimeTypeEl.textContent = "\u03B1 MIME type: " + mimeType;
  encoding = encoding == "" ? "Unknown" : encoding;
  if (encoding !== undefined) {
    encodingEl.textContent =
      "\u0950 Payload Encoding: " + encoding.replace(/"/g, "");
  }
  if (lang !== undefined) {
    languageEl.textContent = "\u03C9 Payload Language: " + lang.replace(/"/g, "");
  }
  dataItems.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.textContent = item;
    dataTypesList.appendChild(listItem);
  });
}
// this takes a char code and returns true if it's
// a printable ascii character, false otherwise
function isPrintable(charCode) {
  // ASCII printable: 32 (space) to 126 (~)
  return charCode >= 32 && charCode <= 126;
}

// this changes hex to ascii
function hexToAscii(hex) {
  let ascii = "";
  for (let i = 0; i < hex.length; i += 2) {
    ascii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return ascii;
}

// trunactes a string to a max length
function truncate(str, maxLength) {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength);
}

// returns a 0 padded hex string of a number with a given length
function decToHex(num, pad) {
  return num.toString(16).padStart(pad, "0");
}

// clears the higlights (its called after the moouse leaves grid)
function clearGridHighlights() {
  document
    .querySelectorAll(".griditem")
    .forEach((el) => el.classList.remove("highlight"));
}

/**
 * Populates the hex grid display with the given hex string.
 */
function popHexGrid(hex) {
  const asciiBox = document.getElementById("payloadascii");
  // swap it back to ascii for the fade box
  const asciiStr = hexToAscii(hex);
  const hexGrid = document.getElementById("hexg");
  hexGrid.textContent = "";
  // this block populates the grid with boxes for hex codes
  for (const hexByte of hex.toUpperCase().match(/.{1,2}/g)) {
    const item = document.createElement("div");
    item.classList.add("griditem");
    item.textContent = hexByte;
    hexGrid.appendChild(item);
  }
  function getPrintableSequence(startIndex) {
    let result = "";
    for (let i = startIndex; i < asciiStr.length; i++) {
      if (!isPrintable(asciiStr.charCodeAt(i))) break;
      result += String.fromCharCode(asciiStr.charCodeAt(i));
    }
    return result;
  }
  // Attach event listeners to each grid item
  document.querySelectorAll(".griditem").forEach((item, idx) => {
    item.addEventListener("mouseenter", (e) => {
      //box fade in
      const offsetBox = document.getElementById("asciiOffset");
      const textBox = document.getElementById("asciiText");
      asciiBox.style.top = e.clientY + 18 + "px";
      asciiBox.style.left = e.clientX + 18 + "px";
      asciiBox.classList.add("visible");
      textBox.innerHTML = "";
      const printable = getPrintableSequence(idx);
      // adds only consecutive printable characters to the ascii box
      textBox.textContent += truncate(printable, 32);
      for (let i = 0; i < truncate(printable, 32).length; i++) {
        const highlightedHex = document.querySelectorAll(".griditem")[idx + i];
        highlightedHex.classList.add("highlight");
      }
      const hexLen = parseInt(truncate(printable, 32).length, 10)
        .toString(16)
        .padStart(2, "0")
        .toUpperCase();
      const hexOffset = idx.toString(16).padStart(4, "0").toUpperCase();
      if (printable.length == 0) {
        textBox.textContent = "0x" + item.textContent;
      }
      offsetBox.textContent = "0x" + hexOffset + ":" + hexLen;
    });
  });
  // this fades the box back out and calls the grid clear func
  document.querySelectorAll(".griditem").forEach((item) => {
    item.addEventListener("mouseleave", () => {
      asciiBox.classList.remove("visible");
      clearGridHighlights();
    });
  });
}

/**
 * Utility to create a table from data and headers, and append to a container.
 */
function createTable(data, headers, containerId) {
  const table = document.createElement("table");
  const headerRow = document.createElement("tr");
  headers.forEach((text) => {
    const th = document.createElement("th");
    th.textContent = text;
    headerRow.appendChild(th);
  });
  table.appendChild(headerRow);
  data.forEach((item) => {
    const row = document.createElement("tr");
    Object.values(item).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      row.appendChild(td);
    });
    table.appendChild(row);
  });

  document.getElementById(containerId).appendChild(table);
}

/**
 * Updates the info panel with details about the current packet.
 */

// probably should break this function up into smaller pieces,
// but it works for now, it takes the current packet info and
// populates the info panel with it, including the side tables
// and the main info table, also updates the timestamp and
// ip:port info at the top
function infoPanel(packetList) {
  const infoPane = document.getElementById("packetInfoPane");
  document.getElementById("rightside").style.display = "block";
  document.getElementById("leftside").style.display = "block";
  infoPane.style.display = "block";
  const currentPacket = packetList[index];
  const packetInfo = currentPacket["Packet Info"];
  const extraInfo = currentPacket["Extra Info"];
  const traits = extraInfo["Traits"];
  const networkData = traits["Network Data"];
  const serverInfo = traits["Server Info"];
  const timestamp = packetInfo["Packet Timestamp"];
  const ipChecksum = packetInfo["IP"]["IP Checksum"];
  const tcpChecksum = packetInfo["TCP"]["TCP checksum"];
  const sourceIPPort = packetInfo["IP"]["Source IP"] + ":" + packetInfo["TCP"]["Source port"];
  const destIPPort =
    packetInfo["IP"]["Destination IP"] + ":" + packetInfo["TCP"]["Destination port"];
  const sourceMac = packetInfo["Ethernet Frame"]["MAC Source"];
  const destMac = packetInfo["Ethernet Frame"]["MAC Destination"];
  const sourceMacVendor = packetInfo["Ethernet Frame"]["MAC Source Vendor"];
  const destMacVendor = packetInfo["Ethernet Frame"]["MAC Destination Vendor"];
  const flags = packetInfo["TCP"]["TCP Flag Data"]["Flags"];
  const ipLayerLength = packetInfo["IP"]["IP layer length"];
  const tcpLayerLength = packetInfo["TCP"]["TCP layer length"];
  const wireLength = packetInfo["TCP"]["Wire length"];
  const payloadLength = packetInfo["Raw data"]["Payload Length"];
  let sslCert = "";
  let sslVersion = "";
  let sslAlgorithms = "";
  const encryptionData = serverInfo["Encryption Data"];
  if (
    encryptionData == "N/A" ||
    serverInfo.hasOwnProperty("Encryption Data") == false
  ) {
    sslCert = "Not encrypted";
    sslVersion = "Not encrypted";
    sslAlgorithms = "";
  } else {
    sslCert = encryptionData["SSL Cert"] ?? "Not available";
    sslVersion = encryptionData["SSL Version"] ?? "Not available";
    sslAlgorithms =
      encryptionData["Encrypted With"].join("<br>Extra algo info: ") ??
      "No algorithm information available";
  }
  const decompressed = extraInfo["Decompressed"]["Decompressed"];
  function removeIPs(list) {
    const ipRegex =
      /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/;
    return list.filter((item) => !ipRegex.test(item));
  }

  let dnsHostnames;
  if (networkData["Hostnames"]["Hostnames"] == undefined) {
    dnsHostnames = "localhost";
  } else {
    dnsHostnames =
      "localhost<br>" +
      networkData["Hostnames"]["Hostnames"].join("<br>");
  }
  const filteredHostnames = removeIPs(dnsHostnames.split("<br>")).join("<br>");
  dnsHostnames = filteredHostnames == "" ? "localhost" : filteredHostnames;

  const pageTitle = serverInfo["Page Title"];
  const protocol = networkData["Port Protcol"];
  const protocolDescription = networkData["Port Description"];
  const srcNetworkClass = networkData["Source IP"]["Class"];
  const destNetworkClass = networkData["Destination IP"]["Class"];
  document.getElementById("sidedatatable").textContent = "";
  document.getElementById("protoInfoSrc").textContent = "Source";
  document.getElementById("protoInfoDest").textContent = "Destination";
  document.getElementById("comp").textContent = "Unknown";
  if (decompressed == false || decompressed == undefined) {
    const compressionTypes = extraInfo["Data Types"];

    compressionTypes.forEach((type) => {
      if (type.includes("Zlib") || type.includes("zlib")) {
        document.getElementById("comp").textContent = "Compressed with zlib";

        console.log("Data type identified: " + type);
      }
      if (type.includes("Gzip") || type.includes("gzip")) {
        document.getElementById("comp").textContent = "Compressed with gzip";
      }
      if (type.includes("Zip")) {
        document.getElementById("comp").textContent = "Compressed with zip";
      }
    });
  }
  if (pageTitle == undefined || pageTitle == "N/A") {
    document.getElementById("website").textContent =
      "Not available for this server";
  } else {
    document.getElementById("website").textContent = pageTitle;
  }
  const dnsCollapsedList = dnsHostnames.replace(/(<br\s*\/?>\s*)+/gi, "<br>");
  document.getElementById("dns").innerHTML = dnsCollapsedList;
  if (sslAlgorithms == undefined || sslAlgorithms == "") {
    document.getElementById("crypt").innerHTML = "Not encrypted";
  } else {
    document.getElementById("crypt").innerHTML =
      "Encrypted with: " + sslVersion + "<br>" + sslAlgorithms;
  }

  if (protocol == "Unknown") {
    document.getElementById("protocols").innerHTML = "Unknown";
  } else {
    document.getElementById("protocols").innerHTML =
      "Protocol Name: " + protocol + "<br>Protocol Description: " + protocolDescription;
  }
  const checksumTableData = [
    { name: "IP Checksum \u060F", value: ipChecksum },
    { name: "TCP Checksum \u2643", value: tcpChecksum },
    { name: "Flags \u0D79", value: flags },
    { name: "IP Length \u2366", value: ipLayerLength },
    { name: "TCP Length \u263F", value: tcpLayerLength },
    { name: "Wire Length \u2123", value: wireLength },
    { name: "Payload Length \u0905", value: payloadLength },
  ];
  const checksumTableHeaders = ["Protocol data", "Details"];
  createTable(checksumTableData, checksumTableHeaders, "sidedatatable");
  const hostTableHeaders = ["Packet", "Data"];
  const srcHostData = [
    { name: "IP:Port \u25ce", value: sourceIPPort },
    { name: "MAC \u03C3", value: sourceMac },
    { name: "MAC Vendor \u03b3", value: sourceMacVendor },
    { name: "Network Class \u097E", value: srcNetworkClass },
  ];
  createTable(srcHostData, hostTableHeaders, "protoInfoSrc");
  const destHostData = [
    { name: "IP:Port \u25ce", value: destIPPort },
    { name: "MAC \u03C3", value: destMac },
    { name: "MAC Vendor \u03B3", value: destMacVendor },
    { name: "Network Class \u097E", value: destNetworkClass },
  ];
  createTable(destHostData, hostTableHeaders, "protoInfoDest");
  const entropy = traits["Shannon Entropy"];
  document.getElementById("timestamp").textContent = "Timestamp \u221E " + timestamp;
  document.getElementById("sideloctable").textContent = "";
  document.getElementById("entropybox").textContent =
    "\u096F " + entropy.toFixed(2);
  const entropyBox = document.getElementById("entropybox");
  if (entropy >= 6.8) {
    entropyBox.className = "high";
  } else if (entropy >= 4.5) {
    entropyBox.className = "med";
  } else {
    entropyBox.className = "low";
  }
  const secondColumnCells = document.querySelectorAll(
    "table tr td:nth-child(1), table tr th:nth-child(1)",
  );
  secondColumnCells.forEach((cell) => {
    cell.style.width = "23%";
  });
  const srcLocation = networkData["Source IP"]["Location"];
  if (srcLocation["City"] == undefined) {
    const nodata = [{ name: "Location \u2205", value: "Localnet" }];
    const nodatah = ["Source Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const srcLocationData = [
      { name: "Country \u096D", value: srcLocation["Country"] },
      { name: "City \u2211", value: srcLocation["City"] },
      { name: "Timezone \u221E", value: srcLocation["Time Zone"] },
    ];
    const srcLocationHeaders = ["Source Host", "Location"];
    createTable(srcLocationData, srcLocationHeaders, "sideloctable");
  }
  const destLocation = networkData["Destination IP"]["Location"];
  if (destLocation["City"] == undefined) {
    const nodata = [{ name: "Location \u2205", value: "Localnet" }];
    const nodatah = ["Destination Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const destLocationData = [
      { name: "Country \u096D", value: destLocation["Country"] },
      { name: "City \u2211", value: destLocation["City"] },
      { name: "Timezone \u221E", value: destLocation["Time Zone"] },
    ];
    const destLocationHeaders = ["Destination Host", "Location"];
    createTable(destLocationData, destLocationHeaders, "sideloctable");
  }
}

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns our json data from snitch.py
window.jsonapi.onJsonData((jsonData) => {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("error-container").style.display = "none";
  statusUpdate("Loaded data from backend, processing...");
  processFile(
    new File([jsonData], "capture.json", { type: "application/json" }),
  );
  document.getElementById("loading-container").style.display = "none";
  const retTime = performance.now();
  document.getElementById("load-time").textContent =
    "Load time: " + ((retTime - startTime) / 1000).toFixed(2) + " seconds";
});

// here we create the backend process and hook it to the handler
function runSnitch(file) {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("summary_content").innerHTML =
    '<span id="loaderdots" class="loading">Loading</span>';
  document.getElementById("status").textContent =
    "Status: Running snitch backend, this may take a few minutes...";
  document.getElementById("error-container").style.display = "none";
  startTime = performance.now();
  window.snitchapi.runBackendCommand(file);
}

function doError(message) {
  console.error("Error from backend:", message);
  const loadContainer = document.getElementById("loading-container");
  const errorContainer = document.getElementById("error-container");
  document.getElementById("summary_content").textContent = "";
  loadContainer.style.display = "none";
  errorContainer.style.display = "block";
  errorContainer.textContent = message;
  errorContainer.addEventListener("click", () => {
    errorContainer.style.display = "none";
    loadContainer.style.display = "none";
  });
}

function hideAllData() {
  //  document.getElementById("packetInfoPane").textContent =
  //    "No matching packets found.";
  doError("No packets match the filter criteria!");
  statusUpdate("Status: No packets match the filter criteria");
  document.getElementById("data-types").style.display = "none";
  document.getElementById("protoInfo").style.display = "none";
  document.getElementById("timestamp").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("active-recon").style.display = "none";
  document.getElementById("prev-btn").style.opacity = "0";
  document.getElementById("next-btn").style.opacity = "0";
  popHexGrid("00".repeat(256));
}
function showAllData() {
  document.getElementById("prev-btn").style.opacity = "1";
  document.getElementById("next-btn").style.opacity = "1";
  document.getElementById("data-types").style.display = "block";
  document.getElementById("protoInfo").style.display = "block";
  document.getElementById("timestamp").style.display = "block";
  document.getElementById("rightside").style.display = "block";
  document.getElementById("active-recon").style.display = "block";
  document.getElementById("hexg").hidden = false;
}

document
  .getElementById("filterStr")
  .addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      const filterBy = document.getElementById("filterStr").value;
      filteredPackets = filterPackets(packets, filterBy);

      if (filteredPackets == undefined || filteredPackets.length == 0) {
        hideAllData();
        statusUpdate("Status: No packets match the filter criteria");
      } else {
        statusUpdate(
          "Status: Displaying " +
            filteredPackets.length +
            " packets matching filter",
        );
        handlePacketNavigation("filtered", null);
      }
    }
  });

window.onerror = (message, source, lineno, colno, error) => {
  doError(message + " at " + source + ":" + lineno + ":" + colno);
};

window.onunhandledrejection = (event) => {
  doError("Unhandled promise error! " + event.reason);
};

window.api.onError((msg) => {
  console.error("Error from backend:", msg);
  // Show alert or UI message
  doError(msg);
});

// On page load, hide packet info and payload panes
onload = function () {
  // document.getElementById("selectBookmark").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("leftside").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
};
