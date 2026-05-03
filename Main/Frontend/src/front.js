import './assets/css/style.css';
const { filterPackets } = require('./filter');
const {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderSnmpTable,
  renderDhcpTable,
  renderNtpTable,
  renderSipTable,
  renderHttpTable,
  renderFtpTable,
  renderSmtpTable,
  renderPop3Table,
  renderImapTable,
  renderTelnetTable,
  renderIrcTable,
  renderMtpTable,
  renderLdapTable,
  renderMysqlTable,
  renderPostgresqlTable,
  renderXmppTable,
  renderSmbTable,
  renderMqttTable,
  renderRtspTable,
  renderTftpTable,
  renderBgpTable,
  renderHttp2Table,
  renderNntpTable,
  renderRadiusTable,
} = require('./decoders');
const psVer = require('../package.json').version;

// Cache frequently accessed DOM elements to avoid repeated lookups
const domCache = {};
function getCachedElement(id) {
  if (!domCache[id]) {
    domCache[id] = document.getElementById(id);
  }
  return domCache[id];
}

// Global variables for DOM elements and state
getCachedElement('close-btn').addEventListener('click', () => {
  window.quitapi.quitApp();
});
let capturedPackets = {}; // Stores parsed packet data from JSON
let jsonCapture = ''; // Stringified JSON capture for pretty display
let currentIp;
let finalSummary = ''; // Stores the summary section from JSON
const status = getCachedElement('status'); // Status bar element
let hostsList = ['0.0.0.0']; // List of hosts found in capture
const hostFilterEl = getCachedElement('host_filter'); // Host filter dropdown
let packetsForHost = []; // Packets for the currently selected host
let index = 0; // Navigation index for packets
let bookmarkList = []; // List of bookmarks (host:packet index)
let activeBookmark = {}; // Current bookmark object
let isFileLoaded = false;
let jsonOfPackets;
let filteredPackets;
let currentPacketKey;
let startTime;

// Check for first run after new version install and show install screen if needed
if (window.installapi) {
  window.installapi.checkFirstRun().then((installInfo) => {
    if (installInfo && installInfo.isFirstRun) {
      showInstallScreen(installInfo);
    }
  });
}

function showInstallScreen(installInfo) {
  const screen = document.getElementById('install-screen');
  if (!screen) return;

  document.getElementById('install-version').textContent =
    'Version ' + installInfo.version;

  const fileList = document.getElementById('install-file-list');
  fileList.innerHTML = '';
  installInfo.installedFiles.forEach((file) => {
    const item = document.createElement('li');
    item.className = file.exists ? 'install-file-ok' : 'install-file-missing';
    item.textContent = (file.exists ? '\u2713 ' : '\u2717 ') + file.name;
    if (!file.exists) {
      item.title = 'Not found at: ' + file.path;
    }
    fileList.appendChild(item);
  });

  const ollamaStatus = document.getElementById('install-ollama-status');
  if (!installInfo.ollamaInstalled) {
    ollamaStatus.textContent =
      '\u26a0 Ollama is not installed. LLM packet summarisation will be unavailable. Install Ollama from https://ollama.com to enable this feature.';
    ollamaStatus.className = 'install-warning';
  } else {
    ollamaStatus.textContent =
      '\u2713 Ollama is installed. LLM summarisation is available.';
    ollamaStatus.className = 'install-ok';
  }

  screen.style.display = 'flex';
}

const installContinueBtn = document.getElementById('install-continue-btn');
if (installContinueBtn) {
  installContinueBtn.addEventListener('click', () => {
    if (window.installapi) {
      window.installapi.dismissFirstRun().then(() => {
        document.getElementById('install-screen').style.display = 'none';
      });
    } else {
      document.getElementById('install-screen').style.display = 'none';
    }
  });
}

popHexGrid('00'.repeat(256));
// Set up file upload handler for JSON capture
document
  .getElementById('json-upload')
  .addEventListener('change', function (event) {
    const file = event.target.files[0];
    if (file) {
      startTime = performance.now();
      statusUpdate('Processing file: ' + file.name);
      processFile(file);
      isFileLoaded = true;
      event.target.value = ''; // Reset so the same file can be loaded again
    }
  });

document
  .getElementById('pcap-filename')
  .addEventListener('click', function (event) {
    window.getfileapi.selectFile().then((filePath) => {
      if (filePath) {
        window.fsize
          .getFSize()
          .then((fileSize) => {
            // Update the UI with the file size
            const fileSizeKb = (fileSize / 1024).toFixed(2);
            document.getElementById('pcap-size').textContent =
              `PCAP size: ${fileSizeKb}kb`;
          })
          .catch((error) => {
            // Handle any errors (e.g., file not found)
            console.error('Error fetching file size:', error);
          });

        runSnitch(filePath);
      }
    });
  });

function isValidJson(str) {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
}

// Chunked JSON parsing for large files to avoid blocking the UI
function parseJsonChunked(jsonString, chunkSize = 65536) {
  return new Promise((resolve, reject) => {
    try {
      // For smaller files, parse directly
      if (jsonString.length < chunkSize * 2) {
        resolve(JSON.parse(jsonString));
        return;
      }

      // For large files, use setTimeout to yield to the main thread
      let position = 0;
      const length = jsonString.length;
      let result = '';
      const stack = [];
      let inString = false;
      let escape = false;

      function processChunk() {
        const end = Math.min(position + chunkSize, length);

        for (; position < end; position++) {
          const char = jsonString[position];
          if (escape) {
            escape = false;
          } else if (char === '\\') {
            escape = true;
          } else if (char === '"') {
            inString = !inString;
          } else if (!inString) {
            if (char === '{' || char === '[') {
              stack.push(char);
            } else if (char === '}' || char === ']') {
              stack.pop();
            }
          }
          result += char;
        }

        if (position < length) {
          // Yield to main thread and continue
          setTimeout(processChunk, 0);
        } else {
          resolve(JSON.parse(result));
        }
      }

      setTimeout(processChunk, 0);
    } catch (e) {
      reject(e);
    }
  });
}

function fileLoaded(isLoaded) {
  if (isLoaded) {
    const loadEndTime = performance.now();
    document.getElementById('load-time').textContent =
      'Load time: ' +
      ((loadEndTime - startTime) / 1000).toFixed(2) +
      ' seconds';
    document.getElementById('filterStr').disabled = false;
    document.getElementById('tab-btns').style.opacity = '1';
    document.getElementById('prev-btn').style.opacity = '1';
    document.getElementById('next-btn').style.opacity = '1';
    document.getElementById('json-lab').style.display = 'none';
    document.getElementById('pcap-lab').style.display = 'none';
    document.getElementById('llm-toggle').style.display = 'none';
  } else {
    document.getElementById('json-lab').style.display = 'block';
    document.getElementById('pcap-lab').style.display = 'block';
  }
}

/**
 * Reads and parses the JSON file, updates UI and state.
 * Uses chunked parsing for large files to avoid UI blocking.
 */
function processFile(file) {
  const reader = new FileReader();
  reader.onload = (event) => {
    const mainPanel = getCachedElement('main');
    if (isValidJson(event.target.result) == false) {
      console.log('Invalid JSON file');
      doError('Invalid JSON file, please upload a valid JSON capture!');
      fileLoaded(false);
      return;
    }
    fileLoaded(true);
    jsonOfPackets = event.target.result;
    getCachedElement('error-container').style.display = 'none';

    // Use chunked parsing for large files (>1MB)
    const fileSize = event.target.result.length;
    if (fileSize > 1024 * 1024) {
      statusUpdate('Status: Parsing large file (' + (fileSize / 1024 / 1024).toFixed(2) + 'MB)...');
      parseJsonChunked(event.target.result)
        .then((parsed) => {
          capturedPackets = parsed;
          jsonCapture = JSON.stringify(capturedPackets, null, 2);
          finalSummary = capturedPackets['Final Summary'] ?? '';
          finishProcessingFile();
        })
        .catch((e) => {
          console.error('JSON parse error:', e);
          doError('Error parsing JSON file!');
        });
    } else {
      capturedPackets = JSON.parse(event.target.result);
      jsonCapture = JSON.stringify(capturedPackets, null, 2);
      finalSummary = capturedPackets['Final Summary'] ?? '';
      finishProcessingFile();
    }
  };

  function finishProcessingFile() {
    getCachedElement('target_hosts').hidden = false;
    getCachedElement('summary-btn').style.display = 'block';
    // Reset host list and dropdowns for the new file
    hostsList = ['0.0.0.0'];
    const targetHostsDropdown = getCachedElement('target_hosts');
    while (targetHostsDropdown.options.length > 0) {
      targetHostsDropdown.remove(0);
    }
    bookmarkList = [];
    const selectBookmarkEl = document.getElementById('selectBookmark');
    while (selectBookmarkEl.options.length > 1) {
      selectBookmarkEl.remove(1);
    }
    // Populate host dropdown with hosts from JSON
    for (const host in capturedPackets['Host']) {
      hostsList.push(host);
      const newhost = document.createElement('option');
      newhost.textContent = host;
      newhost.value = host;
      targetHostsDropdown.appendChild(newhost);
      isFileLoaded = true;
    }
    writeSummary();
    initializeDataView();
  };
  reader.onerror = (error) => {
    status.textContent = 'Status: Error reading file: ' + error;
    doError('Error reading file!');
  };
  reader.readAsText(file);
}

/**
 * Updates the status bar with a message, then resets after 6 seconds.
 */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = 'PacketSnitch ' + psVer + ': Ready';
  }, 6000);
}

/**
 * Loads all capturedPackets for a given host IP into packetsForHost.
 */
function hostPacketInfo(currentIp) {
  const selected = currentIp;
  packetsForHost = [];
  const hostPackets = capturedPackets['Host'][selected];
  for (const packet in hostPackets) {
    packetsForHost.push(hostPackets[packet]);
  }
}

// Use event delegation for dynamically created elements
// and cache static elements at module load
const navButtons = {
  prev: getCachedElement('prev-btn'),
  next: getCachedElement('next-btn'),
  summary: getCachedElement('summary-btn'),
  data: getCachedElement('data-btn'),
  setBookmark: getCachedElement('setBookmark'),
};

// Update host filter when a new host is selected from dropdown
getCachedElement('target_hosts').addEventListener('change', function () {
  const selected = getCachedElement('target_hosts').value;
  let hostFilterEl = getCachedElement('host_filter');
  filteredPackets = []; // reset filter when host changes
  if (hostFilterEl.value !== selected) {
    hostFilterEl.value = selected;
  }
});

getCachedElement('target_hosts').addEventListener('click', function () {
  const selected = getCachedElement('target_hosts').value;
  filteredPackets = filterPackets(
    capturedPackets,
    'ip.src.addr: ' + selected + '|| ip.dst.addr: ' + selected,
  );
  handlePacketNavigation('filtered', null);
});

// Show summary when summary button is clicked
getCachedElement('summary-btn').addEventListener('click', function () {
  writeSummary();
});

// Displays the summary section from the loaded JSON.

function writeSummary() {
  statusUpdate('Status: Displaying capture analysis summary');
  //highlightTab("summary-navAction");
  if (jsonCapture == '') {
    statusUpdate('Status: No JSON file loaded, please upload a file first');
  } else {
    const summaryContainer = document.getElementById('main');
    document.getElementById('packetInfoPane').style.display = 'none';
    document.getElementById('packetPayloadPane').style.display = 'none';
    document.getElementById('summary_content').textContent =
      finalSummary || 'No LLM summary available.';
    document.getElementById('summary_box').style.display = 'block';
    fileLoaded(true);
  }
}

// Show host data when data button is clicked
document.getElementById('data-btn').addEventListener('click', function () {
  //highlightTab("data-navAction");
  initializeDataView();
});

function initializeDataView() {
  statusUpdate(
    'Status: Displaying packet information for ' + hostFilterEl.value,
  );
  if (jsonCapture == '') {
    statusUpdate('Status: No JSON file loaded, please upload a file first');
    doError('No file loaded! Upload one of JSON or PCAP first!');
  } else {
    document.getElementById('prev-btn').style.display = 'block';
    document.getElementById('next-btn').style.display = 'block';
    document.getElementById('welcome').style.display = 'none';
    //hostPacketInfostPacketInfo(hostFilterEl.value);
    if (document.getElementById('host_filter').value == '') {
      document.getElementById('host_filter').value = hostsList[1];
    }

    handlePacketNavigation('first-load');
  }
}

// Navigation for previous packet
document.getElementById('prev-btn').addEventListener('click', function () {
  statusUpdate('Status: Displaying capture analysis summary');
  //highlightTab("prev-navAction");
  if (index > 0) {
    index--;

    currentIp = packetsForHost[index]['Packet Info']['IP']['Source IP'];
    currentPacketKey =
      currentIp + ':' + packetsForHost[index]['Packet Info']['Index'];
    syncBookmarkDropdown(currentPacketKey);
    infoPanel(packetsForHost);
    popHexGrid(
      packetsForHost[index]['Packet Info']['Raw data']['Payload'][
        'Hex Encoded'
      ],
    );
    populateDataTypes(packetsForHost);
  }
});

// Navigation for next packet
document.getElementById('next-btn').addEventListener('click', function () {
  statusUpdate('Status: Displaying capture analysis summary');
  if (index < packetsForHost.length - 1) {
    index++;
    currentIp = packetsForHost[index]['Packet Info']['IP']['Source IP'];
    currentPacketKey =
      currentIp + ':' + packetsForHost[index]['Packet Info']['Index'];
  }
  syncBookmarkDropdown(currentPacketKey);
  infoPanel(packetsForHost);
  popHexGrid(
    packetsForHost[index]['Packet Info']['Raw data']['Payload']['Hex Encoded'],
  );
  populateDataTypes(packetsForHost);
});

// Handle bookmark selection from dropdown
document
  .getElementById('selectBookmark')
  .addEventListener('change', function () {
    const bookmarkHost = document
      .getElementById('selectBookmark')
      .value.split(':')[0];
    index = document.getElementById('selectBookmark').value.split(':')[1];
    packetsForHost = capturedPackets['Host'][bookmarkHost];
    activeBookmark['Host'] = bookmarkHost;
    activeBookmark['Packet'] = index;
    hostFilterEl.value = bookmarkHost;
    if (bookmarkHost == undefined || index == undefined) {
      statusUpdate('Invalid bookmark selection, missing host or packet index');
      doError('Invalid bookmark selection, missing host or packet index!');
    } else {
      document.getElementById('target_hosts').value = bookmarkHost;
    }
    handlePacketNavigation('bookmark', activeBookmark);
  });

// Add current packet as a bookmark
document.getElementById('setBookmark').addEventListener('click', function () {
  if (!bookmarkList.includes(currentPacketKey)) {
    if (currentPacketKey != undefined) {
      bookmarkList.push(currentPacketKey);
      document
        .getElementById('selectBookmark')
        .appendChild(new Option(currentPacketKey, currentPacketKey));
    }
  }
});

// Syncs the bookmark dropdown to reflect whether the given packet key is bookmarked
function syncBookmarkDropdown(packetKey) {
  document.getElementById('selectBookmark').value = bookmarkList.includes(
    packetKey,
  )
    ? packetKey
    : '';
}

// function that returns the total number of packets in the entire capture
function totalPacketCount() {
  let totalCount = 0;
  if (capturedPackets['Host'] != undefined) {
    for (const host in capturedPackets['Host']) {
      totalCount += capturedPackets['Host'][host].length;
    }
  } else {
    return 0;
  }
  return totalCount;
}

/**
 * Handles navigation between capturedPackets (next, prev, activeBookmark, first-load).
 * Updates UI and packet info accordingly.
 */
function handlePacketNavigation(navAction, navBookmark) {
  document.getElementById('loading-container').style.display = 'none';
  document.getElementById('summary_box').style.display = 'none';
  document.getElementById('packetInfoPane').style.display = 'block';
  document.getElementById('packetPayloadPane').style.display = 'block';
  document.getElementById('summary_box').style.display = 'none';
  document.getElementById('welcome').style.display = 'none';
  showAllData();

  document.getElementById('total-packets').innerHTML =
    'Total Packets: ' + totalPacketCount();
  index = 0;
  if (navAction === undefined) {
    handlePacketNavigation('first-load');
  }
  let packetSet = capturedPackets['Host'][hostFilterEl.value];
  if (navAction === 'filtered') {
    packetSet = [];
    document.getElementById('filter-returned').textContent =
      'Filtered Packets: ' + filteredPackets.length;
    packetSet = filteredPackets;
  }

  if (navAction === 'bookmark') {
    if (
      navBookmark['Host'] == undefined ||
      navBookmark['Packet'] == undefined
    ) {
      statusUpdate('Status: Invalid bookmark data, reverting to first packet');
      doError('Invalid bookmark data, missing host or packet index!');
      handlePacketNavigation('first-load');
    } else {
      index = navBookmark['Packet'] - 1;

      statusUpdate(
        'Navigating to bookmark: ' +
          navBookmark['Host'] +
          ' packet ' +
          navBookmark['Packet'],
      );
    }
  }
  if (!packetSet || packetSet.length === 0) {
    statusUpdate('Status: No packets');
    return;
  }
  if (
    packetSet != undefined &&
    (packetSet.length == 0 || packetSet[0] == undefined)
  ) {
    statusUpdate('Status: No packet information found for this host');
    document.getElementById('main').innerHTML = 'Please select a json file!';
  }
  // in the data main secton, this is where we would
  // add the packet info for each packet, for now we just
  // dump the json, we'll format later
  // packetsForHost[index] is an array of all packet info
  // for the current host, we want to be able to navigate
  // through it with next and prev buttons
  if (packetSet == undefined || packetSet[index] == undefined) {
    statusUpdate('Status: No packet information found for this host');
    doError('No packet information found for this host!');
    return;
  } else {
    currentIp = packetSet[index]['Packet Info']['IP']['Source IP'];
    currentPacketKey =
      currentIp + ':' + packetSet[index]['Packet Info']['Index'];
    syncBookmarkDropdown(currentPacketKey);
    console.log(packetSet[index]);
    const hexPayload =
      packetSet[index]['Packet Info']['Raw data']['Payload']['Hex Encoded'];
    infoPanel(packetSet);
    popHexGrid(hexPayload);
    populateDataTypes(packetSet);
  }
}
function populateDataTypes(p) {
  const typesListEl = document.getElementById('types-list');
  typesListEl.textContent = '';
  const mimeTypeEl = document.getElementById('mime-type');
  const charsetEl = document.getElementById('charset');
  const encodingEl = document.getElementById('encoding');
  const languageEl = document.getElementById('language');
  encodingEl.textContent = '';
  languageEl.textContent = '';
  let encodingText = '';
  let languageText = '';
  // packetsForHost = capturedPackets["Host"][hostFilterEl.value];
  packetsForHost = p;
  let charsetText = JSON.parse(
    JSON.stringify(
      packetsForHost[index]['Extra Info']['Traits']['Characters']['Charset'],
    ),
  );
  if (
    packetsForHost[index]['Extra Info']['Traits']['Characters']['Encoding'] ==
    'Unavailable for high entropy data'
  ) {
    encodingText = JSON.parse(
      JSON.stringify(
        packetsForHost[index]['Extra Info']['Traits']['Characters']['Encoding'],
      ),
    );
  } else {
    encodingText = JSON.stringify(
      packetsForHost[index]['Extra Info']['Traits']['Characters']['Encoding'][
        'encoding'
      ],
    );
    languageText = JSON.stringify(
      packetsForHost[index]['Extra Info']['Traits']['Characters']['Encoding'][
        'language'
      ],
    );
  }

  const mimeTypeText = JSON.parse(
    JSON.stringify(packetsForHost[index]['Extra Info']['MIME Type']),
  );
  let dataItems = JSON.parse(
    JSON.stringify(packetsForHost[index]['Extra Info']['Data Types']),
  );
  let sslDetails = '';
  if (
    packetsForHost[index]['Extra Info']['Traits']['Server Info'][
      'Encryption Data'
    ] != 'N/A' &&
    packetsForHost[index]['Extra Info']['Traits']['Server Info'][
      'Encryption Data'
    ] != undefined
  ) {
    sslDetails =
      packetsForHost[index]['Extra Info']['Traits']['Server Info'][
        'Encryption Data'
      ]['SSL Version'];
    const protoName =
      packetsForHost[index]['Extra Info']['Traits']['Network Data'][
        'Port Protcol'
      ];
    dataItems = [];
    dataItems.push(sslDetails + ' encrypted stream');
    dataItems.push(protoName + ' protocol data');
  }

  mimeTypeEl.textContent = 'MIME type: ' + mimeTypeText;
  charsetText = charsetText == '' ? 'Unknown' : charsetText;
  encodingText = encodingText == '' ? 'Unknown' : encodingText;
  if (encodingText !== undefined) {
    encodingEl.textContent =
      'Payload Encoding: ' + encodingText.replace(/"/g, '');
  }
  if (languageText !== undefined) {
    languageEl.textContent =
      'Payload Language: ' + languageText.replace(/"/g, '');
  }
  dataItems.forEach((item) => {
    const listItem = document.createElement('li');
    listItem.textContent = item;
    typesListEl.appendChild(listItem);
  });
}
// this takes a char code and returns true if it's
// a printable ASCII character, false otherwise
function isPrintable(charCode) {
  // ASCII printable: 32 (space) to 126 (~)
  return charCode >= 32 && charCode <= 126;
}

// this changes hex to ASCII
function hexToAscii(hex) {
  let decodedAscii = '';
  for (let i = 0; i < hex.length; i += 2) {
    decodedAscii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return decodedAscii;
}

// trunactes a string to a max length
function truncate(str, maxLength) {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength);
}

// returns a 0 padded hex string of a number with a given length
function decToHex(num, pad) {
  return num.toString(16).padStart(pad, '0');
}

// clears the higlights (its called after the moouse leaves grid)
function clearGridHighlights() {
  document
    .querySelectorAll('.griditem')
    .forEach((el) => el.classList.remove('highlight'));
}

/**
 * Populates the hex grid display with the given hex string.
 */
function popHexGrid(hex) {
  // swap it back to ASCII for the fade box
  const payloadAsciiBox = document.getElementById('payloadascii');
  const decodedAscii = hexToAscii(hex);
  document.getElementById('hexg').textContent = '';
  const hexGridContainer = document.getElementById('hexg');
  // this block populates the grid with boxes for hex codes
  for (const x of hex.toUpperCase().match(/.{1,2}/g)) {
    const item = document.createElement('div');
    item.classList.add('griditem');
    item.textContent = x;
    hexGridContainer.appendChild(item);
  }
  function getPrintableSequence(startIndex) {
    let result = '';
    for (let i = startIndex; i < decodedAscii.length; i++) {
      if (!isPrintable(decodedAscii.charCodeAt(i))) break;
      result += String.fromCharCode(decodedAscii.charCodeAt(i));
    }
    return result;
  }
  // Attach event listeners to each grid item
  document.querySelectorAll('.griditem').forEach((item, idx) => {
    item.addEventListener('mouseenter', (e) => {
      //box fade in
      const hexOffsetDisplay = document.getElementById('asciiOffset');
      const asciiTextBox = document.getElementById('asciiText');
      payloadAsciiBox.style.top = e.clientY + 18 + 'px';
      payloadAsciiBox.style.left = e.clientX + 18 + 'px';
      payloadAsciiBox.classList.add('visible');
      asciiTextBox.innerHTML = '';
      const printable = getPrintableSequence(idx);
      window.currentPrintableSequence = printable;
      // adds only consecutive printable characters to the decodedAscii box
      asciiTextBox.textContent += truncate(printable, 32);
      for (let i = 0; i < truncate(printable, 32).length; i++) {
        const highlightedCell = document.querySelectorAll('.griditem')[idx + i];
        highlightedCell.classList.add('highlight');
      }
      const hexLen = parseInt(truncate(printable, 32).length, 10)
        .toString(16)
        .padStart(2, '0')
        .toUpperCase();
      const hexOffset = idx.toString(16).padStart(4, '0').toUpperCase();
      if (printable.length == 0) {
        asciiTextBox.textContent = '0x' + item.textContent;
      }
      hexOffsetDisplay.textContent = '0x' + hexOffset + ':' + hexLen;
    });
  });
  // this fades the box back out and calls the grid clear func
  document.querySelectorAll('.griditem').forEach((item) => {
    item.addEventListener('mouseleave', () => {
      payloadAsciiBox.classList.remove('visible');
      clearGridHighlights();
    });
  });
}

/**
 * Utility to create a table from data and headers, and append to a container.
 */
// probably should break this function up into smaller pieces,
// but it works for now, it takes the current packet info and
// populates the info panel with it, including the side tables
// and the main info table, also updates the timestamp and
// currentIp:port info at the top
function infoPanel(pk) {
  const infoPaneEl = document.getElementById('packetInfoPane');
  document.getElementById('rightside').style.display = 'block';
  document.getElementById('leftside').style.display = 'block';
  const infoPaneOrigHtml = infoPaneEl.innerHTML;
  infoPaneEl.style.display = 'block';
  const p = pk[index];
  let packetInfoData = p['Packet Info'];
  let extraInfoData = p['Extra Info'];
  let packetTimestamp = packetInfoData['Packet Timestamp'];
  let ipChecksum = packetInfoData['IP']['IP Checksum'];

  // Determine transport protocol (TCP or UDP); fall back to TCP for older captures
  const protocol = packetInfoData['Protocol'] || 'TCP';
  const transportData = packetInfoData[protocol] || {};

  const transportChecksum =
    protocol === 'TCP'
      ? transportData['TCP checksum']
      : protocol === 'UDP'
        ? transportData['UDP checksum']
        : protocol === 'ICMP'
          ? transportData['ICMP Checksum']
          : 'N/A';
  const transportLayerLen =
    protocol === 'TCP'
      ? transportData['TCP layer length']
      : protocol === 'UDP'
        ? transportData['UDP length']
        : protocol === 'ICMP'
          ? transportData['Wire length']
          : 'N/A';
  const tcpFlags =
    protocol === 'TCP' && transportData['TCP Flag Data']
      ? transportData['TCP Flag Data']['Flags']
      : 'N/A';

  const sourceIpPort =
    packetInfoData['IP']['Source IP'] +
    ':' +
    (transportData['Source port'] ?? '?');
  const destIpPort =
    packetInfoData['IP']['Destination IP'] +
    ':' +
    (transportData['Destination port'] ?? '?');
  const etherFrame =
    typeof packetInfoData['Ethernet Frame'] === 'object' &&
    packetInfoData['Ethernet Frame'] !== null
      ? packetInfoData['Ethernet Frame']
      : {};
  const srcMac = etherFrame['MAC Source'] ?? 'N/A';
  const dstMac = etherFrame['MAC Destination'] ?? 'N/A';
  const srcMacVendor = etherFrame['MAC Source Vendor'] ?? 'N/A';
  const dstMacVendor = etherFrame['MAC Destination Vendor'] ?? 'N/A';
  const ipLayerLen = packetInfoData['IP']['IP layer length'];
  const wireLen = transportData['Wire length'];
  const payloadLen = packetInfoData['Raw data']['Payload Length'];
  let sslCert = '';
  let sslVersion = '';
  let sslAlgos = '';
  if (
    extraInfoData['Traits']['Server Info']['Encryption Data'] == 'N/A' ||
    extraInfoData['Traits']['Server Info'].hasOwnProperty('Encryption Data') ==
      false
  ) {
    sslCert = 'Not encrypted';
    sslVersion = 'Not encrypted';
    sslAlgos = '';
  } else {
    sslCert =
      extraInfoData['Traits']['Server Info']['Encryption Data']['SSL Cert'] ??
      'Not available';
    sslVersion =
      extraInfoData['Traits']['Server Info']['Encryption Data'][
        'SSL Version'
      ] ?? 'Not available';
    sslAlgos =
      extraInfoData['Traits']['Server Info']['Encryption Data'][
        'Encrypted With'
      ].join('<br>Extra algo info: ') ?? 'No algorithm information available';
  }
  const isDecompressed = extraInfoData['Decompressed']['Decompressed'];
  function removeIps(ipList) {
    const ipRegex =
      /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/;
    return ipList.filter((item) => !ipRegex.test(item));
  }

  let dnsHostsHtml;
  if (
    extraInfoData['Traits']['Network Data']['Hostnames']['Hostnames'] ==
    undefined
  ) {
    dnsHostsHtml = 'localhost';
  } else {
    dnsHostsHtml =
      'localhost<br>' +
      extraInfoData['Traits']['Network Data']['Hostnames']['Hostnames'].join(
        '<br>',
      );
  }
  const filteredDnsHosts = removeIps(dnsHostsHtml.split('<br>')).join('<br>');
  dnsHostsHtml = filteredDnsHosts == '' ? 'localhost' : filteredDnsHosts;

  const pageTitle = extraInfoData['Traits']['Server Info']['Page Title'];
  const isEncrypted = extraInfoData['Traits']['Server Info']['Encrypted'];
  const protoName = extraInfoData['Traits']['Network Data']['Port Protcol'];
  const protoDescription =
    extraInfoData['Traits']['Network Data']['Port Description'];
  const srcNetClass =
    extraInfoData['Traits']['Network Data']['Source IP']['Class'];
  const dstNetClass =
    extraInfoData['Traits']['Network Data']['Destination IP']['Class'];
  document.getElementById('sidedatatable').textContent = '';
  document.getElementById('protoInfoSrc').textContent = 'Source';
  document.getElementById('protoInfoDest').textContent = 'Destination';
  document.getElementById('comp').textContent = 'Unknown';
  if (isDecompressed == false || isDecompressed == undefined) {
    const types = extraInfoData['Data Types'];

    types.forEach((type) => {
      if (type.includes('Zlib') || type.includes('zlib')) {
        document.getElementById('comp').textContent = 'Compressed with zlib';

        console.log('Data type identified: ' + type);
      }
      if (type.includes('Gzip') || type.includes('gzip')) {
        document.getElementById('comp').textContent = 'Compressed with gzip';
      }
      if (type.includes('Zip')) {
        document.getElementById('comp').textContent = 'Compressed with zip';
      }
    });
  }
  if (isDecompressed == true) {
    document.getElementById('comp').textContent =
      'Not regonized as compressed data';
  }
  //  wireLen
  if (pageTitle == undefined || pageTitle == 'N/A') {
    document.getElementById('website').textContent =
      'Not available for this server';
  } else {
    document.getElementById('website').textContent = pageTitle;
  }
  //document.getElementById("crypt").textContent = isEncrypted;
  const dnsCollapsedList = dnsHostsHtml.replace(/(<br\s*\/?>\s*)+/gi, '<br>');
  document.getElementById('dns').innerHTML = dnsCollapsedList;
  if (sslAlgos == undefined || sslAlgos == '') {
    //document.getElementById("crypt").innerHTML = sslCert
    //  ? "Encrypted with: " + sslVersion + "<br>" + sslAlgos
    //  : "Not Encrypted";
    document.getElementById('crypt').innerHTML = 'Not encrypted';
  } else {
    document.getElementById('crypt').innerHTML =
      'Encrypted with: ' + sslVersion + '<br>' + sslAlgos;
  }

  if (protoName == 'Unknown') {
    document.getElementById('protocols').innerHTML = 'Unknown';
  } else {
    document.getElementById('protocols').innerHTML =
      'Protocol Name: ' +
      protoName +
      '<br>Protocol Description: ' +
      protoDescription;
  }
  const checksumData = [
    { name: 'IP Checksum', value: ipChecksum },
    { name: protocol + ' Checksum', value: transportChecksum },
    { name: 'Flags', value: tcpFlags },
    { name: 'IP Length', value: ipLayerLen },
    { name: protocol + ' Length', value: transportLayerLen },
    { name: 'Wire Length', value: wireLen },
    { name: 'Payload Length', value: payloadLen },
  ];
  const checksumHeaders = ['Protocol data', 'Details'];
  createTable(checksumData, checksumHeaders, 'sidedatatable');

  // DNS info table (shown for UDP/DNS packets)
  renderDnsTable(transportData);

  // ICMP info table (shown for ICMP packets)
  renderIcmpTable(protocol, transportData);

  // SNMP info table (shown for SNMP packets on port 161/162)
  renderSnmpTable(transportData);

  // DHCP info table (shown for DHCP packets on port 67/68)
  renderDhcpTable(transportData);

  // NTP info table (shown for NTP packets on port 123)
  renderNtpTable(transportData);

  // SIP info table (shown for SIP packets on port 5060/5061)
  renderSipTable(transportData);

  // HTTP info table (shown for HTTP request/response packets)
  renderHttpTable(transportData);

  // HTTP/2 info table (shown for HTTP/2 frames on any TCP port)
  renderHttp2Table(transportData);

  // FTP info table (shown for FTP packets on port 20/21)
  renderFtpTable(transportData);

  // SMTP info table (shown for SMTP packets on port 25/587/465)
  renderSmtpTable(transportData);

  // POP3 info table (shown for POP3 packets on port 110/995)
  renderPop3Table(transportData);

  // IMAP info table (shown for IMAP packets on port 143/993)
  renderImapTable(transportData);

  // Telnet info table (shown for Telnet packets on port 23)
  renderTelnetTable(transportData);

  // IRC info table (shown for IRC packets on port 6667/6668/6669)
  renderIrcTable(transportData);

  // MTP info table (shown for MTP/MMS packets on port 1755)
  renderMtpTable(transportData);

  // LDAP info table (shown for LDAP packets on port 389/636)
  renderLdapTable(transportData);

  // MySQL info table (shown for MySQL packets on port 3306)
  renderMysqlTable(transportData);

  // PostgreSQL info table (shown for PostgreSQL packets on port 5432)
  renderPostgresqlTable(transportData);

  // XMPP info table (shown for XMPP packets on port 5222/5223)
  renderXmppTable(transportData);

  // SMB info table (shown for SMB packets on port 139/445)
  renderSmbTable(transportData);

  // MQTT info table (shown for MQTT packets on port 1883/8883)
  renderMqttTable(transportData);

  // RTSP info table (shown for RTSP packets on port 554)
  renderRtspTable(transportData);

  // TFTP info table (shown for TFTP packets on UDP port 69)
  renderTftpTable(transportData);

  // BGP info table (shown for BGP packets on port 179)
  renderBgpTable(transportData);

  // NNTP info table (shown for NNTP packets on port 119)
  renderNntpTable(transportData);

  // RADIUS info table (shown for RADIUS packets on port 1812/1813/1645/1646)
  renderRadiusTable(transportData);

  const ipTableHeaders = ['Packet', 'Data'];
  const srcIpData = [
    { name: 'IP:Port', value: sourceIpPort },
    { name: 'MAC', value: srcMac },
    { name: 'MAC Vendor', value: srcMacVendor },
    { name: 'Network Class', value: srcNetClass },
  ];
  createTable(srcIpData, ipTableHeaders, 'protoInfoSrc');
  const dstIpData = [
    { name: 'IP:Port', value: destIpPort },
    { name: 'MAC', value: dstMac },
    { name: 'MAC Vendor', value: dstMacVendor },
    { name: 'Network Class', value: dstNetClass },
  ];
  createTable(dstIpData, ipTableHeaders, 'protoInfoDest');
  const entropyValue = extraInfoData['Traits']['Shannon Entropy'];
  document.getElementById('timestamp').textContent =
    'Timestamp ' + packetTimestamp;
  //document.getElementById("ip2ip").textContent = sourceIpPort + " ~ " + destIpPort;
  document.getElementById('sideloctable').textContent = '';
  document.getElementById('entropybox').textContent =
    '\u096F ' + entropyValue.toFixed(2);
  const entropyBoxEl = document.getElementById('entropybox');
  if (entropyValue >= 6.8) {
    entropyBoxEl.className = 'high';
  } else if (entropyValue >= 4.5) {
    entropyBoxEl.className = 'med';
  } else {
    entropyBoxEl.className = 'low';
  }
  const secondColumnCells = document.querySelectorAll(
    'table tr td:nth-child(1), table tr th:nth-child(1)',
  );
  secondColumnCells.forEach((cell) => {
    cell.style.width = '23%';
  });
  if (
    extraInfoData['Traits']['Network Data']['Source IP']['Location']['City'] ==
    undefined
  ) {
    const localnetData = [{ name: 'Location', value: 'Localnet' }];
    const localnetHeaders = ['Source Host', 'Location'];
    createTable(localnetData, localnetHeaders, 'sideloctable');
  } else {
    const srcLocData = [
      {
        name: 'Country',
        value:
          extraInfoData['Traits']['Network Data']['Source IP']['Location'][
            'Country'
          ],
      },
      {
        name: 'City',
        value:
          extraInfoData['Traits']['Network Data']['Source IP']['Location'][
            'City'
          ],
      },
      {
        name: 'Timezone',
        value:
          extraInfoData['Traits']['Network Data']['Source IP']['Location'][
            'Time Zone'
          ],
      },
    ];
    const srcLocHeaders = ['Source Host', 'Location'];
    createTable(srcLocData, srcLocHeaders, 'sideloctable');
  }
  if (
    extraInfoData['Traits']['Network Data']['Destination IP']['Location'][
      'City'
    ] == undefined
  ) {
    const localnetData = [{ name: 'Location', value: 'Localnet' }];
    const localnetHeaders = ['Destination Host', 'Location'];
    createTable(localnetData, localnetHeaders, 'sideloctable');
  } else {
    const dstLocData = [
      {
        name: 'Country',
        value:
          extraInfoData['Traits']['Network Data']['Destination IP']['Location'][
            'Country'
          ],
      },
      {
        name: 'City',
        value:
          extraInfoData['Traits']['Network Data']['Destination IP']['Location'][
            'City'
          ],
      },
      {
        name: 'Timezone',

        value:
          extraInfoData['Traits']['Network Data']['Destination IP']['Location'][
            'Time Zone'
          ],
      },
    ];
    const dstLocHeaders = ['Destination Host', 'Location'];
    createTable(dstLocData, dstLocHeaders, 'sideloctable');
  }
}

// Save the currently loaded JSON capture to a user-chosen file via a worker thread
document.getElementById('save-json-btn').addEventListener('click', function () {
  if (!jsonCapture) {
    statusUpdate('Status: No data loaded to save');
    return;
  }
  window.saveapi.saveJson(jsonCapture).then((result) => {
    if (result.canceled) {
      statusUpdate('Status: Save cancelled');
    } else if (result.success) {
      statusUpdate('Status: JSON saved successfully');
    } else {
      doError('Save failed');
      statusUpdate(
        'Status: Save failed – ' + (result.error || 'unknown error'),
      );
      console.error('Save failed:', result.error);
    }
  });
});

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns our json data from snitch.py
window.jsonapi.onJsonData((jsonData) => {
  document.getElementById('loading-container').style.display = 'block';
  document.getElementById('error-container').style.display = 'none';
  statusUpdate('Loaded data from backend, processing...');
  processFile(
    new File([jsonData], 'capture.json', { type: 'application/json' }),
  );
  document.getElementById('loading-container').style.display = 'none';
  const loadEndTime = performance.now();
  document.getElementById('load-time').textContent =
    'Load time: ' + ((loadEndTime - startTime) / 1000).toFixed(2) + ' seconds';
});

// here we create the backend process and hook it to the handler
function runSnitch(file) {
  document.getElementById('loading-container').style.display = 'block';
  document.getElementById('summary_content').innerHTML =
    '<span id="loaderdots" class="loading">Loading</span>';
  document.getElementById('status').textContent =
    'Status: Running snitch backend, this may take a few minutes...';
  document.getElementById('error-container').style.display = 'none';
  startTime = performance.now();
  const useLLM = document.getElementById('use-llm').checked;
  window.snitchapi.runBackendCommand(file, useLLM).then((output) => {});
}

function doError(message) {
  console.error('Error from backend:', message);
  const loadingContainerEl = document.getElementById('loading-container');
  const errorContainerEl = document.getElementById('error-container');
  document.getElementById('summary_content').textContent = '';
  loadingContainerEl.style.display = 'none';
  errorContainerEl.style.display = 'block';
  errorContainerEl.textContent = message;
  errorContainerEl.addEventListener('click', () => {
    errorContainerEl.style.display = 'none';
    loadingContainerEl.style.display = 'none';
  });
}

function hideAllData() {
  //  document.getElementById("packetInfoPane").textContent =
  //    "No matching packets found.";
  doError('No packets match the filter criteria!');
  statusUpdate('Status: No packets match the filter criteria');
  document.getElementById('data-types').style.display = 'none';
  document.getElementById('protoInfo').style.display = 'none';
  document.getElementById('timestamp').style.display = 'none';
  document.getElementById('rightside').style.display = 'none';
  document.getElementById('active-recon').style.display = 'none';
  document.getElementById('prev-btn').style.opacity = '0';
  document.getElementById('next-btn').style.opacity = '0';
  popHexGrid('00'.repeat(1));
}
function showAllData() {
  document.getElementById('prev-btn').style.opacity = '1';
  document.getElementById('next-btn').style.opacity = '1';
  document.getElementById('data-types').style.display = 'block';
  document.getElementById('protoInfo').style.display = 'block';
  document.getElementById('timestamp').style.display = 'block';
  document.getElementById('rightside').style.display = 'block';
  document.getElementById('active-recon').style.display = 'block';
  document.getElementById('hexg').hidden = false;
  document.getElementById('error-container').style.display = 'none';
}

document
  .getElementById('filterStr')
  .addEventListener('keydown', function (event) {
    if (event.key === 'Enter') {
      const filterQuery = document.getElementById('filterStr').value;
      filteredPackets = filterPackets(capturedPackets, filterQuery);

      if (filteredPackets == undefined || filteredPackets.length == 0) {
        hideAllData();
        statusUpdate('Status: No packets match the filter criteria');
      } else {
        statusUpdate(
          'Status: Displaying ' +
            filteredPackets.length +
            ' packets matching filter',
        );
        handlePacketNavigation('filtered', null);
      }
    }
  });

window.onerror = (message, source, lineno, colno, error) => {
  doError(message + ' at ' + source + ':' + lineno + ':' + colno);
};

window.onunhandledrejection = (event) => {
  doError('Unhandled promise error! ' + event.reason);
};

window.api.onError((msg) => {
  console.error('Error from backend:', msg);
  // Show alert or UI message
  doError(msg);
});

// On page load, hide packet info and payload panes
onload = function () {
  // document.getElementById("selectBookmark").style.display = "none";
  document.getElementById('packetInfoPane').style.display = 'none';
  document.getElementById('packetPayloadPane').style.display = 'none';
  document.getElementById('rightside').style.display = 'none';
  document.getElementById('leftside').style.display = 'none';
  document.getElementById('loading-container').style.display = 'none';
};
