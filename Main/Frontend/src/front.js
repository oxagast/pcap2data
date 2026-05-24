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
let activityLogPath = 'Unavailable';
const activityLogEntries = [];
const filterInputEl = getCachedElement('filterStr');
const filterHighlightEl = getCachedElement('filterStr-highlight');
const filterHistoryToggleEl = getCachedElement('filter-history-toggle');
const filterHistoryMenuEl = getCachedElement('filter-history-menu');
const filterHistoryContainerEl = getCachedElement('filter-history');
const filterHistory = [];

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

function renderActivityLogEntries(searchText = '') {
  const entriesEl = document.getElementById('activity-log-entries');
  if (!entriesEl) return;
  entriesEl.replaceChildren();
  const normalizedSearch = searchText.trim().toLowerCase();
  activityLogEntries
    .filter((entry) =>
      normalizedSearch
        ? entry.message.toLowerCase().includes(normalizedSearch)
        : true,
    )
    .forEach((entry) => {
      const row = document.createElement('div');
      row.className = 'activity-log-entry';
      row.textContent = entry.message;
      entriesEl.appendChild(row);
    });
}

function writeLogEntry(message) {
  const stampedMessage = `[${new Date().toISOString()}] ${message}`;
  activityLogEntries.unshift({ message: stampedMessage });
  renderActivityLogEntries(
    document.getElementById('activity-log-search')?.value || '',
  );
  if (window.logapi) {
    window.logapi.append(stampedMessage).then((result) => {
      if (result && result.path) {
        activityLogPath = result.path;
        const pathEl = document.getElementById('activity-log-path');
        if (pathEl) {
          pathEl.textContent = `Log file: ${activityLogPath}`;
        }
      }
    });
  }
}

function logErrorEntry(context, error) {
  const errorDetails =
    error && typeof error === 'object' && 'message' in error
      ? error.message
      : String(error);
  writeLogEntry(`Error context=${context} details="${errorDetails}"`);
}

function initializeActivityLog() {
  const pathEl = document.getElementById('activity-log-path');
  const panelEl = document.getElementById('activity-log-panel');
  const searchEl = document.getElementById('activity-log-search');
  const logBtn = document.getElementById('log-btn');
  const closeBtn = document.getElementById('close-log-btn');
  if (window.logapi) {
    window.logapi.getPath().then((path) => {
      if (path) {
        activityLogPath = path;
        pathEl.textContent = `Log file: ${activityLogPath}`;
      }
    });
  }
  logBtn.addEventListener('click', () => {
    panelEl.style.display = 'block';
  });
  closeBtn.addEventListener('click', () => {
    panelEl.style.display = 'none';
  });
  searchEl.addEventListener('input', (event) => {
    renderActivityLogEntries(event.target.value);
  });
  writeLogEntry('PacketSnitch UI session initialized');
}

function getPacketTimeframe() {
  if (!capturedPackets || typeof capturedPackets !== 'object') return null;
  const packetTimes = [];
  if (!capturedPackets['Host']) return null;
  for (const host of Object.keys(capturedPackets['Host'])) {
    const hostPackets = capturedPackets['Host'][host];
    if (!Array.isArray(hostPackets)) continue;
    hostPackets.forEach((packet) => {
      const packetTime = packet?.['Packet Info']?.['Packet Timestamp'];
      if (packetTime) {
        packetTimes.push(packetTime);
      }
    });
  }
  if (packetTimes.length === 0) return null;
  const parsedTimes = packetTimes
    .map((time) => ({
      raw: time,
      value: Date.parse(time),
    }))
    .filter((item) => !Number.isNaN(item.value))
    .sort((a, b) => a.value - b.value);
  if (parsedTimes.length < 1) return null;
  return {
    first: parsedTimes[0].raw,
    last: parsedTimes[parsedTimes.length - 1].raw,
  };
}

function logCurrentPacketDisplay(action) {
  if (!packetsForHost || !packetsForHost[index]) return;
  const packetInfo = packetsForHost[index]['Packet Info'];
  const selectedHost = getCachedElement('host_filter').value || 'Unknown host';
  const sourceIp = packetInfo?.['IP']?.['Source IP'] || 'Unknown source';
  const destinationIp =
    packetInfo?.['IP']?.['Destination IP'] || 'Unknown destination';
  const packetIndex = packetInfo?.['Index'] ?? index;
  const packetTimestamp = packetInfo?.['Packet Timestamp'] || 'Unknown time';
  writeLogEntry(
    `Displayed packet action=${action} host=${selectedHost} packet=${packetIndex} source=${sourceIp} destination=${destinationIp} timeframe=${packetTimestamp}`,
  );
}

initializeActivityLog();

popHexGrid('00'.repeat(256));
// Set up file upload handler for JSON capture
document
  .getElementById('json-upload')
  .addEventListener('change', function (event) {
    const file = event.target.files[0];
    if (file) {
      startTime = performance.now();
      statusUpdate('Processing file: ' + file.name);
      writeLogEntry(
        `User selected JSON file name=${file.name} size_bytes=${file.size}`,
      );
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
        writeLogEntry(`User selected PCAP file path=${filePath}`);
        window.fsize
          .getFSize()
          .then((fileSize) => {
            // Update the UI with the file size
            const fileSizeKb = (fileSize / 1024).toFixed(2);
            document.getElementById('pcap-size').textContent =
              `PCAP size: ${fileSizeKb}kb`;
            writeLogEntry(
              `Capture size recorded bytes=${fileSize} kilobytes=${fileSizeKb}`,
            );
          })
          .catch((error) => {
            // Handle any errors (e.g., file not found)
            console.error('Error fetching file size:', error);
            logErrorEntry('file-size-fetch', error);
          });

        runSnitch(filePath);
      }
    }).catch((error) => {
      doError('Error selecting PCAP file!');
      logErrorEntry('pcap-select', error);
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
  isFileLoaded = isLoaded;
  if (isLoaded) {
    const loadEndTime = performance.now();
    document.getElementById('load-time').textContent =
      'Load time: ' +
      ((loadEndTime - startTime) / 1000).toFixed(2) +
      ' seconds';
    filterInputEl.disabled = false;
    filterHistoryToggleEl.disabled = false;
    document.getElementById('tab-btns').style.opacity = '1';
    document.getElementById('prev-btn').style.opacity = '1';
    document.getElementById('next-btn').style.opacity = '1';
    document.getElementById('log-btn').style.opacity = '1';
    document.getElementById('stats-btn').style.opacity = '1';
    document.getElementById('list-btn').style.opacity = '1';
    document.getElementById('json-lab').style.display = 'none';
    document.getElementById('pcap-lab').style.display = 'none';
    document.getElementById('llm-toggle').style.display = 'none';
    writeLogEntry(
      `Initial file load completed seconds=${((loadEndTime - startTime) / 1000).toFixed(2)}`,
    );
  } else {
    filterInputEl.disabled = true;
    filterHistoryToggleEl.disabled = true;
    document.getElementById('json-lab').style.display = 'block';
    document.getElementById('pcap-lab').style.display = 'block';
    document.getElementById('log-btn').style.opacity = '0';
    document.getElementById('stats-btn').style.opacity = '0';
    document.getElementById('list-btn').style.opacity = '0';
  }
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function decorateExpressionSegment(segmentText) {
  if (!segmentText) return '';

  const colonIndex = segmentText.indexOf(':');
  if (colonIndex === -1) {
    return `<span class="query-token-value">${escapeHtml(segmentText)}</span>`;
  }

  const keyText = segmentText.slice(0, colonIndex);
  const valueText = segmentText.slice(colonIndex + 1);
  const cmpMatch = valueText.match(/^(\s*)(>=|<=|==|!=|>|<)(\s*)(.*)$/);

  let valueHtml = '';
  if (cmpMatch) {
    valueHtml =
      escapeHtml(cmpMatch[1]) +
      `<span class="query-token-operator">${escapeHtml(cmpMatch[2])}</span>` +
      escapeHtml(cmpMatch[3]) +
      `<span class="query-token-value">${escapeHtml(cmpMatch[4])}</span>`;
  } else {
    valueHtml = `<span class="query-token-value">${escapeHtml(valueText)}</span>`;
  }

  return (
    `<span class="query-token-key">${escapeHtml(keyText)}</span>` +
    '<span class="query-token-colon">:</span>' +
    valueHtml
  );
}

function renderHighlightedQuery(query) {
  const source = query || '';
  if (!source) return '&nbsp;';

  // Query grammar tokens: logical OR/AND operators and grouping parentheses.
  const tokenRegex = /(\|\||&&|\(|\))/g;
  let cursor = 0;
  let html = '';
  let tokenMatch = tokenRegex.exec(source);

  while (tokenMatch !== null) {
    const segmentText = source.slice(cursor, tokenMatch.index);
    html += decorateExpressionSegment(segmentText);

    const tokenText = tokenMatch[0];
    const tokenClass = tokenText === '(' || tokenText === ')' ? 'paren' : 'logic';
    html += `<span class="query-token-${tokenClass}">${escapeHtml(tokenText)}</span>`;
    cursor = tokenRegex.lastIndex;
    tokenMatch = tokenRegex.exec(source);
  }

  html += decorateExpressionSegment(source.slice(cursor));
  return html;
}

function syncFilterHighlight() {
  filterHighlightEl.innerHTML = renderHighlightedQuery(filterInputEl.value);
  syncFilterHighlightScroll();
}

function syncFilterHighlightScroll() {
  filterHighlightEl.scrollLeft = filterInputEl.scrollLeft;
}

function setHistoryMenuOpen(isOpen) {
  filterHistoryMenuEl.hidden = !isOpen;
  if (isOpen) {
    const firstItem = filterHistoryMenuEl.querySelector('.query-history-item');
    if (firstItem) {
      firstItem.focus();
    } else {
      filterHistoryMenuEl.focus();
    }
    return;
  }
  if (document.activeElement && filterHistoryContainerEl.contains(document.activeElement)) {
    filterHistoryToggleEl.focus();
  }
}

function renderFilterHistory() {
  filterHistoryMenuEl.replaceChildren();

  const emptyState = document.createElement('div');
  emptyState.textContent = 'No previous queries';
  emptyState.className = 'filter-history-empty';
  emptyState.style.display = filterHistory.length ? 'none' : 'block';
  filterHistoryMenuEl.appendChild(emptyState);

  filterHistory.forEach((query) => {
    const queryOption = document.createElement('button');
    queryOption.type = 'button';
    queryOption.className = 'query-history-item';
    queryOption.dataset.query = query;
    queryOption.innerHTML = renderHighlightedQuery(query);
    filterHistoryMenuEl.appendChild(queryOption);
  });
  setHistoryMenuOpen(false);
}

function addFilterHistory(query) {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) return;
  const existingIndex = filterHistory.indexOf(normalizedQuery);
  if (existingIndex !== -1) {
    filterHistory.splice(existingIndex, 1);
  }
  filterHistory.unshift(normalizedQuery);
  renderFilterHistory();
}

function runFilterQuery(filterQuery) {
  filteredPackets = filterPackets(capturedPackets, filterQuery);
  writeLogEntry(`User executed query="${filterQuery}"`);

  if (filteredPackets === undefined || filteredPackets.length === 0) {
    hideAllData();
    statusUpdate('Status: No packets match the filter criteria');
    writeLogEntry('User query returned 0 packets');
  } else {
    statusUpdate(
      'Status: Displaying ' +
        filteredPackets.length +
        ' packets matching filter',
    );
    writeLogEntry(`User query returned packets=${filteredPackets.length}`);
    handlePacketNavigation('filtered', null);
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
          logErrorEntry('json-parse', e);
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
    writeLogEntry(`Hosts targeted discovered count=${hostsList.length - 1}`);
    const timeframe = getPacketTimeframe();
    if (timeframe) {
      writeLogEntry(
        `Packet timeframe start="${timeframe.first}" end="${timeframe.last}"`,
      );
    }
    writeLogEntry(`Total packet count=${totalPacketCount()}`);
    writeSummary();
    initializeDataView();
  };
  reader.onerror = (error) => {
    status.textContent = 'Status: Error reading file: ' + error;
    logErrorEntry('file-read', error);
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
  writeLogEntry(`Host target changed host=${selected}`);
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
  writeLogEntry(
    `Host target clicked host=${selected} packets_returned=${filteredPackets.length}`,
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
    document.getElementById('packetInfoPane').style.display = 'none';
    document.getElementById('packetPayloadPane').style.display = 'none';
    document.getElementById('stats_box').style.display = 'none';
    document.getElementById('list_box').style.display = 'none';
    document.getElementById('summary_content').textContent =
      finalSummary || 'No LLM summary available.';
    document.getElementById('summary_box').style.display = 'block';
    fileLoaded(true);
  }
}

function normalizeStatsTextValue(value, options = {}) {
  if (value === null || value === undefined) return null;

  const { stripNonPrintable = false } = options;
  let normalized = typeof value === 'string' ? value : String(value);

  if (stripNonPrintable) {
    normalized = normalized.replace(/[\x00-\x1F\x7F]/g, '');
  }

  normalized = normalized.trim();
  return normalized ? normalized : null;
}

function normalizeStatsPortValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const normalizedText = normalizeStatsTextValue(value);
  if (!normalizedText || !/^\d+$/.test(normalizedText)) return null;
  return Number(normalizedText);
}

/**
 * Iterates all packets in capturedPackets and returns aggregate statistics
 * useful for understanding what is in the capture at a glance.
 */
function buildCaptureStats() {
  const protocols = new Set();
  const transportProtocols = new Set();
  const hosts = new Set();
  const ports = new Set();
  const macVendors = new Set();
  const mimeTypes = new Set();
  const locations = new Map(); // "City, Country" -> count
  const hostnames = new Set();
  const dataTypes = new Set();
  let encryptedCount = 0;
  let unencryptedCount = 0;
  let totalPackets = 0;

  if (!capturedPackets || !capturedPackets['Host']) return null;

  for (const host of Object.keys(capturedPackets['Host'])) {
    const normalizedHostKey = normalizeStatsTextValue(host);
    if (normalizedHostKey) hosts.add(normalizedHostKey);
    const packets = capturedPackets['Host'][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      totalPackets++;
      const pi = pkt?.['Packet Info'];
      const ei = pkt?.['Extra Info'];
      if (!pi || !ei) continue;

      // Transport protocol (TCP/UDP/ICMP)
      const tp = normalizeStatsTextValue(pi['Protocol']);
      if (tp) transportProtocols.add(tp);

      // Source/destination IPs
      const srcIp = normalizeStatsTextValue(pi?.['IP']?.['Source IP']);
      const dstIp = normalizeStatsTextValue(pi?.['IP']?.['Destination IP']);
      if (srcIp) hosts.add(srcIp);
      if (dstIp) hosts.add(dstIp);

      // MAC vendors
      const ef = pi?.['Ethernet Frame'];
      if (ef) {
        const srcVendor = normalizeStatsTextValue(ef['MAC Source Vendor']);
        const dstVendor = normalizeStatsTextValue(ef['MAC Destination Vendor']);
        if (srcVendor) macVendors.add(srcVendor);
        if (dstVendor) macVendors.add(dstVendor);
      }

      // Port-level protocol name and ports
      const netData = ei?.['Traits']?.['Network Data'];
      if (netData) {
        const protoName = normalizeStatsTextValue(netData['Port Protcol']);
        if (protoName && protoName !== 'Unknown') protocols.add(protoName);

        // Source/dest ports
        const tpData = tp ? pi[tp] : null;
        if (tpData) {
          const srcPort = normalizeStatsPortValue(tpData['Source port']);
          const dstPort = normalizeStatsPortValue(tpData['Destination port']);
          if (srcPort !== null) ports.add(srcPort);
          if (dstPort !== null) ports.add(dstPort);
        }

        // Hostnames
        const hn = netData?.['Hostnames']?.['Hostnames'];
        if (Array.isArray(hn)) {
          hn.forEach((h) => {
            const normalizedHostname = normalizeStatsTextValue(h);
            if (normalizedHostname) hostnames.add(normalizedHostname);
          });
        }

        // Locations
        for (const side of ['Source IP', 'Destination IP']) {
          const loc = netData?.[side]?.['Location'];
          const city = normalizeStatsTextValue(loc?.['City']);
          const country = normalizeStatsTextValue(loc?.['Country']);
          if (city && country) {
            const key = `${city}, ${country}`;
            locations.set(key, (locations.get(key) || 0) + 1);
          }
        }
      }

      // MIME types
      const mimeType = normalizeStatsTextValue(ei?.['MIME Type']);
      if (mimeType) mimeTypes.add(mimeType);

      // Data types
      const dt = ei?.['Data Types'];
      if (Array.isArray(dt)) {
        dt.forEach((d) => {
          const normalizedDataType = normalizeStatsTextValue(d, {
            stripNonPrintable: true,
          });
          if (normalizedDataType) dataTypes.add(normalizedDataType);
        });
      }

      // Encryption
      const encData = ei?.['Traits']?.['Server Info']?.['Encryption Data'];
      if (!encData || encData === 'N/A') {
        unencryptedCount++;
      } else {
        encryptedCount++;
      }
    }
  }

  return {
    protocols: [...protocols].sort(),
    transportProtocols: [...transportProtocols].sort(),
    hosts: [...hosts].sort(),
    ports: [...ports].sort((a, b) => a - b),
    macVendors: [...macVendors].filter((v) => v !== 'N/A').sort(),
    mimeTypes: [...mimeTypes].sort(),
    locations: [...locations.entries()].sort((a, b) => b[1] - a[1]),
    hostnames: [...hostnames].sort(),
    dataTypes: [...dataTypes].sort(),
    encryptedCount,
    unencryptedCount,
    totalPackets,
  };
}

/**
 * Renders a section of tags that, when clicked, populate the filter bar
 * with a suggested query for that value.
 */
function makeStatsSection(title, items, queryBuilder) {
  if (!items || items.length === 0) return null;
  const normalizedItems = Array.from(
    new Set(
      items.filter((item) => {
        if (item === null || item === undefined) return false;
        if (typeof item !== 'string') return true;
        return normalizeStatsTextValue(item) !== null;
      }),
    ),
  );
  if (normalizedItems.length === 0) return null;

  const section = document.createElement('div');
  section.className = 'stats-section';

  const heading = document.createElement('div');
  heading.className = 'stats-section-title';
  heading.textContent = title;
  section.appendChild(heading);

  const tagList = document.createElement('div');
  tagList.className = 'stats-tag-list';

  normalizedItems.forEach((item) => {
    const tag = document.createElement('span');
    tag.className = 'stats-tag';
    tag.textContent = item;
    tag.title = 'Click to use in filter query';
    if (queryBuilder) {
      tag.addEventListener('click', () => {
        const query = queryBuilder(item);
        if (query) {
          filterInputEl.value = query;
          syncFilterHighlight();
          filterInputEl.focus();
          statusUpdate('Status: Filter query populated — press Enter to apply');
          writeLogEntry(`Stats tag clicked query="${query}"`);
        }
      });
    }
    tagList.appendChild(tag);
  });

  section.appendChild(tagList);
  return section;
}

/**
 * Shows the capture stats panel with aggregated data from the loaded capture.
 */
function showStats() {
  if (jsonCapture === '') {
    statusUpdate('Status: No JSON file loaded, please upload a file first');
    return;
  }
  statusUpdate('Status: Displaying capture statistics');
  writeLogEntry('User opened capture stats view');

  document.getElementById('packetInfoPane').style.display = 'none';
  document.getElementById('packetPayloadPane').style.display = 'none';
  document.getElementById('summary_box').style.display = 'none';
  document.getElementById('list_box').style.display = 'none';
  document.getElementById('stats_box').style.display = 'block';

  const content = document.getElementById('stats_content');
  content.replaceChildren();

  const stats = buildCaptureStats();
  if (!stats) {
    content.textContent = 'No packet data available.';
    return;
  }

  // Overview row
  const overview = document.createElement('div');
  overview.className = 'stats-section';
  const ovHead = document.createElement('div');
  ovHead.className = 'stats-section-title';
  ovHead.textContent = 'Capture Overview';
  overview.appendChild(ovHead);
  [
    `Total Packets: ${stats.totalPackets}`,
    `Unique Hosts Targeted: ${stats.hosts.length}`,
    `Encrypted Packets: ${stats.encryptedCount}`,
    `Unencrypted Packets: ${stats.unencryptedCount}`,
    `Unique Protocols: ${stats.protocols.length}`,
    `Unique Locations: ${stats.locations.length}`,
  ].forEach((line) => {
    const kv = document.createElement('div');
    kv.className = 'stats-kv';
    kv.textContent = line;
    overview.appendChild(kv);
  });
  content.appendChild(overview);

  // Application protocols
  const protoSec = makeStatsSection(
    'Application Protocols',
    stats.protocols,
    (v) => `tcp.proto: ${v.toLowerCase()}`,
  );
  if (protoSec) content.appendChild(protoSec);

  // Transport protocols
  const tpSec = makeStatsSection(
    'Transport Protocols',
    stats.transportProtocols,
    (v) => `wire.proto: ${v.toLowerCase()}`,
  );
  if (tpSec) content.appendChild(tpSec);

  // All hosts
  const hostSec = makeStatsSection(
    'All Hosts Addressed',
    stats.hosts,
    (v) => `ip.src.addr: ${v} || ip.dst.addr: ${v}`,
  );
  if (hostSec) content.appendChild(hostSec);

  // Hostnames / DNS
  const hnSec = makeStatsSection(
    'Hostnames (DNS)',
    stats.hostnames,
    (v) => `dns.qname: ${v}`,
  );
  if (hnSec) content.appendChild(hnSec);

  // Physical locations
  if (stats.locations.length > 0) {
    const locItems = stats.locations.map(([place, count]) => `${place} (${count})`);
    const locSec = makeStatsSection(
      'Physical Locations',
      locItems,
      null,
    );
    if (locSec) content.appendChild(locSec);
  }

  // Ports
  const portSec = makeStatsSection(
    'Ports Seen',
    stats.ports.map(String),
    (v) => `tcp.src.port: ${v} || tcp.dst.port: ${v}`,
  );
  if (portSec) content.appendChild(portSec);

  // MAC vendors
  const macSec = makeStatsSection(
    'MAC Vendors',
    stats.macVendors,
    (v) => `eth.src.vendor: ${v}`,
  );
  if (macSec) content.appendChild(macSec);

  // MIME types
  const mimeSec = makeStatsSection(
    'MIME Types',
    stats.mimeTypes,
    (v) => `mime.type: ${v}`,
  );
  if (mimeSec) content.appendChild(mimeSec);

  // Data types
  const dtSec = makeStatsSection(
    'Data Types',
    stats.dataTypes,
    null,
  );
  if (dtSec) content.appendChild(dtSec);
}

// Show host data when data button is clicked
document.getElementById('data-btn').addEventListener('click', function () {
  //highlightTab("data-navAction");
  initializeDataView();
});

// Show capture stats when stats button is clicked
document.getElementById('stats-btn').addEventListener('click', function () {
  showStats();
});

// Show packet list when list button is clicked
document.getElementById('list-btn').addEventListener('click', function () {
  showPacketList();
});

/**
 * Builds and shows the packet list tab, displaying all packets grouped by host
 * in a scrollable, selectable table.
 */
function showPacketList() {
  if (jsonCapture === '') {
    statusUpdate('Status: No JSON file loaded, please upload a file first');
    return;
  }
  statusUpdate('Status: Displaying packet list');
  writeLogEntry('User opened packet list view');

  document.getElementById('packetInfoPane').style.display = 'none';
  document.getElementById('packetPayloadPane').style.display = 'none';
  document.getElementById('summary_box').style.display = 'none';
  document.getElementById('stats_box').style.display = 'none';
  const listBox = document.getElementById('list_box');
  listBox.style.display = 'flex';

  const content = document.getElementById('list_content');
  const searchEl = document.getElementById('list-search');
  const groupByStreamEl = document.getElementById('list-group-streams');
  const columnDefinitions = [
    { label: '#', key: 'idx' },
    { label: '★', key: 'isBookmarked' },
    { label: 'Stream', key: 'streamOrder' },
    { label: 'Host', key: 'host' },
    { label: 'Src IP', key: 'srcIp' },
    { label: 'Dst IP', key: 'dstIp' },
    { label: 'Src Port', key: 'srcPort' },
    { label: 'Dst Port', key: 'dstPort' },
    { label: 'Transport', key: 'transport' },
    { label: 'App Protocol', key: 'appProto' },
  ];
  const sortState = { key: 'idx', direction: 'asc' };

  function buildTable(filterText) {
    content.replaceChildren();
    if (!capturedPackets || !capturedPackets['Host']) {
      content.textContent = 'No packet data available.';
      return;
    }

    const hosts = Object.keys(capturedPackets['Host']).sort();
    const lc = filterText ? filterText.toLowerCase() : '';

    const rows = [];

    const getStreamKey = (packetInfo) => {
      const transportName = packetInfo?.['Protocol'] || 'TCP';
      const transportData = packetInfo?.[transportName] || {};
      const sourceIp = packetInfo?.['IP']?.['Source IP'] ?? '';
      const destinationIp = packetInfo?.['IP']?.['Destination IP'] ?? '';
      const sourcePort = transportData?.['Source port'] ?? '';
      const destinationPort = transportData?.['Destination port'] ?? '';

      const endpointA = `${sourceIp}:${sourcePort}`;
      const endpointB = `${destinationIp}:${destinationPort}`;
      const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
      return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
    };

    for (const host of hosts) {
      const packets = capturedPackets['Host'][host];
      if (!Array.isArray(packets)) continue;

      packets.forEach((pkt, pktIdx) => {
        const pi = pkt?.['Packet Info'];
        const ei = pkt?.['Extra Info'];
        if (!pi) return;

        const idx = pi['Index'] ?? pktIdx + 1;
        const srcIp = pi?.['IP']?.['Source IP'] ?? '';
        const dstIp = pi?.['IP']?.['Destination IP'] ?? '';
        const transport = pi['Protocol'] || 'TCP';
        const tpData = pi[transport] || null;
        const srcPort = tpData?.['Source port'] ?? '';
        const dstPort = tpData?.['Destination port'] ?? '';
        const netData = ei?.['Traits']?.['Network Data'];
        const appProto =
          netData?.['Port Protocol'] ?? netData?.['Port Protcol'] ?? '';
        const packetKey = srcIp + ':' + pi['Index'];
        const isBookmarked = bookmarkList.includes(packetKey);
        const streamKey = getStreamKey(pi);

        if (lc) {
          const rowText = [host, srcIp, dstIp, String(srcPort), String(dstPort), transport, appProto].join(' ').toLowerCase();
          if (!rowText.includes(lc)) return;
        }

        rows.push({
          idx,
          host,
          srcIp,
          dstIp,
          srcPort,
          dstPort,
          transport,
          appProto,
          pktIdx,
          pi,
          streamKey,
          isBookmarked,
        });
      });
    }

    const streamOrderMap = new Map();
    let nextStreamOrder = 1;
    rows.forEach((row) => {
      if (!streamOrderMap.has(row.streamKey)) {
        streamOrderMap.set(row.streamKey, nextStreamOrder++);
      }
      row.streamOrder = streamOrderMap.get(row.streamKey);
      row.streamLabel = `S${row.streamOrder}`;
    });

    const activeGroupByStream = document.getElementById('list-group-streams')?.checked;
    const sortDirection = sortState.direction === 'asc' ? 1 : -1;
    const compareText = (left, right) => String(left ?? '').localeCompare(String(right ?? ''));
    const comparePortValue = (left, right) => {
      const leftNum = Number(left);
      const rightNum = Number(right);
      const leftIsNumber = Number.isFinite(leftNum);
      const rightIsNumber = Number.isFinite(rightNum);
      if (leftIsNumber && rightIsNumber) return leftNum - rightNum;
      return compareText(left, right);
    };

    const compareByColumn = (left, right, columnKey) => {
      switch (columnKey) {
        case 'idx':
        case 'streamOrder':
          return Number(left[columnKey]) - Number(right[columnKey]);
        case 'isBookmarked':
          return Number(left.isBookmarked) - Number(right.isBookmarked);
        case 'srcPort':
        case 'dstPort':
          return comparePortValue(left[columnKey], right[columnKey]);
        default:
          return compareText(left[columnKey], right[columnKey]);
      }
    };

    rows.sort((left, right) => {
      if (activeGroupByStream && sortState.key !== 'streamOrder') {
        const streamDiff = left.streamOrder - right.streamOrder;
        if (streamDiff !== 0) return streamDiff;
      }

      const sortedDiff = compareByColumn(left, right, sortState.key);
      if (sortedDiff !== 0) return sortedDiff * sortDirection;
      return Number(left.idx) - Number(right.idx);
    });

    const table = document.createElement('table');
    table.className = 'packet-list-table';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    columnDefinitions.forEach((column) => {
      const th = document.createElement('th');
      const isActiveSort = sortState.key === column.key;
      const sortArrow = isActiveSort
        ? sortState.direction === 'asc'
          ? ' ▲'
          : ' ▼'
        : '';
      th.textContent = column.label + sortArrow;
      th.classList.add('packet-list-sortable-header');
      th.tabIndex = 0;
      th.title = `Sort by ${column.label}`;
      th.setAttribute(
        'aria-sort',
        isActiveSort
          ? sortState.direction === 'asc'
            ? 'ascending'
            : 'descending'
          : 'none',
      );
      const sortByColumn = () => {
        if (sortState.key === column.key) {
          sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
        } else {
          sortState.key = column.key;
          sortState.direction = 'asc';
        }
        buildTable(document.getElementById('list-search')?.value || '');
      };
      th.addEventListener('click', sortByColumn);
      th.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          sortByColumn();
        }
      });
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');

    if (rows.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = columnDefinitions.length;
      td.textContent = filterText ? 'No packets match the filter.' : 'No packets available.';
      td.style.textAlign = 'center';
      td.style.padding = '12px';
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      let previousStreamLabel = '';
      rows.forEach((row) => {
        const tr = document.createElement('tr');
        tr.dataset.host = row.host;
        tr.dataset.pktIdx = row.pktIdx;
        tr.dataset.stream = row.streamLabel;

        if (activeGroupByStream && previousStreamLabel !== '' && previousStreamLabel !== row.streamLabel) {
          tr.classList.add('packet-list-stream-break');
        }
        previousStreamLabel = row.streamLabel;

        [
          row.idx,
          row.isBookmarked ? '★' : '',
          row.streamLabel,
          row.host,
          row.srcIp,
          row.dstIp,
          row.srcPort,
          row.dstPort,
          row.transport,
          row.appProto,
        ].forEach((val) => {
          const td = document.createElement('td');
          td.textContent = val ?? '';
          tr.appendChild(td);
        });

        tr.addEventListener('mouseenter', () => {
          tr.classList.add('packet-list-hovered');
        });
        tr.addEventListener('mouseleave', () => {
          tr.classList.remove('packet-list-hovered');
        });

        tr.addEventListener('click', () => {
          // Remove previous selection
          tbody.querySelectorAll('.packet-list-selected').forEach((r) => r.classList.remove('packet-list-selected'));
          tr.classList.add('packet-list-selected');

          // Navigate to selected packet
          hostFilterEl.value = row.host;
          document.getElementById('target_hosts').value = row.host;
          packetsForHost = capturedPackets['Host'][row.host];
          index = row.pktIdx;
          currentIp = row.srcIp;
          currentPacketKey = row.srcIp + ':' + row.pi['Index'];
          syncBookmarkDropdown(currentPacketKey);

          // Switch to Host Data view
          document.getElementById('list_box').style.display = 'none';
          document.getElementById('packetInfoPane').style.display = 'block';
          document.getElementById('packetPayloadPane').style.display = 'block';
          document.getElementById('prev-btn').style.display = 'block';
          document.getElementById('next-btn').style.display = 'block';
          showAllData();

          infoPanel(packetsForHost);
          const hexPayload = packetsForHost[index]?.['Packet Info']?.['Raw data']?.['Payload']?.['Hex Encoded'];
          if (hexPayload) popHexGrid(hexPayload);
          populateDataTypes(packetsForHost);
          statusUpdate('Status: Displaying packet ' + row.pi['Index'] + ' for host ' + row.host);
          writeLogEntry(`Packet list row selected host=${row.host} index=${row.pi['Index']}`);
        });

        tbody.appendChild(tr);
      });
    }

    table.appendChild(tbody);
    content.appendChild(table);
  }

  buildTable(searchEl.value);

  // Re-register search listener (replace old one)
  const newSearch = searchEl.cloneNode(true);
  searchEl.parentNode.replaceChild(newSearch, searchEl);
  newSearch.addEventListener('input', () => buildTable(newSearch.value));
  if (groupByStreamEl) {
    const newGroupByStream = groupByStreamEl.cloneNode(true);
    groupByStreamEl.parentNode.replaceChild(newGroupByStream, groupByStreamEl);
    newGroupByStream.addEventListener('change', () => buildTable(newSearch.value));
  }
}

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
    logCurrentPacketDisplay('prev');
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
  logCurrentPacketDisplay('next');
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
      writeLogEntry(`Bookmark added key=${currentPacketKey}`);
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
  document.getElementById('stats_box').style.display = 'none';
  document.getElementById('list_box').style.display = 'none';
  document.getElementById('packetInfoPane').style.display = 'block';
  document.getElementById('packetPayloadPane').style.display = 'block';
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
    writeLogEntry(`Filtered packet navigation packets_returned=${packetSet.length}`);
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
      writeLogEntry(
        `Navigating bookmark host=${navBookmark['Host']} packet=${navBookmark['Packet']}`,
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
    logCurrentPacketDisplay(navAction || 'first-load');
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
      logErrorEntry('save-json', result.error || 'unknown');
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
  writeLogEntry('Backend JSON payload received for processing');
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
  const fileLabel = typeof file === 'string' ? file : file?.name || 'unknown';
  writeLogEntry(
    `Backend analysis started file=${fileLabel} llm_enabled=${useLLM}`,
  );
  window.snitchapi
    .runBackendCommand(file, useLLM)
    .then((output) => {})
    .catch((error) => {
      doError('Backend run error!');
      logErrorEntry('backend-run', error);
    });
}

function doError(message) {
  console.error('Error from backend:', message);
  writeLogEntry(`Error shown message="${message}"`);
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
      const filterQuery = filterInputEl.value;
      addFilterHistory(filterQuery);
      runFilterQuery(filterQuery);
      setHistoryMenuOpen(false);
    }
  });

filterInputEl.addEventListener('input', syncFilterHighlight);
filterInputEl.addEventListener('scroll', syncFilterHighlightScroll);

filterHistoryToggleEl.addEventListener('click', () => {
  setHistoryMenuOpen(filterHistoryMenuEl.hidden);
});

filterHistoryMenuEl.addEventListener('click', (event) => {
  const selectedItem = event.target.closest('.query-history-item');
  if (!selectedItem) return;
  const selectedQuery = selectedItem.dataset.query;
  if (!selectedQuery) return;
  filterInputEl.value = selectedQuery;
  syncFilterHighlight();
  renderFilterHistory();
  runFilterQuery(selectedQuery);
  setHistoryMenuOpen(false);
});

document.addEventListener('click', (event) => {
  if (!filterHistoryMenuEl.hidden && !filterHistoryContainerEl.contains(event.target)) {
    setHistoryMenuOpen(false);
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !filterHistoryMenuEl.hidden) {
    setHistoryMenuOpen(false);
  }
});

syncFilterHighlight();

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
