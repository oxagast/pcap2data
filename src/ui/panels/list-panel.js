
const threadName = "List";
const LIST_COLUMN_MIN_WIDTH = 48;
const LIST_COLUMN_MAX_WIDTH = 640;

// Returns whether unknown like protocol.
function isUnknownLikeProtocol(value) {
  if (value === null || value === undefined) return true;
  const normalized = String(value).trim().toLowerCase();
  return (
    normalized === "" ||
    normalized === "unknown" ||
    normalized === "n/a" ||
    normalized === "na" ||
    normalized === "none" ||
    normalized === "unavailable" ||
    normalized === "null"
  );
}

// Returns whether protocol like field name.
function isProtocolLikeFieldName(fieldName, fieldValue) {
  if (fieldName.includes(".")) return false;
  if (!fieldValue || typeof fieldValue !== "object") return false;
  if (Array.isArray(fieldValue)) return false;
  // Exclude transport metadata objects such as "TCP Flag Data".
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(fieldName)) return false;
  return true;
}

// Collects decoded protocol names.
function collectDecodedProtocolNames(packetInfo) {
  const decodedNames = new Set();
  const packetDecodedValues = [
    packetInfo?.["packet.decoded_protocols"] ?? packetInfo?.["Decoded Protocols"],
    packetInfo?.["packet.decoded_protocols"],
  ];
  packetDecodedValues.forEach((packetDecoded) => {
    if (Array.isArray(packetDecoded)) {
      packetDecoded.forEach((name) => {
        if (typeof name === "string" && name.trim()) {
          decodedNames.add(name.trim());
        }
      });
      return;
    }
    if (typeof packetDecoded === "string" && packetDecoded.trim()) {
      decodedNames.add(packetDecoded.trim());
    }
  });

  const sectionNames = ["TCP", "UDP", "ICMP", "IGMP", "LINK", "IP"];
  sectionNames.forEach((sectionName) => {
    const section = packetInfo?.[sectionName];
    if (!section || typeof section !== "object") return;
    Object.entries(section).forEach(([fieldName, fieldValue]) => {
      if (isProtocolLikeFieldName(fieldName, fieldValue)) {
        decodedNames.add(fieldName);
      }
    });
  });

  return [...decodedNames];
}

function formatLayerOnlyLabel(baseLabel, layerName) {
  const normalizedBase = String(baseLabel ?? "").trim();
  const normalizedLayer = String(layerName ?? "").trim();
  if (!normalizedBase) return "";
  if (!normalizedLayer) return normalizedBase;
  return `${normalizedBase} (${normalizedLayer} Only)`;
}

function normalizeGenericApplicationProtocolLabel(label, packetProtocol) {
  const normalizedLabel = String(label ?? "").trim();
  const normalizedProtocol = String(packetProtocol ?? "").trim().toUpperCase();
  if (!normalizedLabel) return "";

  if (normalizedLabel.toUpperCase() === "TCP" || normalizedProtocol === "TCP" && normalizedLabel.toUpperCase() === normalizedProtocol) {
    return formatLayerOnlyLabel("TCP", "Transport");
  }
  if (normalizedLabel.toUpperCase() === "UDP" || normalizedProtocol === "UDP" && normalizedLabel.toUpperCase() === normalizedProtocol) {
    return formatLayerOnlyLabel("UDP", "Transport");
  }
  if (normalizedLabel.toUpperCase() === "SCTP" || normalizedProtocol === "SCTP" && normalizedLabel.toUpperCase() === normalizedProtocol) {
    return formatLayerOnlyLabel("SCTP", "Transport");
  }
  if (normalizedLabel.toUpperCase() === "ICMP" || normalizedProtocol === "ICMP" && normalizedLabel.toUpperCase() === normalizedProtocol) {
    return formatLayerOnlyLabel("ICMP", "Network");
  }
  if (normalizedLabel.toUpperCase() === "IGMP" || normalizedProtocol === "IGMP" && normalizedLabel.toUpperCase() === normalizedProtocol) {
    return formatLayerOnlyLabel("IGMP", "Network");
  }
  if (normalizedLabel.toUpperCase() === "LINK") {
    return formatLayerOnlyLabel("LINK", "Link");
  }
  if (normalizedLabel.toUpperCase() === "FRAME") {
    return formatLayerOnlyLabel("FRAME", "Link");
  }
  if (normalizedLabel.toUpperCase() === "IP" || normalizedLabel.toUpperCase() === "UNDECODABLE") {
    return formatLayerOnlyLabel("IP", "Network");
  }

  return normalizedLabel;
}

function inferZeroPayloadProtocolLabel(packetInfo) {
  const packetProtocol = String(
    packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "",
  ).trim().toUpperCase();

  if (packetProtocol === "TCP") {
    const tcpSection = packetInfo?.["TCP"] || {};
    const tcpFlags = String(
      tcpSection?.["TCP Flag Data"]?.["Flags"] ??
      tcpSection?.["tcp.flags"] ??
      tcpSection?.["transport.tcp.flags"] ??
      "",
    ).trim();
    if (tcpFlags && tcpFlags.toLowerCase() !== "none") {
      return formatLayerOnlyLabel(
        `TCP ${tcpFlags.replace(/\|+/g, "-")}`,
        "Transport",
      );
    }
    return formatLayerOnlyLabel("TCP control", "Transport");
  }

  if (packetProtocol === "UDP") return formatLayerOnlyLabel("UDP datagram", "Transport");
  if (packetProtocol === "SCTP") return formatLayerOnlyLabel("SCTP packet", "Transport");
  if (packetProtocol === "IGMP") return formatLayerOnlyLabel("IGMP control", "Network");
  if (packetProtocol === "LINK") return formatLayerOnlyLabel("Link-layer frame", "Link");
  if (packetProtocol === "FRAME") return formatLayerOnlyLabel("Frame", "Link");
  if (packetProtocol === "UNDECODABLE") return formatLayerOnlyLabel("IP packet", "Network");

  return "";
}

// Handles infer application protocol.
function inferApplicationProtocol(packetInfo, extraInfo) {
  const packetProtocol = String(packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "").trim().toLowerCase();
  if (packetProtocol === "undecodable") {
    return "Unknown protocol";
  }

  if (packetProtocol === "icmp") {
    const icmpSection = packetInfo?.["ICMP"] || {};
    const icmpTypeValue =
      icmpSection?.["icmp.type"] ??
      icmpSection?.["Type"] ??
      icmpSection?.["transport.icmp.type"];
    const icmpType = Number.parseInt(String(icmpTypeValue ?? ""), 10);
    const icmpTypeLabel = String(icmpTypeValue ?? "").toLowerCase();

    if (icmpType === 0 || icmpType === 8 || icmpTypeLabel.includes("echo")) {
      return "Ping";
    }

    if (
      icmpType === 3 ||
      icmpType === 11 ||
      icmpTypeLabel.includes("destination unreachable") ||
      icmpTypeLabel.includes("time exceeded")
    ) {
      return "Traceroute";
    }

    return "ICMP";
  }

  const netData = extraInfo?.["Traits"]?.["Network Data"];
  const fromTraitsRaw =
    netData?.["Port Protocol"] ??
    netData?.["Port Protcol"] ??
    "";
  const fromTraits =
    typeof fromTraitsRaw === "string" ? fromTraitsRaw.trim() : "";

  const decodedNames = collectDecodedProtocolNames(packetInfo);
  const preferred = [
    "SSH",
    "HTTP2",
    "HTTP",
    "WebSocket",
    "DNS",
    "TLS",
    "Kerberos",
    "NFS",
    "RADIUS",
  ];

  const decodedByLower = new Map(
    decodedNames.map((name) => [String(name).toLowerCase(), name]),
  );

  // List-tab precedence: decoded protocol evidence should override the
  // traits app protocol mapping when both are available.
  for (const name of preferred) {
    const matched = decodedByLower.get(name.toLowerCase());
    if (matched) return matched;
  }

  if (decodedNames.length > 0) {
    return normalizeGenericApplicationProtocolLabel(decodedNames[0], packetProtocol);
  }
  if (!isUnknownLikeProtocol(fromTraits)) {
    return normalizeGenericApplicationProtocolLabel(fromTraits, packetProtocol);
  }
  if (getPacketPayloadLength(packetInfo) === 0) {
    const zeroPayloadLabel = inferZeroPayloadProtocolLabel(packetInfo);
    if (zeroPayloadLabel) return zeroPayloadLabel;
  }
  return normalizeGenericApplicationProtocolLabel(packetProtocol || "Unknown protocol", packetProtocol);
}

// Returns packet payload length.
function getPacketPayloadLength(packetInfo) {
  const payloadLength = Number(packetInfo?.["raw.data"]?.["payload.len"] ?? packetInfo?.["Raw data"]?.["payload.len"] ?? packetInfo?.["Raw data"]?.["Payload Length"]);
  if (!Number.isFinite(payloadLength) || payloadLength < 0) return 0;
  return Math.floor(payloadLength);
}

// Handles clamp column width.
function clampColumnWidth(width) {
  const parsedWidth = Number.parseInt(String(width), 10);
  if (!Number.isFinite(parsedWidth)) return null;
  return Math.max(LIST_COLUMN_MIN_WIDTH, Math.min(LIST_COLUMN_MAX_WIDTH, parsedWidth));
}

// Creates list panel.
function createListPanel({
  constants,
  getJsonCapture,
  getCapturedPackets,
  getBookmarkList,
  setActiveMainTab,
  statusUpdate,
  writeLogEntry,
  hostFilterEl,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  getFilteredPackets,
  setPacketsForHost,
  setIndex,
  setCurrentIp,
  setCurrentPacketKey,
  getCurrentPacketKey,
  syncBookmarkDropdown,
  setActivePacketCursor,
  showAllData,
  infoPanel,
  popHexGrid,
  populateDataTypes,
  isCaptureStoreBackedCapture,
  getCurrentSettings,
  setCurrentSettings,
  getEnableUngroupedListVirtualization,
}) {
  const { MAIN_TAB_LIST } = constants;
  const VIRTUAL_LIST_THRESHOLD = 250;
  const VIRTUAL_LIST_OVERSCAN = 24;
  const VIRTUAL_LIST_ROW_HEIGHT = 28;

  let virtualListState = null;
  let virtualListScrollFrame = 0;
  let listPreferencesSaveChain = Promise.resolve();

  function loadListPreferences(columnDefinitions) {
    const defaultVisibility = Object.fromEntries(
      columnDefinitions.map((column) => [column.key, column.defaultVisible !== false]),
    );
    const defaultWidths = Object.fromEntries(
      columnDefinitions.map((column) => [column.key, clampColumnWidth(column.defaultWidth) || 120]),
    );
    const settings = typeof getCurrentSettings === "function" ? getCurrentSettings() : null;
    const savedListSettings = settings?.list && typeof settings.list === "object"
      ? settings.list
      : {};
    const savedVisibility = savedListSettings.columnVisibility && typeof savedListSettings.columnVisibility === "object"
      ? savedListSettings.columnVisibility
      : {};
    const savedWidths = savedListSettings.columnWidths && typeof savedListSettings.columnWidths === "object"
      ? savedListSettings.columnWidths
      : {};

    columnDefinitions.forEach((column) => {
      if (typeof savedVisibility[column.key] === "boolean") {
        defaultVisibility[column.key] = savedVisibility[column.key];
      }
      const savedWidth = clampColumnWidth(savedWidths[column.key]);
      if (savedWidth !== null) {
        defaultWidths[column.key] = savedWidth;
      }
    });

    return {
      columnVisibility: defaultVisibility,
      columnWidths: defaultWidths,
    };
  }

  function persistListPreferences(columnVisibility, columnWidths) {
    if (!window.settingsapi || typeof window.settingsapi.update !== "function") {
      return Promise.resolve(null);
    }
    const nextVisibility = Object.fromEntries(
      Object.entries(columnVisibility).filter(([, value]) => typeof value === "boolean"),
    );
    const nextWidths = Object.fromEntries(
      Object.entries(columnWidths)
        .map(([key, value]) => [key, clampColumnWidth(value)])
        .filter(([, value]) => value !== null),
    );

    listPreferencesSaveChain = listPreferencesSaveChain
      .catch(() => null)
      .then(async () => {
        const savedSettings = await window.settingsapi.update({
          list: {
            columnVisibility: nextVisibility,
            columnWidths: nextWidths,
          },
        });
        if (typeof setCurrentSettings === "function" && savedSettings) {
          setCurrentSettings(savedSettings);
        }
        return savedSettings;
      });

    return listPreferencesSaveChain;
  }

  function buildStreamFilterQuery(transport, srcIp, dstIp, srcPort, dstPort) {
    if (!srcIp || !dstIp) return null;
    const tp = (transport || "").toLowerCase();
    const hasPorts =
      (srcPort !== "" && srcPort !== undefined && srcPort !== null) &&
      (dstPort !== "" && dstPort !== undefined && dstPort !== null);
    if (hasPorts && (tp === "tcp" || tp === "udp")) {
      return (
        `(ip.src.addr: ${srcIp} && ip.dst.addr: ${dstIp} && ${tp}.src.port: ${srcPort} && ${tp}.dst.port: ${dstPort})` +
        ` || ` +
        `(ip.src.addr: ${dstIp} && ip.dst.addr: ${srcIp} && ${tp}.src.port: ${dstPort} && ${tp}.dst.port: ${srcPort})`
      );
    }
    return `(ip.src.addr: ${srcIp} && ip.dst.addr: ${dstIp}) || (ip.src.addr: ${dstIp} && ip.dst.addr: ${srcIp})`;
  }

  function clearVirtualListState() {
    if (virtualListState?.content && virtualListState.scrollHandler) {
      virtualListState.content.removeEventListener("scroll", virtualListState.scrollHandler);
    }
    virtualListState = null;
    if (virtualListScrollFrame) {
      window.cancelAnimationFrame(virtualListScrollFrame);
      virtualListScrollFrame = 0;
    }
  }

  function createSpacerRow(columnCount, pixelHeight) {
    const tr = document.createElement("tr");
    tr.className = "packet-list-spacer";
    const td = document.createElement("td");
    td.colSpan = columnCount;
    td.setAttribute("aria-hidden", "true");
    td.style.height = `${Math.max(0, pixelHeight)}px`;
    td.style.padding = "0";
    td.style.border = "0";
    td.style.lineHeight = "0";
    td.style.fontSize = "0";
    tr.appendChild(td);
    return tr;
  }

  function appendPacketRow(selectionContainer, appendTarget, row, columns, activeGroupByStream, previousStreamLabel) {
    const tr = document.createElement("tr");
    tr.dataset.host = row.host;
    tr.dataset.pktIdx = row.pktIdx;
    tr.dataset.stream = row.streamLabel;
    tr.dataset.packetKey = row.packetKey;

    if (row.packetKey === getCurrentPacketKey()) {
      tr.classList.add("packet-list-selected");
    }

    if (
      activeGroupByStream &&
      previousStreamLabel !== "" &&
      previousStreamLabel !== row.streamLabel
    ) {
      tr.classList.add("packet-list-stream-break");
    }

    columns.forEach((column) => {
      const td = document.createElement("td");
      td.textContent = String(column.getValue(row) ?? "");
      if (column.widthPx) {
        const columnWidth = `${column.widthPx}px`;
        td.style.width = columnWidth;
        td.style.minWidth = columnWidth;
      }
      tr.appendChild(td);
    });

    tr.addEventListener("mouseenter", () => {
      tr.classList.add("packet-list-hovered");
    });
    tr.addEventListener("mouseleave", () => {
      tr.classList.remove("packet-list-hovered");
    });

    tr.addEventListener("click", async () => {
      selectionContainer
        .querySelectorAll(".packet-list-selected")
        .forEach((r) => r.classList.remove("packet-list-selected"));
      tr.classList.add("packet-list-selected");

      hostFilterEl.value = row.host;
      document.getElementById("target_hosts").value = row.host;
      setCurrentIp(row.srcIp);
      setCurrentPacketKey(row.packetKey);
      syncBookmarkDropdown(row.packetKey);
      writeLogEntry(
        `[${threadName}] Packet list row selected host=${row.host} index=${row.idx}`,
      );

      const streamFilter = buildStreamFilterQuery(
        row.transport, row.srcIp, row.dstIp, row.srcPort, row.dstPort,
      );
      if (streamFilter) {
        filterInputEl.value = streamFilter;
        syncFilterHighlight();
        await runFilterQuery(streamFilter);
        setPacketsForHost(getFilteredPackets());
      } else {
        const capturedPackets = getCapturedPackets();
        const hostPackets = capturedPackets["host"][row.host];
        setPacketsForHost(hostPackets);
        setIndex(row.pktIdx);
        setActivePacketCursor(row.pktIdx);
        document.getElementById("list_box").style.display = "none";
        document.getElementById("data_tools_box").style.display = "none";
        document.getElementById("crypt_box").style.display = "none";
        document.getElementById("keystore_box").style.display = "none";
        document.getElementById("notes_box").style.display = "none";
        document.getElementById("packetInfoPane").style.display = "block";
        document.getElementById("packetPayloadPane").style.display = "block";
        const rightsideDataEl = document.getElementById("rightside-data");
        const rightsideNotesEl = document.getElementById("rightside-notes");
        if (rightsideDataEl) rightsideDataEl.hidden = false;
        if (rightsideNotesEl) rightsideNotesEl.hidden = true;
        showAllData();
        infoPanel(hostPackets);
        const hexPayload =
          hostPackets[row.pktIdx]?.["packet.info"]?.["Raw data"]?.[
          "Payload"
          ]?.["payload.hex"] ?? hostPackets[row.pktIdx]?.["packet.info"]?.["Raw data"]?.[
          "Payload"
          ]?.["Hex Encoded"];
        if (hexPayload) popHexGrid(hexPayload);
        populateDataTypes(hostPackets);
      }

      statusUpdate(
        "Status: Displaying packet " +
        row.idx +
        " for host " +
        row.host,
      );
    });

    appendTarget.appendChild(tr);
  }

  function renderVirtualRows() {
    if (!virtualListState) return;

    const {
      rows,
      tbody,
      content,
      columnCount,
      activeGroupByStream,
      onRendered,
      sourceBacked,
      visibleColumns,
    } = virtualListState;
    const rowHeight = virtualListState.rowHeight || VIRTUAL_LIST_ROW_HEIGHT;
    const viewportHeight = Math.max(0, content.clientHeight || 0);
    const scrollTop = Math.max(0, content.scrollTop || 0);
    const visibleCount = Math.max(
      1,
      Math.ceil(viewportHeight / rowHeight) + VIRTUAL_LIST_OVERSCAN * 2,
    );
    const totalCount = sourceBacked ? virtualListState.totalCount : rows.length;
    const desiredStartIndex = Math.max(
      0,
      Math.floor(scrollTop / rowHeight) - VIRTUAL_LIST_OVERSCAN,
    );
    const desiredEndIndex = Math.min(totalCount, desiredStartIndex + visibleCount);

    if (
      sourceBacked &&
      (
        desiredStartIndex < virtualListState.windowStart ||
        desiredEndIndex > virtualListState.windowEnd
      )
    ) {
      void loadSourceBackedListWindow(desiredStartIndex).then(() => {
        if (virtualListState) {
          renderVirtualRows();
        }
      });
      return;
    }

    const startIndex = sourceBacked
      ? Math.max(desiredStartIndex, virtualListState.windowStart)
      : desiredStartIndex;
    const endIndex = sourceBacked
      ? Math.min(desiredEndIndex, virtualListState.windowEnd)
      : Math.min(rows.length, startIndex + visibleCount);
    const fragment = document.createDocumentFragment();

    const windowStart = sourceBacked ? virtualListState.windowStart : 0;
    if (startIndex > windowStart) {
      fragment.appendChild(
        createSpacerRow(columnCount, (startIndex - windowStart) * rowHeight),
      );
    }

    const visibleRows = sourceBacked ? rows : rows.slice(startIndex, endIndex);
    const rowStartOffset = sourceBacked ? startIndex - windowStart : 0;
    const rowEndOffset = sourceBacked ? endIndex - windowStart : visibleRows.length;
    let previousStreamLabel =
      sourceBacked && startIndex > windowStart
        ? rows[startIndex - windowStart - 1]?.streamLabel || ""
        : startIndex > 0
          ? rows[startIndex - 1].streamLabel
          : "";
    for (let rowIndex = rowStartOffset; rowIndex < rowEndOffset; rowIndex += 1) {
      const row = visibleRows[rowIndex];
      appendPacketRow(
        tbody,
        fragment,
        row,
        visibleColumns,
        activeGroupByStream,
        previousStreamLabel,
      );
      previousStreamLabel = row.streamLabel;
    }

    if (endIndex < totalCount) {
      fragment.appendChild(
        createSpacerRow(columnCount, (totalCount - endIndex) * rowHeight),
      );
    }

    tbody.replaceChildren(fragment);

    const firstRow = tbody.querySelector("tr:not(.packet-list-spacer)");
    const measuredRowHeight = firstRow?.getBoundingClientRect().height || rowHeight;
    if (
      !virtualListState.rowHeightMeasured &&
      measuredRowHeight > 0 &&
      measuredRowHeight !== rowHeight
    ) {
      virtualListState.rowHeight = measuredRowHeight;
      virtualListState.rowHeightMeasured = true;
      renderVirtualRows();
      return;
    }
    virtualListState.rowHeightMeasured = true;

    if (typeof onRendered === "function") {
      onRendered();
    }
  }

  function scheduleVirtualRowsRender() {
    if (!virtualListState) return;
    if (virtualListScrollFrame) return;
    virtualListScrollFrame = window.requestAnimationFrame(() => {
      virtualListScrollFrame = 0;
      renderVirtualRows();
    });
  }

  async function loadSourceBackedListWindow(desiredStartIndex) {
    if (!virtualListState || !window.captureapi?.getListWindow) return;
    const totalCount = virtualListState.totalCount || 0;
    const rowHeight = virtualListState.rowHeight || VIRTUAL_LIST_ROW_HEIGHT;
    const viewportHeight = Math.max(0, virtualListState.content.clientHeight || 0);
    const visibleCount = Math.max(
      1,
      Math.ceil(viewportHeight / rowHeight) + VIRTUAL_LIST_OVERSCAN * 2,
    );
    const windowSize = Math.max(visibleCount * 2, 200);
    const windowStart = Math.max(
      0,
      Math.min(
        Math.max(0, totalCount - windowSize),
        desiredStartIndex - Math.floor(windowSize / 3),
      ),
    );

    const response = await window.captureapi.getListWindow({
      startIndex: windowStart,
      count: windowSize,
    });
    if (!response?.success || !virtualListState) return;

    const bookmarkSet = new Set(getBookmarkList());
    const normalizedRows = (Array.isArray(response.rows) ? response.rows : []).map((row) => ({
      ...row,
      pktIdx: Number.isFinite(Number(row?.pktIdx)) ? Number(row.pktIdx) : 0,
      pcapOrder: Number.isFinite(Number(row?.pcapOrder)) ? Number(row.pcapOrder) : 0,
      isBookmarked: bookmarkSet.has(String(row?.packetKey || "")),
      streamLabel:
        typeof row?.streamLabel === "string" && row.streamLabel.trim()
          ? row.streamLabel
          : Number.isFinite(Number(row?.streamOrder))
            ? `S${Number(row.streamOrder)}`
            : "",
    }));

    virtualListState.rows = normalizedRows;
    virtualListState.totalCount = Number(response.totalCount) || totalCount;
    virtualListState.windowStart = Number(response.startIndex) || 0;
    virtualListState.windowEnd =
      virtualListState.windowStart + virtualListState.rows.length;
  }

  function showPacketList() {
    setActiveMainTab(MAIN_TAB_LIST);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      return;
    }
    statusUpdate("Status: Displaying packet list");
    writeLogEntry(`[${threadName}] User opened packet list view`);

    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("prev-btn").style.display = "none";
    document.getElementById("next-btn").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("crypt_box").style.display = "none";
    document.getElementById("keystore_box").style.display = "none";
    document.getElementById("notes_box").style.display = "none";
    document.getElementById("rightside").style.display = "none";
    const listBox = document.getElementById("list_box");
    listBox.style.display = "flex";

    const content = document.getElementById("list_content");
    const searchEl = document.getElementById("list-search");
    const groupByStreamEl = document.getElementById("list-group-streams");
    const columnsMenuEl = document.getElementById("list-columns-menu");
    const columnsControlEl = document.getElementById("list-columns-control");
    const columnDefinitions = [
      { label: "#", key: "idx", defaultWidth: 64, getValue: (row) => row.idx },
      { label: "PCAP #", key: "pcapOrder", defaultWidth: 82, getValue: (row) => row.pcapOrder },
      { label: "★", key: "isBookmarked", defaultWidth: 46, getValue: (row) => row.isBookmarked ? "★" : "" },
      { label: "Stream", key: "streamOrder", defaultWidth: 78, getValue: (row) => row.streamLabel },
      { label: "Host", key: "host", defaultWidth: 180, getValue: (row) => row.host },
      { label: "Src IP", key: "srcIp", defaultWidth: 150, getValue: (row) => row.srcIp },
      { label: "Dst IP", key: "dstIp", defaultWidth: 150, getValue: (row) => row.dstIp },
      { label: "Src Port", key: "srcPort", defaultWidth: 96, getValue: (row) => row.srcPort },
      { label: "Dst Port", key: "dstPort", defaultWidth: 96, getValue: (row) => row.dstPort },
      { label: "Transport", key: "transport", defaultWidth: 110, getValue: (row) => row.transport },
      { label: "App Protocol", key: "appProto", defaultWidth: 170, getValue: (row) => row.appProto },
      { label: "Payload Len", key: "payloadLength", defaultWidth: 110, getValue: (row) => row.payloadLength },
    ];
    const sortState = { key: "idx", direction: "asc" };
    const loadedPreferences = loadListPreferences(columnDefinitions);
    let columnVisibility = loadedPreferences.columnVisibility;
    let columnWidths = loadedPreferences.columnWidths;

    const withRuntimeColumnState = (column) => ({
      ...column,
      widthPx: clampColumnWidth(columnWidths[column.key]) || clampColumnWidth(column.defaultWidth) || 120,
    });

    const getVisibleColumns = () => {
      const visibleColumns = columnDefinitions
        .filter((column) => columnVisibility[column.key] !== false)
        .map(withRuntimeColumnState);
      return visibleColumns.length > 0
        ? visibleColumns
        : [withRuntimeColumnState(columnDefinitions[0])];
    };

    const renderColumnVisibilityControls = () => {
      if (!columnsMenuEl) return;
      columnsMenuEl.replaceChildren();
      columnDefinitions.forEach((column) => {
        const optionLabel = document.createElement("label");
        optionLabel.className = "list-columns-option";
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = columnVisibility[column.key] !== false;
        checkbox.addEventListener("change", () => {
          const currentlyVisibleCount = columnDefinitions.filter(
            (candidate) => columnVisibility[candidate.key] !== false,
          ).length;
          if (!checkbox.checked && currentlyVisibleCount <= 1) {
            checkbox.checked = true;
            return;
          }
          columnVisibility[column.key] = checkbox.checked;
          void persistListPreferences(columnVisibility, columnWidths);
          buildTable(document.getElementById("list-search")?.value || "");
        });
        optionLabel.appendChild(checkbox);
        optionLabel.appendChild(document.createTextNode(column.label === "★" ? "Bookmarked" : column.label));
        columnsMenuEl.appendChild(optionLabel);
      });
    };

    renderColumnVisibilityControls();
    columnsControlEl?.removeAttribute("open");

    function buildTable(filterText) {
      clearVirtualListState();
      content.replaceChildren();
      const capturedPackets = getCapturedPackets();
      if (!capturedPackets || !capturedPackets["host"]) {
        content.textContent = "No packet data available.";
        return;
      }

      const hosts = Object.keys(capturedPackets["host"]).sort();
      const lc = filterText ? filterText.toLowerCase() : "";
      const visibleColumns = getVisibleColumns();
      const activeGroupByStream =
        document.getElementById("list-group-streams")?.checked;
      const ungroupedVirtualizationEnabled =
        typeof getEnableUngroupedListVirtualization === "function"
          ? Boolean(getEnableUngroupedListVirtualization())
          : false;

      const canUseSourceBackedList =
        Boolean(
          typeof isCaptureStoreBackedCapture === "function" &&
          isCaptureStoreBackedCapture() &&
          window.captureapi?.getListWindow &&
          !lc &&
          !activeGroupByStream &&
          sortState.key === "idx" &&
          sortState.direction === "asc",
        );

      if (canUseSourceBackedList) {
        const table = document.createElement("table");
        table.className = "packet-list-table";

        const thead = document.createElement("thead");
        const headerRow = document.createElement("tr");
        visibleColumns.forEach((column) => {
          const th = document.createElement("th");
          const isActiveSort = sortState.key === column.key;
          const sortArrow = isActiveSort
            ? sortState.direction === "asc"
              ? " ▲"
              : " ▼"
            : "";
          th.textContent = column.label + sortArrow;
          th.classList.add("packet-list-sortable-header");
          th.tabIndex = 0;
          th.title = `Sort by ${column.label}`;
          const columnWidth = `${column.widthPx}px`;
          th.style.width = columnWidth;
          th.style.minWidth = columnWidth;
          th.setAttribute(
            "aria-sort",
            isActiveSort
              ? sortState.direction === "asc"
                ? "ascending"
                : "descending"
              : "none",
          );
          const sortByColumn = () => {
            if (sortState.key === column.key) {
              sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
            } else {
              sortState.key = column.key;
              sortState.direction = "asc";
            }
            buildTable(document.getElementById("list-search")?.value || "");
          };
          th.addEventListener("click", sortByColumn);
          th.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              sortByColumn();
            }
          });
          const resizeHandle = document.createElement("span");
          resizeHandle.className = "packet-list-column-resize-handle";
          resizeHandle.title = `Resize ${column.label}`;
          resizeHandle.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
          });
          resizeHandle.addEventListener("pointerdown", (event) => {
            event.preventDefault();
            event.stopPropagation();
            const startX = event.clientX;
            const startWidth = column.widthPx;
            const pointerId = event.pointerId;
            const nextVisibleColumns = getVisibleColumns();
            const columnIndex = nextVisibleColumns.findIndex((entry) => entry.key === column.key);
            if (columnIndex < 0) return;
            const tableEl = th.closest("table");
            const bodyRows = Array.from(tableEl?.querySelectorAll("tbody tr") || []);
            const applyWidth = (nextWidth) => {
              const widthPx = clampColumnWidth(nextWidth) || startWidth;
              th.style.width = `${widthPx}px`;
              th.style.minWidth = `${widthPx}px`;
              bodyRows.forEach((rowEl) => {
                if (rowEl.classList.contains("packet-list-spacer")) return;
                const cell = rowEl.children[columnIndex];
                if (!cell) return;
                cell.style.width = `${widthPx}px`;
                cell.style.minWidth = `${widthPx}px`;
              });
              return widthPx;
            };
            let lastWidth = startWidth;
            const onPointerMove = (moveEvent) => {
              lastWidth = applyWidth(startWidth + (moveEvent.clientX - startX));
            };
            const finishResize = () => {
              window.removeEventListener("pointermove", onPointerMove);
              window.removeEventListener("pointerup", onPointerUp);
              window.removeEventListener("pointercancel", onPointerUp);
              try {
                resizeHandle.releasePointerCapture(pointerId);
              } catch (_error) {
                // Ignore pointer capture release failures.
              }
              columnWidths = {
                ...columnWidths,
                [column.key]: lastWidth,
              };
              void persistListPreferences(columnVisibility, columnWidths);
              buildTable(document.getElementById("list-search")?.value || "");
            };
            const onPointerUp = () => finishResize();
            try {
              resizeHandle.setPointerCapture(pointerId);
            } catch (_error) {
              // Ignore pointer capture failures and continue with window listeners.
            }
            window.addEventListener("pointermove", onPointerMove);
            window.addEventListener("pointerup", onPointerUp, { once: true });
            window.addEventListener("pointercancel", onPointerUp, { once: true });
          });
          th.appendChild(resizeHandle);
          headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        const loadingRow = document.createElement("tr");
        const loadingCell = document.createElement("td");
        loadingCell.colSpan = visibleColumns.length;
        loadingCell.textContent = "Loading packet list...";
        loadingCell.style.textAlign = "center";
        loadingCell.style.padding = "12px";
        loadingRow.appendChild(loadingCell);
        tbody.appendChild(loadingRow);
        table.appendChild(tbody);
        content.appendChild(table);

        virtualListState = {
          rows: [],
          totalCount: 0,
          windowStart: 0,
          windowEnd: 0,
          tbody,
          content,
          columnCount: visibleColumns.length,
          activeGroupByStream: false,
          visibleColumns,
          rowHeight: VIRTUAL_LIST_ROW_HEIGHT,
          rowHeightMeasured: false,
          sourceBacked: true,
          onRendered: null,
        };

        const scrollHandler = () => scheduleVirtualRowsRender();
        virtualListState.scrollHandler = scrollHandler;
        content.addEventListener("scroll", scrollHandler, { passive: true });

        void loadSourceBackedListWindow(0).then(() => {
          if (virtualListState) {
            renderVirtualRows();
          }
        });
        return;
      }

      const rows = [];

      const getStreamKey = (packetInfo) => {
        const transportName = packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "Unknown";
        const transportData = packetInfo?.[transportName] || {};
        const sourceIp = packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "";
        const destinationIp = packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "";
        const sourcePort =
          transportData?.["tcp.src.port"] ??
          transportData?.["udp.src.port"] ??
          transportData?.["sctp.src.port"] ??
          transportData?.["Source port"] ??
          "";
        const destinationPort =
          transportData?.["tcp.dst.port"] ??
          transportData?.["udp.dst.port"] ??
          transportData?.["sctp.dst.port"] ??
          transportData?.["Destination port"] ??
          "";

        const endpointA = `${sourceIp}:${sourcePort}`;
        const endpointB = `${destinationIp}:${destinationPort}`;
        const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
        return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
      };

      for (const host of hosts) {
        const packets = capturedPackets["host"][host];
        if (!Array.isArray(packets)) continue;

        packets.forEach((pkt, pktIdx) => {
          const pi = pkt?.["packet.info"];
          const ei = pkt?.["extra.info"];
          if (!pi) return;

          const idx = pi["index"] ?? pi["Index"] ?? pktIdx + 1;
          const pcapOrderRaw = Number(pi["packet.processed"]);
          const pcapOrder = Number.isFinite(pcapOrderRaw) ? pcapOrderRaw + 1 : idx;
          const srcIp = pi?.["IP"]?.["ip.src.addr"] ?? pi?.["IP"]?.["Source IP"] ?? "";
          const dstIp = pi?.["IP"]?.["ip.dst.addr"] ?? pi?.["IP"]?.["Destination IP"] ?? "";
          const transport = pi["packet.proto"] ?? pi["Protocol"] ?? "TCP";
          const tpData = pi[transport] || null;
          const srcPort =
            tpData?.["tcp.src.port"] ??
            tpData?.["udp.src.port"] ??
            tpData?.["sctp.src.port"] ??
            tpData?.["Source port"] ??
            "";
          const dstPort =
            tpData?.["tcp.dst.port"] ??
            tpData?.["udp.dst.port"] ??
            tpData?.["sctp.dst.port"] ??
            tpData?.["Destination port"] ??
            "";
          const appProto = inferApplicationProtocol(pi, ei);
          const payloadLength = getPacketPayloadLength(pi);
          const packetKey = srcIp + ":" + (pi["index"] ?? pi["Index"] ?? pktIdx + 1);
          const isBookmarked = getBookmarkList().includes(packetKey);
          const streamKey = getStreamKey(pi);

          if (lc) {
            const rowText = [
              String(pcapOrder),
              host,
              srcIp,
              dstIp,
              String(srcPort),
              String(dstPort),
              transport,
              appProto,
              String(payloadLength),
            ]
              .join(" ")
              .toLowerCase();
            if (!rowText.includes(lc)) return;
          }

          rows.push({
            idx,
            pcapOrder,
            host,
            srcIp,
            dstIp,
            srcPort,
            dstPort,
            transport,
            appProto,
            payloadLength,
            pktIdx,
            streamKey,
            isBookmarked,
            packetKey: srcIp + ":" + (pi["index"] ?? pi["Index"] ?? pktIdx + 1),
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

      const sortDirection = sortState.direction === "asc" ? 1 : -1;
      const compareText = (left, right) =>
        String(left ?? "").localeCompare(String(right ?? ""));
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
          case "idx":
          case "pcapOrder":
          case "streamOrder":
          case "payloadLength":
            return Number(left[columnKey]) - Number(right[columnKey]);
          case "isBookmarked":
            return Number(left.isBookmarked) - Number(right.isBookmarked);
          case "srcPort":
          case "dstPort":
            return comparePortValue(left[columnKey], right[columnKey]);
          default:
            return compareText(left[columnKey], right[columnKey]);
        }
      };

      rows.sort((left, right) => {
        if (activeGroupByStream && sortState.key !== "streamOrder") {
          const streamDiff = left.streamOrder - right.streamOrder;
          if (streamDiff !== 0) return streamDiff;
        }

        const sortedDiff = compareByColumn(left, right, sortState.key);
        if (sortedDiff !== 0) return sortedDiff * sortDirection;
        return Number(left.idx) - Number(right.idx);
      });

      const shouldVirtualizeRows =
        rows.length > VIRTUAL_LIST_THRESHOLD &&
        (activeGroupByStream || ungroupedVirtualizationEnabled);

      const table = document.createElement("table");
      table.className = "packet-list-table";

      const thead = document.createElement("thead");
      const headerRow = document.createElement("tr");
      visibleColumns.forEach((column) => {
        const th = document.createElement("th");
        const isActiveSort = sortState.key === column.key;
        const sortArrow = isActiveSort
          ? sortState.direction === "asc"
            ? " ▲"
            : " ▼"
          : "";
        th.textContent = column.label + sortArrow;
        th.classList.add("packet-list-sortable-header");
        th.tabIndex = 0;
        th.title = `Sort by ${column.label}`;
        const columnWidth = `${column.widthPx}px`;
        th.style.width = columnWidth;
        th.style.minWidth = columnWidth;
        th.setAttribute(
          "aria-sort",
          isActiveSort
            ? sortState.direction === "asc"
              ? "ascending"
              : "descending"
            : "none",
        );
        const sortByColumn = () => {
          if (sortState.key === column.key) {
            sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
          } else {
            sortState.key = column.key;
            sortState.direction = "asc";
          }
          buildTable(document.getElementById("list-search")?.value || "");
        };
        th.addEventListener("click", sortByColumn);
        th.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            sortByColumn();
          }
        });
        const resizeHandle = document.createElement("span");
        resizeHandle.className = "packet-list-column-resize-handle";
        resizeHandle.title = `Resize ${column.label}`;
        resizeHandle.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
        });
        resizeHandle.addEventListener("pointerdown", (event) => {
          event.preventDefault();
          event.stopPropagation();
          const startX = event.clientX;
          const startWidth = column.widthPx;
          const pointerId = event.pointerId;
          const nextVisibleColumns = getVisibleColumns();
          const columnIndex = nextVisibleColumns.findIndex((entry) => entry.key === column.key);
          if (columnIndex < 0) return;
          const tableEl = th.closest("table");
          const bodyRows = Array.from(tableEl?.querySelectorAll("tbody tr") || []);
          const applyWidth = (nextWidth) => {
            const widthPx = clampColumnWidth(nextWidth) || startWidth;
            th.style.width = `${widthPx}px`;
            th.style.minWidth = `${widthPx}px`;
            bodyRows.forEach((rowEl) => {
              if (rowEl.classList.contains("packet-list-spacer")) return;
              const cell = rowEl.children[columnIndex];
              if (!cell) return;
              cell.style.width = `${widthPx}px`;
              cell.style.minWidth = `${widthPx}px`;
            });
            return widthPx;
          };
          let lastWidth = startWidth;
          const onPointerMove = (moveEvent) => {
            lastWidth = applyWidth(startWidth + (moveEvent.clientX - startX));
          };
          const finishResize = () => {
            window.removeEventListener("pointermove", onPointerMove);
            window.removeEventListener("pointerup", onPointerUp);
            window.removeEventListener("pointercancel", onPointerUp);
            try {
              resizeHandle.releasePointerCapture(pointerId);
            } catch (_error) {
              // Ignore pointer capture release failures.
            }
            columnWidths = {
              ...columnWidths,
              [column.key]: lastWidth,
            };
            void persistListPreferences(columnVisibility, columnWidths);
            buildTable(document.getElementById("list-search")?.value || "");
          };
          const onPointerUp = () => finishResize();
          try {
            resizeHandle.setPointerCapture(pointerId);
          } catch (_error) {
            // Ignore pointer capture failures and continue with window listeners.
          }
          window.addEventListener("pointermove", onPointerMove);
          window.addEventListener("pointerup", onPointerUp, { once: true });
          window.addEventListener("pointercancel", onPointerUp, { once: true });
        });
        th.appendChild(resizeHandle);
        headerRow.appendChild(th);
      });
      thead.appendChild(headerRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");

      if (rows.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = visibleColumns.length;
        td.textContent = filterText
          ? "No packets match the filter."
          : "No packets available.";
        td.style.textAlign = "center";
        td.style.padding = "12px";
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else if (shouldVirtualizeRows) {
        table.dataset.virtualized = "true";
        const renderState = {
          rows,
          tbody,
          content,
          columnCount: visibleColumns.length,
          activeGroupByStream,
          visibleColumns,
          rowHeight: VIRTUAL_LIST_ROW_HEIGHT,
          rowHeightMeasured: false,
          onRendered: null,
        };
        virtualListState = renderState;
        renderState.onRendered = () => {
          if (!virtualListState) return;
          const selectedRow = tbody.querySelector(".packet-list-selected");
          if (selectedRow) {
            selectedRow.scrollIntoView({ block: "nearest" });
          }
        };
        const scrollHandler = () => scheduleVirtualRowsRender();
        renderState.scrollHandler = scrollHandler;
        content.addEventListener("scroll", scrollHandler, { passive: true });
        content.scrollTop = 0;
      } else {
        let previousStreamLabel = "";
        rows.forEach((row) => {
          appendPacketRow(
            tbody,
            tbody,
            row,
            visibleColumns,
            activeGroupByStream,
            previousStreamLabel,
          );
          previousStreamLabel = row.streamLabel;
        });
      }

      table.appendChild(tbody);
      content.appendChild(table);

      if (shouldVirtualizeRows) {
        renderVirtualRows();
      }
    }
    if (getCapturedPackets() && Object.keys(getCapturedPackets()["host"]).length > 1) {
      buildTable(searchEl.value);
    }

    const newSearch = searchEl.cloneNode(true);
    searchEl.parentNode.replaceChild(newSearch, searchEl);
    newSearch.addEventListener("input", () => buildTable(newSearch.value));
    if (groupByStreamEl) {
      const newGroupByStream = groupByStreamEl.cloneNode(true);
      groupByStreamEl.parentNode.replaceChild(newGroupByStream, groupByStreamEl);
      newGroupByStream.addEventListener("change", () =>
        buildTable(newSearch.value),
      );
    }
  }

  return {
    showPacketList,
  };
}

module.exports = {
  id: "list",
  createListPanel,
};
