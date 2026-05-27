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
  syncBookmarkDropdown,
  setActivePacketCursor,
  showAllData,
  infoPanel,
  popHexGrid,
  populateDataTypes,
}) {
  const { MAIN_TAB_LIST } = constants;

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

  function showPacketList() {
    setActiveMainTab(MAIN_TAB_LIST);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      return;
    }
    statusUpdate("Status: Displaying packet list");
    writeLogEntry("User opened packet list view");

    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("prev-btn").style.display = "none";
    document.getElementById("next-btn").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("crypt_box").style.display = "none";
    document.getElementById("keystore_box").style.display = "none";
    document.getElementById("rightside").style.display = "none";
    const listBox = document.getElementById("list_box");
    listBox.style.display = "flex";

    const content = document.getElementById("list_content");
    const searchEl = document.getElementById("list-search");
    const groupByStreamEl = document.getElementById("list-group-streams");
    const columnDefinitions = [
      { label: "#", key: "idx" },
      { label: "★", key: "isBookmarked" },
      { label: "Stream", key: "streamOrder" },
      { label: "Host", key: "host" },
      { label: "Src IP", key: "srcIp" },
      { label: "Dst IP", key: "dstIp" },
      { label: "Src Port", key: "srcPort" },
      { label: "Dst Port", key: "dstPort" },
      { label: "Transport", key: "transport" },
      { label: "App Protocol", key: "appProto" },
    ];
    const sortState = { key: "idx", direction: "asc" };

    function buildTable(filterText) {
      content.replaceChildren();
      const capturedPackets = getCapturedPackets();
      if (!capturedPackets || !capturedPackets["Host"]) {
        content.textContent = "No packet data available.";
        return;
      }

      const hosts = Object.keys(capturedPackets["Host"]).sort();
      const lc = filterText ? filterText.toLowerCase() : "";

      const rows = [];

      const getStreamKey = (packetInfo) => {
        const transportName = packetInfo?.["Protocol"] || "Unknown";
        const transportData = packetInfo?.[transportName] || {};
        const sourceIp = packetInfo?.["IP"]?.["Source IP"] ?? "";
        const destinationIp = packetInfo?.["IP"]?.["Destination IP"] ?? "";
        const sourcePort = transportData?.["Source port"] ?? "";
        const destinationPort = transportData?.["Destination port"] ?? "";

        const endpointA = `${sourceIp}:${sourcePort}`;
        const endpointB = `${destinationIp}:${destinationPort}`;
        const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
        return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
      };

      for (const host of hosts) {
        const packets = capturedPackets["Host"][host];
        if (!Array.isArray(packets)) continue;

        packets.forEach((pkt, pktIdx) => {
          const pi = pkt?.["Packet Info"];
          const ei = pkt?.["Extra Info"];
          if (!pi) return;

          const idx = pi["Index"] ?? pktIdx + 1;
          const srcIp = pi?.["IP"]?.["Source IP"] ?? "";
          const dstIp = pi?.["IP"]?.["Destination IP"] ?? "";
          const transport = pi["Protocol"] || "TCP";
          const tpData = pi[transport] || null;
          const srcPort = tpData?.["Source port"] ?? "";
          const dstPort = tpData?.["Destination port"] ?? "";
          const netData = ei?.["Traits"]?.["Network Data"];
          const appProto =
            netData?.["Port Protocol"] ?? netData?.["Port Protcol"] ?? "";
          const packetKey = srcIp + ":" + pi["Index"];
          const isBookmarked = getBookmarkList().includes(packetKey);
          const streamKey = getStreamKey(pi);

          if (lc) {
            const rowText = [
              host,
              srcIp,
              dstIp,
              String(srcPort),
              String(dstPort),
              transport,
              appProto,
            ]
              .join(" ")
              .toLowerCase();
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

      const activeGroupByStream =
        document.getElementById("list-group-streams")?.checked;
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
          case "streamOrder":
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

      const table = document.createElement("table");
      table.className = "packet-list-table";

      const thead = document.createElement("thead");
      const headerRow = document.createElement("tr");
      columnDefinitions.forEach((column) => {
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
        headerRow.appendChild(th);
      });
      thead.appendChild(headerRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");

      if (rows.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = columnDefinitions.length;
        td.textContent = filterText
          ? "No packets match the filter."
          : "No packets available.";
        td.style.textAlign = "center";
        td.style.padding = "12px";
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else {
        let previousStreamLabel = "";
        rows.forEach((row) => {
          const tr = document.createElement("tr");
          tr.dataset.host = row.host;
          tr.dataset.pktIdx = row.pktIdx;
          tr.dataset.stream = row.streamLabel;

          if (
            activeGroupByStream &&
            previousStreamLabel !== "" &&
            previousStreamLabel !== row.streamLabel
          ) {
            tr.classList.add("packet-list-stream-break");
          }
          previousStreamLabel = row.streamLabel;

          [
            row.idx,
            row.isBookmarked ? "★" : "",
            row.streamLabel,
            row.host,
            row.srcIp,
            row.dstIp,
            row.srcPort,
            row.dstPort,
            row.transport,
            row.appProto,
          ].forEach((val) => {
            const td = document.createElement("td");
            td.textContent = val ?? "";
            tr.appendChild(td);
          });

          tr.addEventListener("mouseenter", () => {
            tr.classList.add("packet-list-hovered");
          });
          tr.addEventListener("mouseleave", () => {
            tr.classList.remove("packet-list-hovered");
          });

          tr.addEventListener("click", () => {
            tbody
              .querySelectorAll(".packet-list-selected")
              .forEach((r) => r.classList.remove("packet-list-selected"));
            tr.classList.add("packet-list-selected");

            hostFilterEl.value = row.host;
            document.getElementById("target_hosts").value = row.host;
            setCurrentIp(row.srcIp);
            setCurrentPacketKey(row.srcIp + ":" + row.pi["Index"]);
            syncBookmarkDropdown(row.srcIp + ":" + row.pi["Index"]);
            writeLogEntry(
              `Packet list row selected host=${row.host} index=${row.pi["Index"]}`,
            );

            const streamFilter = buildStreamFilterQuery(
              row.transport, row.srcIp, row.dstIp, row.srcPort, row.dstPort,
            );
            if (streamFilter) {
              filterInputEl.value = streamFilter;
              syncFilterHighlight();
              runFilterQuery(streamFilter);
              setPacketsForHost(getFilteredPackets());
            } else {
              const capturedPackets = getCapturedPackets();
              const hostPackets = capturedPackets["Host"][row.host];
              setPacketsForHost(hostPackets);
              setIndex(row.pktIdx);
              setActivePacketCursor(row.pktIdx);
              document.getElementById("list_box").style.display = "none";
              document.getElementById("data_tools_box").style.display = "none";
              document.getElementById("crypt_box").style.display = "none";
              document.getElementById("keystore_box").style.display = "none";
              document.getElementById("packetInfoPane").style.display = "block";
              document.getElementById("packetPayloadPane").style.display = "block";
              showAllData();
              infoPanel(hostPackets);
              const hexPayload =
                hostPackets[row.pktIdx]?.["Packet Info"]?.["Raw data"]?.[
                  "Payload"
                ]?.["Hex Encoded"];
              if (hexPayload) popHexGrid(hexPayload);
              populateDataTypes(hostPackets);
            }

            statusUpdate(
              "Status: Displaying packet " +
                row.pi["Index"] +
                " for host " +
                row.host,
            );
          });

          tbody.appendChild(tr);
        });
      }

      table.appendChild(tbody);
      content.appendChild(table);
    }

    buildTable(searchEl.value);

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
