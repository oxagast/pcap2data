function createCryptPanel({
  constants,
  getCapturedPackets,
  getJsonCapture,
  setActiveMainTab,
  setActiveCryptSubtab,
  statusUpdate,
  writeLogEntry,
  doError,
  logErrorEntry,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  addSessionKeystoreEntry,
  getFirstLineOrFallback,
}) {
  const {
    MAIN_TAB_CRYPT,
    CRYPT_SSL_SUBTAB,
    CRYPT_PGP_SUBTAB,
    CRYPT_OPENSSH_SUBTAB,
    SESSION_KEYCHAIN_LABEL,
    STRICT_IPV4_REGEX,
  } = constants;

  let cryptEncounteredEntries = [];
  let cryptActiveEntryIndex = -1;

  function formatCryptSummary(rawText, label, sourceLabel, expectedRegex) {
    const normalized = (rawText || "").trim();
    if (!normalized) {
      return `No ${label.toLowerCase()} loaded.`;
    }

    const lines = normalized.split(/\r?\n/);
    const beginMatch = normalized.match(/-----BEGIN ([^-]+)-----/);
    const endMatch = normalized.match(/-----END ([^-]+)-----/);
    const blockType = beginMatch ? beginMatch[1] : "Plain text";
    const looksExpected =
      !expectedRegex || (beginMatch && expectedRegex.test(blockType));

    return [
      `${label} loaded from ${sourceLabel}.`,
      `Bytes: ${new TextEncoder().encode(normalized).length}`,
      `Lines: ${lines.length}`,
      `Detected block type: ${blockType}`,
      beginMatch && endMatch
        ? `PEM boundaries: ${beginMatch[1]} ... ${endMatch[1]}`
        : "PEM boundaries not detected",
      looksExpected
        ? "Format check: looks valid for this input type"
        : "Format check: unexpected block type for this input",
    ].join("\n");
  }

  function getCryptEncounteredEntries() {
    const entries = [];
    const capturedPackets = getCapturedPackets();
    if (
      !capturedPackets ||
      typeof capturedPackets !== "object" ||
      !capturedPackets["Host"]
    ) {
      return entries;
    }

    for (const host of Object.keys(capturedPackets["Host"])) {
      const packets = capturedPackets["Host"][host];
      if (!Array.isArray(packets)) continue;

      packets.forEach((packet) => {
        const packetInfo = packet?.["Packet Info"];
        const extraInfo = packet?.["Extra Info"];
        const serverInfo = extraInfo?.["Traits"]?.["Server Info"];
        const encryptionData = serverInfo?.["Encryption Data"];
        if (!packetInfo || !serverInfo || !encryptionData || encryptionData === "N/A")
          return;

        const protocol = packetInfo["Protocol"] || "Unknown";
        const transportData = packetInfo[protocol] || {};
        const encryptedWithRaw = encryptionData["Encrypted With"];
        const encryptedWith = Array.isArray(encryptedWithRaw)
          ? encryptedWithRaw.filter(Boolean)
          : encryptedWithRaw
            ? [String(encryptedWithRaw)]
            : [];
        entries.push({
          host,
          packetIndex: packetInfo["Index"] ?? "?",
          protocol,
          srcIp: packetInfo?.["IP"]?.["Source IP"] ?? "N/A",
          dstIp: packetInfo?.["IP"]?.["Destination IP"] ?? "N/A",
          srcPort: transportData?.["Source port"] ?? "N/A",
          dstPort: transportData?.["Destination port"] ?? "N/A",
          encrypted: serverInfo["Encrypted"] ?? "Unknown",
          sslVersion: encryptionData["SSL Version"] ?? "Unknown",
          sslCert: encryptionData["SSL Cert"] ?? "",
          encryptedWith,
        });
      });
    }

    return entries.sort((a, b) => {
      const aIdx = Number(a.packetIndex);
      const bIdx = Number(b.packetIndex);
      if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
      return String(a.packetIndex).localeCompare(String(b.packetIndex));
    });
  }

  function renderCryptEncounteredDetails(entry) {
    const detailsEl = document.getElementById("crypt-encountered-details");
    if (!entry) {
      detailsEl.textContent = "Select an encountered SSL/TLS item to inspect.";
      return;
    }
    const algoText = entry.encryptedWith.length
      ? entry.encryptedWith.join(", ")
      : "Unavailable";
    detailsEl.textContent = [
      `Host: ${entry.host}`,
      `Packet: ${entry.packetIndex}`,
      `Protocol: ${entry.protocol}`,
      `Path: ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort}`,
      `Encrypted: ${entry.encrypted}`,
      `SSL/TLS Version: ${entry.sslVersion}`,
      `Algorithms: ${algoText}`,
    ].join("\n");
  }

  function refreshCryptEncounteredEntries() {
    const listEl = document.getElementById("crypt-encountered-list");
    cryptEncounteredEntries = getCryptEncounteredEntries();
    listEl.replaceChildren();
    cryptActiveEntryIndex = -1;

    if (cryptEncounteredEntries.length === 0) {
      const option = document.createElement("option");
      option.textContent = "No SSL/TLS encryption encountered in loaded capture.";
      option.disabled = true;
      listEl.appendChild(option);
      renderCryptEncounteredDetails(null);
      return;
    }

    cryptEncounteredEntries.forEach((entry, entryIndex) => {
      const option = document.createElement("option");
      option.value = String(entryIndex);
      const algoPreview = entry.encryptedWith.length
        ? entry.encryptedWith[0]
        : "Unknown cipher";
      option.textContent = `#${entry.packetIndex} ${entry.sslVersion} ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort} (${algoPreview})`;
      listEl.appendChild(option);
    });

    listEl.selectedIndex = 0;
    cryptActiveEntryIndex = 0;
    renderCryptEncounteredDetails(cryptEncounteredEntries[0]);
  }

  function setCryptSubtab(tabName) {
    setActiveCryptSubtab(tabName);
    const sslActive = tabName === CRYPT_SSL_SUBTAB;
    const pgpActive = tabName === CRYPT_PGP_SUBTAB;
    const opensshActive = tabName === CRYPT_OPENSSH_SUBTAB;
    document.getElementById("crypt-subtab-ssl").classList.toggle("active", sslActive);
    document.getElementById("crypt-subtab-pgp").classList.toggle("active", pgpActive);
    document
      .getElementById("crypt-subtab-openssh")
      .classList.toggle("active", opensshActive);
    document.getElementById("crypt-ssl-panel").hidden = !sslActive;
    document.getElementById("crypt-pgp-panel").hidden = !pgpActive;
    document.getElementById("crypt-openssh-panel").hidden = !opensshActive;
  }

  function applyCryptCertificateText(rawText, sourceLabel) {
    const certInputEl = document.getElementById("crypt-cert-input");
    const certPreviewEl = document.getElementById("crypt-cert-preview");
    const normalized = (rawText || "").trim();
    certInputEl.value = normalized;
    certPreviewEl.textContent = formatCryptSummary(
      normalized,
      "Certificate",
      sourceLabel,
      /CERTIFICATE/i,
    );
    if (normalized) {
      statusUpdate(`Status: Certificate loaded from ${sourceLabel}`);
      writeLogEntry(`Crypt certificate loaded source="${sourceLabel}"`);
      if (sourceLabel !== SESSION_KEYCHAIN_LABEL) {
        addSessionKeystoreEntry({
          type: "certificate",
          label: getFirstLineOrFallback(
            "crypt-cert-preview",
            `Certificate-${new Date().toISOString()}`,
          ),
          source: `cert-tab ${sourceLabel}`,
          content: normalized,
          summary: "Imported into cert tab",
        });
      }
    }
  }

  function applyCryptPrivateKeyText(rawText, sourceLabel) {
    const keyInputEl = document.getElementById("crypt-key-input");
    const keyPreviewEl = document.getElementById("crypt-key-preview");
    const normalized = (rawText || "").trim();
    keyInputEl.value = normalized;
    keyPreviewEl.textContent = formatCryptSummary(
      normalized,
      "Private key",
      sourceLabel,
      /(PRIVATE KEY|OPENSSH)/i,
    );
    if (normalized) {
      statusUpdate(`Status: Private key loaded from ${sourceLabel}`);
      writeLogEntry(`Crypt private key loaded source="${sourceLabel}"`);
      if (sourceLabel !== SESSION_KEYCHAIN_LABEL) {
        addSessionKeystoreEntry({
          type: "private-key",
          label: getFirstLineOrFallback(
            "crypt-key-preview",
            `Private-key-${new Date().toISOString()}`,
          ),
          source: `cert-tab ${sourceLabel}`,
          content: normalized,
          summary: "Imported into cert tab",
        });
      }
    }
  }

  function readCryptTextFile(fileInputEl, onLoad) {
    const file = fileInputEl.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onLoad(String(reader.result || ""), `file ${file.name}`);
    reader.onerror = (error) => {
      logErrorEntry("crypt-file-read", error);
      doError("Could not read selected crypt file.");
    };
    reader.readAsText(file);
  }

  function applyCryptFilterForActiveEntry() {
    if (cryptActiveEntryIndex < 0 || !cryptEncounteredEntries[cryptActiveEntryIndex]) {
      statusUpdate("Status: Select an encountered SSL/TLS entry first");
      return;
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    if (
      !STRICT_IPV4_REGEX.test(String(activeEntry.srcIp || "")) ||
      !STRICT_IPV4_REGEX.test(String(activeEntry.dstIp || ""))
    ) {
      statusUpdate("Status: Cannot build filter query for non-IPv4 packet endpoints");
      return;
    }
    const query = `ip.src.addr: ${activeEntry.srcIp} && ip.dst.addr: ${activeEntry.dstIp}`;
    filterInputEl.value = query;
    syncFilterHighlight();
    runFilterQuery(query);
    writeLogEntry(`Crypt filter applied query="${query}"`);
  }

  function loadEncounteredCertificateIntoCrypt() {
    if (cryptActiveEntryIndex < 0 || !cryptEncounteredEntries[cryptActiveEntryIndex]) {
      statusUpdate("Status: Select an encountered SSL/TLS entry first");
      return;
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    if (!activeEntry.sslCert || activeEntry.sslCert === "Not available") {
      statusUpdate("Status: No certificate text available for selected entry");
      return;
    }
    applyCryptCertificateText(
      String(activeEntry.sslCert),
      `encountered packet #${activeEntry.packetIndex}`,
    );
  }

  function selectEncounteredEntry(selectedIndex) {
    if (!Number.isFinite(selectedIndex) || !cryptEncounteredEntries[selectedIndex]) {
      return;
    }
    cryptActiveEntryIndex = selectedIndex;
    renderCryptEncounteredDetails(cryptEncounteredEntries[selectedIndex]);
  }

  function showCryptWorkspace(tabName = CRYPT_SSL_SUBTAB) {
    setActiveMainTab(MAIN_TAB_CRYPT);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("Please upload a JSON file before accessing crypt tools.");
      return;
    }

    statusUpdate("Status: Displaying crypt workspace");
    writeLogEntry("User opened crypt workspace");
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("list_box").style.display = "none";
    document.getElementById("keystore_box").style.display = "none";
    document.getElementById("rightside").style.display = "none";
    const cryptBoxEl = document.getElementById("crypt_box");
    cryptBoxEl.style.display = "flex";
    setCryptSubtab(tabName);
    refreshCryptEncounteredEntries();
  }

  return {
    setCryptSubtab,
    showCryptWorkspace,
    refreshCryptEncounteredEntries,
    readCryptTextFile,
    applyCryptCertificateText,
    applyCryptPrivateKeyText,
    applyCryptFilterForActiveEntry,
    loadEncounteredCertificateIntoCrypt,
    selectEncounteredEntry,
  };
}

module.exports = {
  id: "crypt",
  createCryptPanel,
};
