const convertContextMenuMarkup = `
  <div id="ctx-copy-submenu" class="ctx-submenu">
    <button id="ctx-copy-branch" class="ctx-branch" type="button">Copy...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-copy" role="menuitem">Copy</button>
      <button id="convert-context-copy-hex" type="button">Copy Hex</button>
      <button id="convert-context-copy-ascii" type="button">Copy ASCII</button>
      <button id="convert-context-copy-raw" type="button">Copy Raw</button>
      <button id="ctx-copy-cookie-jar" role="menuitem">Copy Cookie Jar</button>
    </div>
  </div>
  <button id="ctx-paste" role="menuitem">Paste</button>
  <hr id="convert-context-divider" class="ctx-divider" />
  <div id="ctx-convert-submenu" class="ctx-submenu">
    <button id="ctx-convert-branch" class="ctx-branch" type="button">Convert to...</button>
    <div class="ctx-submenu-panel">
      <button id="convert-context-hex" type="button">as Hex</button>
      <button id="convert-context-binary" type="button">as Binary</button>
      <button id="convert-context-base64" type="button">as Base64</button>
      <button id="convert-context-decimal" type="button">as Decimal bytes</button>
      <button id="convert-context-ascii" type="button">as ASCII / UTF-8</button>
      <button id="convert-context-derive-guess" type="button">Derive Type</button>
      <button id="convert-context-load-cursor-ascii" type="button">Cursor ASCII to Conv tab</button>
      <button id="convert-context-load-payload" type="button">Raw Payload to Conv tab</button>
      <button id="convert-context-decompress-conv" type="button">Decompress to Conv tab</button>
      <button id="convert-context-load-file" type="button">Import File</button>
    </div>
  </div>
  <div id="ctx-follow-stream-submenu" class="ctx-submenu">
    <button id="ctx-follow-stream-branch" class="ctx-branch" type="button">Follow stream...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-follow-stream-conv" type="button">Stream to Conv tab</button>
      <button id="ctx-follow-stream-conv-decompress" type="button">Stream to Conv tab (decompressed)</button>
      <button id="ctx-follow-stream-crypt" type="button">Stream to Crypt tab</button>
    </div>
  </div>
  <div id="ctx-notes-submenu" class="ctx-submenu">
    <button id="ctx-notes-branch" class="ctx-branch" type="button">Send to Notes...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-notes-send-data" type="button">Selected/context data</button>
      <button id="ctx-notes-send-list-packet" type="button">List row visible data</button>
      <button id="ctx-notes-send-conv-input" type="button">Conv input (current format)</button>
      <button id="ctx-notes-send-conv-hex" type="button">Conv output (hex)</button>
      <button id="ctx-notes-send-conv-ascii" type="button">Conv output (ASCII)</button>
      <button id="ctx-notes-send-conv-base64" type="button">Conv output (base64)</button>
      <button id="ctx-notes-send-conv-hashes" type="button">Conv hashes</button>
    </div>
  </div>
  <div id="ctx-filter-submenu" class="ctx-submenu">
    <button id="ctx-filter-branch" class="ctx-branch" type="button">Add to filter...</button>
    <div class="ctx-submenu-panel">
      <div id="ctx-filter-and-submenu" class="ctx-submenu">
        <button id="ctx-filter-and-branch" class="ctx-branch" type="button">Add with &&...</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-filter-ip" type="button">Add IP</button>
          <button id="ctx-filter-port" type="button">Add Port</button>
          <button id="ctx-filter-mac" type="button">Add MAC</button>
          <button id="ctx-filter-link-protocol" type="button">Add Link Proto</button>
          <button id="ctx-filter-wire-protocol" type="button">Add Transport Proto</button>
          <button id="ctx-filter-app-protocol" type="button">Add Application Proto</button>
          <button id="ctx-filter-protocol" type="button">Add Both Protos</button>
          <button id="ctx-filter-mime" type="button">Add MIME</button>
        </div>
      </div>
      <div id="ctx-filter-or-submenu" class="ctx-submenu">
        <button id="ctx-filter-or-branch" class="ctx-branch" type="button">Add with ||...</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-filter-or-ip" type="button">Add IP</button>
          <button id="ctx-filter-or-port" type="button">Add Port</button>
          <button id="ctx-filter-or-mac" type="button">Add MAC</button>
          <button id="ctx-filter-or-link-protocol" type="button">Add Link Proto</button>
          <button id="ctx-filter-or-wire-protocol" type="button">Add Transport Proto</button>
          <button id="ctx-filter-or-app-protocol" type="button">Add Application Proto</button>
          <button id="ctx-filter-or-protocol" type="button">Add Both Protos</button>
          <button id="ctx-filter-or-mime" type="button">Add MIME</button>
        </div>
      </div>
      <div id="ctx-filter-not-submenu" class="ctx-submenu">
        <button id="ctx-filter-not-branch" class="ctx-branch" type="button">is not...</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-filter-not-ip" type="button">Add IP</button>
          <button id="ctx-filter-not-port" type="button">Add Port</button>
          <button id="ctx-filter-not-mac" type="button">Add MAC</button>
          <button id="ctx-filter-not-link-protocol" type="button">Add Link Proto</button>
          <button id="ctx-filter-not-wire-protocol" type="button">Add Transport Proto</button>
          <button id="ctx-filter-not-app-protocol" type="button">Add Application Proto</button>
          <button id="ctx-filter-not-protocol" type="button">Add Both Protos</button>
          <button id="ctx-filter-not-mime" type="button">Add MIME</button>
        </div>
      </div>
      <div id="ctx-filter-parentheses-submenu" class="ctx-submenu">
        <button id="ctx-filter-parentheses-branch" class="ctx-branch" type="button">Parentheses...</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-filter-paren-open" type="button">Append (</button>
          <button id="ctx-filter-paren-close" type="button">Append )</button>
          <button id="ctx-filter-paren-wrap" type="button">Wrap with (...)</button>
        </div>
      </div>
      <hr class="ctx-divider" />
      <div id="ctx-filter-clear-submenu" class="ctx-submenu">
        <button id="ctx-filter-clear-branch" class="ctx-branch" type="button">Clear and...</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-filter-clear-ip" type="button">Add IP</button>
          <button id="ctx-filter-clear-port" type="button">Add Port</button>
          <button id="ctx-filter-clear-mac" type="button">Add MAC</button>
          <button id="ctx-filter-clear-link-protocol" type="button">Add Link Proto</button>
          <button id="ctx-filter-clear-wire-protocol" type="button">Add Transport Proto</button>
          <button id="ctx-filter-clear-app-protocol" type="button">Add Application Proto</button>
          <button id="ctx-filter-clear-protocol" type="button">Add Both Protos</button>
          <button id="ctx-filter-clear-mime" type="button">Add MIME</button>
        </div>
      </div>
    </div>
  </div>
  <div id="ctx-keystore-submenu" class="ctx-submenu">
    <button id="ctx-keystore-branch" class="ctx-branch" type="button">Add to Keystore...</button>
    <div class="ctx-submenu-panel">
      <div id="ctx-keystore-password-submenu" class="ctx-submenu">
        <button id="ctx-keystore-password-branch" class="ctx-branch" type="button">As Password</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-keystore-password-session" type="button">Session</button>
          <button id="ctx-keystore-password-persistent" type="button">Persistent</button>
        </div>
      </div>
      <div id="ctx-keystore-key-submenu" class="ctx-submenu">
        <button id="ctx-keystore-key-branch" class="ctx-branch" type="button">As Private Key</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-keystore-key-session" type="button">Session</button>
          <button id="ctx-keystore-key-persistent" type="button">Persistent</button>
        </div>
      </div>
      <div id="ctx-keystore-cert-submenu" class="ctx-submenu">
        <button id="ctx-keystore-cert-branch" class="ctx-branch" type="button">As Certificate</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-keystore-cert-session" type="button">Session</button>
          <button id="ctx-keystore-cert-persistent" type="button">Persistent</button>
        </div>
      </div>
      <div id="ctx-keystore-cookie-submenu" class="ctx-submenu">
        <button id="ctx-keystore-cookie-branch" class="ctx-branch" type="button">As Session Cookie</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-keystore-cookie-session" type="button">Session</button>
          <button id="ctx-keystore-cookie-persistent" type="button">Persistent</button>
        </div>
      </div>
      <div id="ctx-keystore-uri-submenu" class="ctx-submenu">
        <button id="ctx-keystore-uri-branch" class="ctx-branch" type="button">As URI / URL</button>
        <div class="ctx-submenu-panel">
          <button id="ctx-keystore-uri-session" type="button">Session</button>
          <button id="ctx-keystore-uri-persistent" type="button">Persistent</button>
        </div>
      </div>
    </div>
  </div>
  <div id="ctx-export-submenu" class="ctx-submenu">
    <button id="ctx-export-branch" class="ctx-branch" type="button">Export...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-export-packet" role="menuitem">Packet</button>
      <button id="ctx-export-payload" role="menuitem">Payload</button>
      <button id="ctx-export-conv-input" role="menuitem">Conv input</button>
      <button id="ctx-export-conv-raw" role="menuitem">Conv Raw</button>
      <button id="ctx-export-conv-hex" role="menuitem">Conv output (hex)</button>
      <button id="ctx-export-conv-binary" role="menuitem">Conv output (binary)</button>
      <button id="ctx-export-conv-decimal" role="menuitem">Conv output (decimal)</button>
      <button id="ctx-export-conv-decimal-integer" role="menuitem">Conv output (integer)</button>
      <button id="ctx-export-conv-ascii" role="menuitem">Conv output (ASCII)</button>
      <button id="ctx-export-conv-base64" role="menuitem">Conv output (base64)</button>
      <button id="ctx-export-conv-hashes" role="menuitem">Conv hashes</button>
      <button id="ctx-export-conv-decodes" role="menuitem">Conv decode output</button>
      <button id="ctx-export-decrypted" role="menuitem">Decrypted data</button>
      <button id="ctx-save-cookie-jar" role="menuitem">Cookie Jar</button>
    </div>
  </div>
  <div id="ctx-reports-submenu" class="ctx-submenu">
    <button id="ctx-reports-branch" class="ctx-branch" type="button">Reports...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-export-summary-md" role="menuitem">Save Report (Markdown)</button>
      <button id="ctx-export-summary-txt" role="menuitem">Save Report (Text)</button>
      <button id="ctx-export-summary-html" role="menuitem">Save Report (HTML)</button>
    </div>
  </div>
  <div id="ctx-http-file-submenu" class="ctx-submenu">
    <button id="ctx-http-file-branch" class="ctx-branch" type="button">HTTP Body...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-http-file-load" type="button">Body to Conv tab</button>
      <button id="ctx-http-file-load-decompressed" type="button">Body to Conv tab (decompressed)</button>
      <button id="ctx-http-file-preview" type="button">Browser preview</button>
      <button id="ctx-http-file-preview-decompressed" type="button">Browser preview (decompressed)</button>
    </div>
  </div>
  <div id="ctx-file-carve-submenu" class="ctx-submenu">
    <button id="ctx-file-carve-branch" class="ctx-branch" type="button">File Carving...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-http-file-save" type="button">HTTP body to file</button>
      <button id="ctx-http-file-save-decompressed" type="button">HTTP body to file (decompressed)</button>
      <button id="ctx-file-carve-smb" type="button">SMB file to disk</button>
      <button id="ctx-file-carve-nfs" type="button">NFS file to disk</button>
      <button id="ctx-file-carve-ftp" type="button">FTP file to disk</button>
      <button id="ctx-load-carvable-extraction" role="menuitem">Load carved file into Extraction</button>
      <button id="ctx-load-carvable-decoders" role="menuitem">Load carved file into Decoders</button>
      <button id="ctx-load-carvable-virustotal" role="menuitem">Send carved file to VirusTotal</button>
    </div>
  </div>
  <div id="ctx-llm-submenu" class="ctx-submenu">
    <button id="ctx-llm-branch" class="ctx-branch" type="button">Ask PacketSnitch...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-llm-question" role="menuitem">Ask a question...</button>
      <button id="ctx-llm-explain" role="menuitem">Explain this data...</button>
      <button id="ctx-llm-summarize" role="menuitem">Summarize this packet...</button>
      <button id="ctx-llm-subnet-host-summary" role="menuitem">Summarize this subnet host...</button>
    </div>
  </div>
  <button id="ctx-open-heatmap-location" role="menuitem">Open in Heatmap</button>
  <div id="ctx-analyze-ip-submenu" class="ctx-submenu">
    <button id="ctx-analyze-ip-branch" class="ctx-branch" type="button">Analyze IP...</button>
    <div class="ctx-submenu-panel">
      <button id="ctx-analyze-ip-subnet" type="button">Run in Subnet Calculator</button>
      <button id="ctx-analyze-ip-threat-intel" type="button">Run Threat Intel lookup</button>
    </div>
  </div>
  <hr id="convert-context-save-divider" class="ctx-divider" />
  <button id="ctx-save-json" role="menuitem">Save Session</button>
`;

module.exports = { convertContextMenuMarkup };
