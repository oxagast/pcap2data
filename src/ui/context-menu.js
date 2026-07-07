
function initializeContextMenu({
  documentRef = document,
  windowRef = window,
  convertContextMenuEl,
  getPasteTargetFromContextTarget,
  getTrimmedSelectionText,
  getConversionTextFromTarget,
  detectConvertibleFormats,
  buildContextFilterQueries,
  getCookieJarTextForContextTarget,
  onFilterBarContextMenu,
  showConvertContextMenu,
  hideConvertContextMenu,
}) {
  documentRef.addEventListener("contextmenu", (event) => {
    const target = event.target;
    if (typeof onFilterBarContextMenu === "function") {
      const handled = onFilterBarContextMenu({
        event,
        target,
        clientX: event.clientX,
        clientY: event.clientY,
      });
      if (handled) {
        return;
      }
    }

    const pasteTarget = getPasteTargetFromContextTarget(target);
    const selectedText = getTrimmedSelectionText();
    const insideEligiblePanel = target?.closest(
      "#packetInfoPane, #packetPayloadPane, #stats_box, #list_box, #notes_box, #data_tools_box, #crypt_box, #keystore_box, #sidedata",
    );
    const isHexViewTarget = Boolean(target?.closest("#hexg"));
    let conversionText = "";
    let formats = [];
    if (insideEligiblePanel) {
      conversionText = getConversionTextFromTarget(target);
      if (conversionText || isHexViewTarget) {
        formats = conversionText ? detectConvertibleFormats(conversionText) : [];
      }
    }
    const filterQueries = insideEligiblePanel
      ? buildContextFilterQueries(target, selectedText, conversionText)
      : {};
    const cookieJarText = insideEligiblePanel
      ? getCookieJarTextForContextTarget(target)
      : "";

    event.preventDefault();
    showConvertContextMenu(
      event.clientX,
      event.clientY,
      conversionText,
      formats,
      {
        isHexViewTarget,
        target,
        pasteTarget,
        showCopySelection: Boolean(selectedText),
        showPaste: Boolean(pasteTarget),
        showSaveJson: true,
        filterQueries,
        cookieJarText,
        showManualKeystoreUri: Boolean(insideEligiblePanel),
      },
    );
  });

  documentRef.addEventListener("click", () => {
    hideConvertContextMenu();
  });
  documentRef.addEventListener(
    "mousedown",
    (event) => {
      if (event.button !== 0) return;
      if (
        !convertContextMenuEl.hidden &&
        !convertContextMenuEl.contains(event.target)
      ) {
        hideConvertContextMenu();
      }
    },
    true,
  );
  documentRef.addEventListener("scroll", () => {
    hideConvertContextMenu();
  });
  windowRef.addEventListener("resize", () => {
    hideConvertContextMenu();
  });
  documentRef.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !convertContextMenuEl.hidden) {
      hideConvertContextMenu();
    }
  });
}

module.exports = {
  initializeContextMenu,
};
