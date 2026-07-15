// Coordinates main workspace tab switching and tab-specific UI visibility.

function createWorkspaceTabController({
    constants,
    state,
    statusUpdate,
    writeLogEntry,
    threadName,
    setConvSubtab,
    normalizeDataToolsHexInputFormatting,
    runDeferredDataToolsAnalysisForActiveSubtab,
    renderNotesList,
    setSettingsSubtab,
    syncSettingsFormFromState,
}) {
    function showDataTools(tabName = constants.CONV_CONVERSIONS_SUBTAB) {
        state.activeMainTab = constants.MAIN_TAB_DATA_TOOLS;
        statusUpdate("Status: Displaying data conversion tools");
        writeLogEntry(`[${threadName}] User opened data conversion tools view`);
        document.getElementById("prev-btn").style.display = "none";
        document.getElementById("next-btn").style.display = "none";
        document.getElementById("packetInfoPane").style.display = "none";
        document.getElementById("packetPayloadPane").style.display = "none";
        document.getElementById("summary_box").style.display = "none";
        document.getElementById("stats_box").style.display = "none";
        document.getElementById("list_box").style.display = "none";
        document.getElementById("notes_box").style.display = "none";
        document.getElementById("settings_box").style.display = "none";
        document.getElementById("crypt_box").style.display = "none";
        document.getElementById("keystore_box").style.display = "none";
        document.getElementById("rightside").style.display = "none";
        document.getElementById("data_tools_box").style.display = "flex";
        setConvSubtab(tabName);
        if (tabName === constants.CONV_CONVERSIONS_SUBTAB) {
            normalizeDataToolsHexInputFormatting();
        }
        runDeferredDataToolsAnalysisForActiveSubtab();
    }

    function showNotesWorkspace() {
        state.activeMainTab = constants.MAIN_TAB_NOTES;
        statusUpdate("Status: Displaying session notes");
        writeLogEntry(`[${threadName}] User opened notes workspace view`);
        document.getElementById("prev-btn").style.display = "none";
        document.getElementById("next-btn").style.display = "none";
        document.getElementById("packetInfoPane").style.display = "none";
        document.getElementById("packetPayloadPane").style.display = "none";
        document.getElementById("summary_box").style.display = "none";
        document.getElementById("stats_box").style.display = "none";
        document.getElementById("list_box").style.display = "none";
        document.getElementById("data_tools_box").style.display = "none";
        document.getElementById("settings_box").style.display = "none";
        document.getElementById("crypt_box").style.display = "none";
        document.getElementById("keystore_box").style.display = "none";
        document.getElementById("notes_box").style.display = "flex";
        document.getElementById("rightside").style.display = "block";
        const rightsideDataEl = document.getElementById("rightside-data");
        const rightsideNotesEl = document.getElementById("rightside-notes");
        const rightsideConvInsightsEl = document.getElementById("rightside-conv-insights");
        if (rightsideDataEl) rightsideDataEl.hidden = true;
        if (rightsideNotesEl) rightsideNotesEl.hidden = false;
        if (rightsideConvInsightsEl) rightsideConvInsightsEl.hidden = true;
        renderNotesList();
    }

    function showSettingsWorkspace() {
        state.activeMainTab = constants.MAIN_TAB_SETTINGS;
        statusUpdate("Status: Displaying settings");
        writeLogEntry(`[${threadName}] User opened settings workspace view`);
        document.getElementById("prev-btn").style.display = "none";
        document.getElementById("next-btn").style.display = "none";
        document.getElementById("packetInfoPane").style.display = "none";
        document.getElementById("packetPayloadPane").style.display = "none";
        document.getElementById("summary_box").style.display = "none";
        document.getElementById("stats_box").style.display = "none";
        document.getElementById("list_box").style.display = "none";
        document.getElementById("notes_box").style.display = "none";
        document.getElementById("data_tools_box").style.display = "none";
        document.getElementById("settings_box").style.display = "none";
        document.getElementById("crypt_box").style.display = "none";
        document.getElementById("keystore_box").style.display = "none";
        document.getElementById("settings_box").style.display = "flex";
        document.getElementById("rightside").style.display = "none";
        setSettingsSubtab(state.activeSettingsSubtab);
        syncSettingsFormFromState();
    }

    return {
        showDataTools,
        showNotesWorkspace,
        showSettingsWorkspace,
    };
}

module.exports = {
    createWorkspaceTabController,
};