function showInstallScreen(installInfo, documentRef) {
  const screen = documentRef.getElementById("install-screen");
  if (!screen) return;

  documentRef.getElementById("install-version").textContent =
    "Version " + installInfo.version;

  const fileList = documentRef.getElementById("install-file-list");
  fileList.innerHTML = "";
  installInfo.installedFiles.forEach((file) => {
    const item = documentRef.createElement("li");
    item.className = file.exists ? "install-file-ok" : "install-file-missing";
    item.textContent = (file.exists ? "\u2713 " : "\u2717 ") + file.name;
    if (!file.exists) {
      item.title = "Not found at: " + file.path;
    }
    fileList.appendChild(item);
  });

  const ollamaStatus = documentRef.getElementById("install-ollama-status");
  if (!installInfo.ollamaInstalled) {
    ollamaStatus.textContent =
      "\u26a0 Ollama is not installed. LLM packet summarisation will be unavailable. Install Ollama from https://ollama.com to enable this feature.";
    ollamaStatus.className = "install-warning";
  } else {
    ollamaStatus.textContent =
      "\u2713 Ollama is installed. LLM summarisation is available.";
    ollamaStatus.className = "install-ok";
  }

  screen.style.display = "flex";
}

function initializeInstallScreen({ installapi, documentRef }) {
  if (installapi) {
    installapi.checkFirstRun().then((installInfo) => {
      if (installInfo && installInfo.isFirstRun) {
        showInstallScreen(installInfo, documentRef);
      }
    });
  }

  const installContinueBtn = documentRef.getElementById("install-continue-btn");
  if (!installContinueBtn) return;

  installContinueBtn.addEventListener("click", () => {
    if (installapi) {
      installapi.dismissFirstRun().then(() => {
        documentRef.getElementById("install-screen").style.display = "none";
      });
    } else {
      documentRef.getElementById("install-screen").style.display = "none";
    }
  });
}

module.exports = {
  initializeInstallScreen,
};
