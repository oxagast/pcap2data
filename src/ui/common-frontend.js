// Boots common renderer-side helpers shared across frontend modules.

// ── Reusable div-dropdown factory ──────────────────────────────────────────────
// Converts a native <select id="…"> into a div-based combobox so option-hover
// colors respect CSS custom properties on Linux GTK (which ignores CSS on
// <option> elements).  One factory instance per dropdown.
//
// HTML expected structure (replaces the <select>):
//   <div id="⟨id⟩" class="dropdown-container" role="combobox"
//        aria-haspopup="listbox" aria-expanded="false" tabindex="0">
//     <div class="dropdown-selected" id="⟨id⟩-selected-label">
//       <span class="dropdown-label-text"></span>
//       <span class="dropdown-arrow">&#x25BC;</span>
//     </div>
//     <div class="dropdown-list" id="⟨id⟩-options" role="listbox"></div>
//   </div>
//
// The factory returns an object with:
//   .render(options, selectedValue)  – rebuild options, highlight selection
//   .getValue()                    – return current value string
//   .setValue(value)              – set selection by value string
//   .open() / .close()            – toggle list visibility
//   .destroy()                    – remove outside-click listener
// ───────────────────────────────────────────────────────────────────────────────
function makeDropdown(id, onSelect) {
  const container = document.getElementById(id);
  const listEl = document.getElementById(id + "-options");
  const labelEl = container?.querySelector(".dropdown-label-text");

  let selectedIndex = 0;
  let options = []; // { value, label }
  let outsideHandler = null;

  function render(opts, selectedValue) {
    if (!listEl) return;
    options = opts;
    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

    const idx = options.findIndex((o) => o.value === selectedValue);
    selectedIndex = idx >= 0 ? idx : 0;

    if (options.length === 0) {
      const empty = document.createElement("div");
      empty.className = "dropdown-empty";
      empty.textContent = "No options";
      listEl.appendChild(empty);
    } else {
      options.forEach((opt, i) => {
        const item = document.createElement("div");
        item.className = "dropdown-option";
        item.setAttribute("role", "option");
        item.setAttribute("tabindex", "-1");
        item.dataset.index = String(i);
        item.textContent = opt.label;
        if (i === selectedIndex) {
          item.classList.add("dropdown-option-selected");
          item.setAttribute("aria-selected", "true");
        }
        listEl.appendChild(item);
      });
    }
    updateLabel();
  }

  function updateLabel() {
    if (!labelEl) return;
    const sel = options[selectedIndex];
    labelEl.textContent = sel ? sel.label : "No options";
  }

  function setSelection(idx) {
    if (idx < 0 || idx >= options.length) return;
    selectedIndex = idx;
    listEl.querySelectorAll(".dropdown-option").forEach((opt, i) => {
      const isSelected = i === idx;
      opt.classList.toggle("dropdown-option-selected", isSelected);
      opt.setAttribute("aria-selected", isSelected ? "true" : "false");
    });
    updateLabel();
  }

  function openList() {
    if (!container || !listEl) return;
    container.classList.add("dropdown-open");
    container.setAttribute("aria-expanded", "true");
    const sel = listEl.querySelector(".dropdown-option-selected");
    if (sel) sel.scrollIntoView({ block: "nearest" });
  }

  function closeList() {
    if (!container) return;
    container.classList.remove("dropdown-open");
    container.setAttribute("aria-expanded", "false");
  }

  // Container click → toggle, or item selection.
  container?.addEventListener("click", (e) => {
    const item = e.target.closest(".dropdown-option");
    if (item) {
      const idx = parseInt(item.dataset.index ?? "-1", 10);
      if (idx >= 0) {
        setSelection(idx);
        closeList();
        if (onSelect) onSelect(options[idx].value);
      }
      return;
    }
    if (container.classList.contains("dropdown-open")) {
      closeList();
    } else {
      openList();
    }
  });

  container?.addEventListener("keydown", (e) => {
    if (!container?.classList.contains("dropdown-open")) {
      if (e.key === "Enter" || e.key === " " || e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        openList();
      }
      return;
    }
    switch (e.key) {
      case "Enter":
      case " ":
        e.preventDefault();
        closeList();
        break;
      case "Escape":
        e.preventDefault();
        closeList();
        break;
      case "ArrowDown":
        e.preventDefault();
        setSelection(Math.min(selectedIndex + 1, options.length - 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setSelection(Math.max(selectedIndex - 1, 0));
        break;
      case "Tab":
        closeList();
        break;
      default:
        break;
    }
  });

  outsideHandler = (e) => {
    if (container && !container.contains(e.target)) closeList();
  };
  document.addEventListener("click", outsideHandler);

  return {
    render,
    getValue() {
      return options[selectedIndex]?.value ?? "";
    },
    getOptions() {
      return options.map((option) => ({ ...option }));
    },
    setValue(val) {
      const idx = options.findIndex((o) => o.value === val);
      if (idx >= 0) setSelection(idx);
    },
    open: openList,
    close: closeList,
    destroy() {
      document.removeEventListener("click", outsideHandler);
    },
    getContainer() {
      return container;
    },
  };
}

const PANEL_MODULES = [
  "summary-panel",
  "data-panel",
  "stats-panel",
  "list-panel",
  "data-tools-panel",
  "crypt-panel",
  "keystore-panel",
  "session-picker",
];

module.exports = {
  makeDropdown,
  PANEL_MODULES,
};
