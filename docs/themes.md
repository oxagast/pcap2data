## PacketSnitch Themes

PacketSnitch uses a file-driven theming engine. A theme is a JSON file that overrides CSS variables and can optionally replace the app logo, apply a backdrop wallpaper, and tune panel transparency.

This guide covers:

- Where theme files live
- Theme JSON schema
- How to set app colors
- How to set a custom logo
- How to set a backdrop wallpaper
- How to control opacity and panel translucency
- How the app validates/falls back when a theme is invalid

---

## Screenshot

<p align="center">
Screenshot of the "Matrix" theme.

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-matrix-theme.png">
<img alt="The Matrix Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-matrix-theme.png">
</a>

Also a cobalt/black "Sub7" inspired theme.

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-sub7-theme.png">
<img alt="The Sub7 Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-sub7-theme.png">
</a>

A lighter, airy pastels theme, "Nilla Horizon".

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-nilla-horizon-theme.png">
<img alt="The Matrix Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-nilla-horizon-theme.png">
</a>
</p>



---

## Theme File Locations

PacketSnitch uses two theme locations:

- Repository defaults: `themes/*.json`
- Runtime/user themes: `userData/themes/*.json`

At startup, PacketSnitch ensures default themes exist in `userData/themes`. The Settings tab reads from this runtime directory.

In-app, open **Settings → General** and check the theme-directory hint text to find the exact path on your system.

---

## Theme JSON Schema

A valid theme must have a non-empty `variables` object with CSS custom properties.

```json
{
  "id": "my_custom_theme",
  "name": "My Custom Theme",
  "description": "Optional description shown in docs/source",
  "variables": {
    "--app-bg": "#101418",
    "--surface-0": "#0b0f13",
    "--surface-1": "#151c24",
    "--surface-2": "#111820",
    "--color-1": "#9ad8ff",
    "--color-5": "#d7e9f7",
    "--tab-inactive-opacity": "0.72"
  },
  "logoImage": {
    "format": "png",
    "base64": "iVBORw0KGgoAAAANSUhEUgAA..."
  },
  "backdropImage": {
    "format": "jpg",
    "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
  }
}
```

### Field Rules

- `id`: sanitized to lowercase with only `a-z`, `0-9`, `_`, `-`
- `name`: display label shown in Settings
- `description`: optional text
- `variables`: required, must include at least one valid CSS variable key/value
- `quitButtonCharacter`: optional single-character override for the app quit button label
- `logoImage`: optional
- `backdropImage`: optional

Validation behavior:

- Only variable keys starting with `--` are applied.
- Variable values must be non-empty strings.
- If `variables` is empty/invalid, the theme file is ignored.
- Invalid JSON files are skipped (the app continues running).
- Duplicate theme IDs are de-duplicated.

---

## Setting App Colors

The base color system is driven by CSS custom properties in `src/assets/css/style.css`.

Tip: start from an existing file in `themes/`, then change values incrementally.

## Full Variable Reference

The variables below are currently consumed by PacketSnitch styles and can be set in `theme.variables`.

### Core Surfaces and UI Colors

- `--app-bg`: app/page background.
- `--surface-0`: primary workspace surface.
- `--surface-1`: secondary panel surface.
- `--surface-2`: tertiary surface token (available for themes).
- `--scrollbar-track`: scrollbar track color.
- `--border-strong`: stronger border color used by major frames.
- `--color-1`: primary accent/foreground token.
- `--color-2`: secondary accent/background token.
- `--color-2-hover`: hover state for secondary accents.
- `--color-3`: common border/outline token used widely.
- `--color-4`: muted panel/background token.
- `--color-5`: primary readable foreground text token.
- `--color-6`: secondary readable foreground text token.
- `--color-7`: shared panel background token.

### Header, Sidebar, Inputs, and App Chrome

- `--top-bar-bg`: top title/tagline bar background (center logo/tagline strip).
- `--header-text-color`: heading/title text color.
- `--sidebar-text-color`: sidebar text color.
- `--input-bg-color`: text/select input background.
- `--input-text-color`: text/select input foreground.
- `--quit-btn-color`: quit button color.
- `--quit-btn-hover-color`: quit button hover color.
- `--stats-tag-text-color`: stats tag text color.
- `--notes-link-color`: markdown preview link color in notes.
- `--notes-markdown-bg`: markdown preview background color in notes.
- `--crypt-panel-bg`: crypt workspace panel background.
- `--crypt-panel-text`: crypt workspace text color.

### Data Tools Workspace Variables

- `--data-tools-frame-bg`: data tools frame background.
- `--data-tools-frame-color`: data tools frame text color.
- `--data-tools-frame-border`: data tools frame border color.
- `--data-tools-hex-color`: hex conversion accent/border color.
- `--data-tools-binary-color`: binary conversion accent/border color.
- `--data-tools-decimal-color`: decimal conversion accent/border color.
- `--data-tools-decimal-integer-color`: decimal-integer conversion accent/border color.
- `--data-tools-ascii-color`: ASCII conversion accent/border color.
- `--data-tools-base64-color`: Base64 conversion accent/border color.

### Activity Log Variables

- `--log-bg`: activity log background.
- `--log-text`: activity log text.

### Typography and Layout Variables

- `--body-font-family`: global body font family.
- `--panel-bg-opacity`: panel background opacity mix percentage (`0%`-`100%`). Lower values let the backdrop wallpaper show through panel surfaces.
- `--tab-inactive-opacity`: inactive tab opacity (string value from `0` to `1`).
- `--sidebar-width`: sidebar width token used in layout sizing.

### Internal Utility Tokens (Usually Leave Alone)

These are internal sizing helpers used by the filter input/clear button layout.

- `--filter-clear-button-width`
- `--filter-clear-padding`
- `--filter-clear-right-offset`

You can override them, but values that are too small/large may cause overlap or clipping in the filter controls.

---

## Custom Logo

You can set a per-theme logo with `logoImage`.

Supported formats:

- `png`
- `jpg` (or `jpeg`, normalized to `jpg`)

Supported payload fields:

- `logoImage.base64`
- `logoImage.data`

If a data URI prefix is included (for example `data:image/png;base64,...`), PacketSnitch strips it automatically.

Example:

```json
"logoImage": {
  "format": "jpg",
  "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
}
```

If `logoImage` is missing or invalid, PacketSnitch falls back to the default app logo.

---

## Optional Backdrop Wallpaper

You can set a full-app backdrop wallpaper with `backdropImage`.

This image is rendered in the dedicated backdrop layer behind the full UI stack.

Hint: Animated .png images (APNG format) *are* supported by the theme engine, however, I just personally think they are too distracting to be practical in this use case.

Supported formats:

- `png`
- `jpg` (or `jpeg`, normalized to `jpg`)

Supported payload fields:

- `backdropImage.base64`
- `backdropImage.data`

Example:

```json
"backdropImage": {
  "format": "jpg",
  "base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
}
```

If `backdropImage` is missing or invalid, PacketSnitch shows no wallpaper and uses standard theme backgrounds only.

---

## Opacity Controls

Theme opacity is controlled with CSS variable values where supported.

Most useful controls:

- `--tab-inactive-opacity`: inactive tab button opacity (`0` to `1`)
- `--panel-bg-opacity`: major panel/chrome background mix percentage (`0%` to `100%`) used to let backdrop wallpaper show through

Example:

```json
"variables": {
  "--tab-inactive-opacity": "0.60",
  "--panel-bg-opacity": "84%"
}
```

Recommended starting points:

- `--panel-bg-opacity: "80%"` to `"92%"` for subtle translucency
- `--tab-inactive-opacity: "0.55"` to `"0.75"` for readable but dimmed inactive tabs

---

## Build and Test Workflow

1. Copy an existing theme JSON in `userData/themes`.
2. Rename file and update `id`/`name`.
3. Modify `variables` (and optional `logoImage` / `backdropImage`).
4. Open **Settings → General** and select your theme.
5. Save settings.
6. If needed, reopen Settings or restart the app to refresh newly added files.

---

## Troubleshooting

Theme does not appear in Settings:

- Confirm file extension is `.json`.
- Confirm JSON is valid.
- Confirm `variables` exists and has at least one `--variable` string value.
- Confirm the file is in `userData/themes` (not only repository `themes/` in production installs).

Theme appears but styles do not change:

- Confirm variable names exactly match CSS variable names used by the app.
- Confirm values are valid CSS strings (`#hex`, `rgb(...)`, numeric string for opacity).

Logo does not render:

- Confirm `format` is `png`, `jpg`, or `jpeg`.
- Confirm base64 payload is valid and non-empty.
- Remove line breaks/whitespace from base64 if needed.

Backdrop wallpaper does not render:

- Confirm `backdropImage.format` is `png`, `jpg`, or `jpeg`.
- Confirm `backdropImage.base64` is valid base64.
- If using custom runtime themes, ensure you edited the active file in `userData/themes` and restart the app if needed.

Wallpaper renders but is hard to notice:

- Lower `--panel-bg-opacity` (for example from `100%` to `84%`).
- Ensure your panel surfaces are not fully opaque overrides in the selected theme.
