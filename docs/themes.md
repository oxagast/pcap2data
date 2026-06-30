## PacketSnitch Themes

PacketSnitch uses a file-driven theming engine. A theme is a JSON file that overrides CSS variables and can optionally replace the app logo.

This guide covers:

- Where theme files live
- Theme JSON schema
- How to set app colors
- How to set a custom logo
- How to control opacity
- How the app validates/falls back when a theme is invalid

---

## Screenshot

This is a screenshot of the "Matrix" theme.


<p align="center">
<img alt="The Matrix Theme on PacketSnitch 1.8" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-matrix-theme.png">
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
  }
}
```

### Field Rules

- `id`: sanitized to lowercase with only `a-z`, `0-9`, `_`, `-`
- `name`: display label shown in Settings
- `description`: optional text
- `variables`: required, must include at least one valid CSS variable key/value
- `logoImage`: optional

Validation behavior:

- Only variable keys starting with `--` are applied.
- Variable values must be non-empty strings.
- If `variables` is empty/invalid, the theme file is ignored.
- Invalid JSON files are skipped (the app continues running).
- Duplicate theme IDs are de-duplicated.

---

## Setting App Colors

The base color system is driven by CSS custom properties in `src/assets/css/style.css`.

Most themes start by overriding these core variables:

- `--app-bg`
- `--surface-0`
- `--surface-1`
- `--surface-2`
- `--scrollbar-track`
- `--border-strong`
- `--color-1` through `--color-7`

Conv/data tools color variables:

- `--data-tools-frame-bg`
- `--data-tools-hex-color`
- `--data-tools-binary-color`
- `--data-tools-decimal-color`
- `--data-tools-decimal-integer-color`
- `--data-tools-ascii-color`
- `--data-tools-base64-color`

Optional readability overrides:

- `--header-text-color`
- `--sidebar-text-color`
- `--input-bg-color`
- `--input-text-color`
- `--stats-tag-text-color`
- `--crypt-panel-bg`
- `--crypt-panel-text`

Tip: start from an existing file in `themes/`, then change values incrementally.

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

## Opacity Controls

Theme opacity is controlled with CSS variable values where supported.

Most important global opacity control:

- `--tab-inactive-opacity`

Example:

```json
"variables": {
  "--tab-inactive-opacity": "0.78"
}
```

Use values between `0` and `1`:

- `0` = fully transparent
- `1` = fully opaque

Other opacity effects in the app are hardcoded in component styles and not all are theme-variable driven.

---

## Build and Test Workflow

1. Copy an existing theme JSON in `userData/themes`.
2. Rename file and update `id`/`name`.
3. Modify `variables` (and optional `logoImage`).
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
