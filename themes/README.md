# PacketSnitch Themes

Themes are JSON files. Add a new `*.json` file in this folder and restart the app.

For full documentation (schema, all common variables, custom logos, opacity, troubleshooting), see:

- `docs/themes.md`

Required shape:

```json
{
  "id": "mytheme",
  "name": "My Theme",
  "description": "Optional",
  "quitButtonCharacter": "x",
  "logoImage": {
    "format": "png",
    "base64": "<base64-image-data>"
  },
  "backdropImage": {
    "format": "jpg",
    "base64": "<base64-image-data>"
  },
  "variables": {
    "--color-1": "#7f80ff"
  }
}
```

Tips:
- `id` should be lowercase letters/numbers with `-` or `_`.
- Only CSS variables in `variables` are applied.
- `logoImage` is optional; supported formats are `png` and `jpg`.
- `backdropImage` is optional; supported formats are `png` and `jpg`.
- `quitButtonCharacter` is optional and can replace the quit button label.
- `--panel-bg-opacity` can make main panel surfaces translucent (for example `"84%"`, range `0%`-`100%`).
- You can copy an existing file and tweak values.
- The app also syncs defaults into your user themes directory for runtime edits.
