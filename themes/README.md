# PacketSnitch Themes

Themes are JSON files. Add a new `*.json` file in this folder and restart the app.

Required shape:

```json
{
  "id": "mytheme",
  "name": "My Theme",
  "description": "Optional",
  "variables": {
    "--color-1": "#7f80ff"
  }
}
```

Tips:
- `id` should be lowercase letters/numbers with `-` or `_`.
- Only CSS variables in `variables` are applied.
- You can copy an existing file and tweak values.
- The app also syncs defaults into your user themes directory for runtime edits.
