# hello-snitch sample plugin

This sample plugin demonstrates three behaviors:

1. Reads current PacketSnitch version via `window.installapi.checkFirstRun()`.
2. Displays `Hello, from PacketSnitch version: x.y.z`.
3. Writes that message to `~/Documents/hello-snitch-version.txt`.
4. Demonstrates capability enforcement with an intentionally unauthorized chmod action.

## Files

- `plugin.json`: plugin manifest (compatible with current PacketSnitch plugin installer checks).
- `hello.js`: plugin runtime script exposing `window.HelloSnitchPlugin.run()`.

## Expected host behavior

When plugin execution is wired by the plugin host, call:

```js
await window.HelloSnitchPlugin.run();
```

This returns:

```js
{
  message: "Hello, from PacketSnitch version: x.y.z",
  version: "x.y.z",
  outputPath: "/home/<user>/Documents/hello-snitch-version.txt"
}
```
