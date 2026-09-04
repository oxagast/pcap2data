---
tool: packet-snitch-assist
version: 1
---

# PacketSnitch — Copilot Instructions

This file provides GitHub Copilot (and other AI assistants) with the context needed to
help users with PacketSnitch settings, configuration questions, and install identity.

---

## 1. Settings

All default settings are defined in `src/settings.js` (`DEFAULT_SETTINGS`).

### General

| Key | Default | Notes |
|---|---|---|
| `themeId` | `"snitchbitch"` | Active theme |
| `convJsonIndentSpaces` | `2` | |
| `statusResetSeconds` | `10` | |
| `backendPacketChunkSize` | `500` | |
| `backendWorkerThreads` | `max(1, hardwareConcurrency/2)` | |
| `streamContextWarnPacketThreshold` | `20` | |
| `manualConvImportMaxBytes` | `2_097_152` | |
| `nmapServiceScanEnabled` | `false` | |
| `checkForNewReleasesOnStartup` | `true` | |
| `hostDataPayloadSplitPercent` | `60` | Draggable split ratio |
| `defaultTab` | `"stats"` | Landing tab after capture: `"stats"` / `"list"` / `"data"` |
| `themeServerBaseUrl` | `"https://catalog.packetsnitch.com:9021/"` | **Locked** — not editable via settings UI |
| `themeRefreshIntervalHours` | `72` | **Locked** |
| `allowInsecureTlsEndpoints` | `true` | **Locked** |

### Backend

| Key | Default | Notes |
|---|---|---|
| `tcpHost` | `"127.0.0.1"` | |
| `tcpPort` | `9020` | |
| `forceLegacySpawn` | `false` | |
| `httpProgressLogMinIntervalMs` | `0` | Throttle bridge HTTP progress log lines |

### Debug / Rendering

| Key | Default | Notes |
|---|---|---|
| `bsonGzipSessionEnabled` | `true` | |
| `ungroupedListVirtualizationEnabled` | `false` | |
| `backendHttpDataModeEnabled` | `true` | |
| `backendJsonDataEmitMinIntervalMs` | `800` | |
| `backendIncrementalRefreshMinIntervalMs` | `1500` | |
| `backendIncrementalRefreshMinPackets` | `4000` | |
| `backendEarlyYieldPacketThreshold` | `5000` | |
| `frontendIngestThreadingEnabled` | `true` | |
| `frontendIngestWorkerThreads` | `max(1, min(8, hardwareConcurrency))` | |
| `mapProjectionCalibrationLocked` | `true` | |

### LLM

| Key | Default | Notes |
|---|---|---|
| `provider` | `"ollama"` | `"ollama"` or `"openrouter"` |
| `ollamaModel` | `"minimax-m3:cloud"` | |
| `openrouterModel` | `"openai/gpt-4o-mini"` | |
| `activeByDefault` | `false` | |
| `backgroundSummaryGenerationEnabled` | `true` | |
| `triggerDelaySeconds` | `5` | |
| `maxSummaryTokens` | `1024` | |
| `ollamaRequestTimeoutSeconds` | `300` | |
| `retryCount` | `2` | |
| `analysisCompactionThresholdBlubs` | `6` | |

### API Keys

| Key | Default | Notes |
|---|---|---|
| `ollamaApiKey` | `""` | Used for cloud (ollama.com) calls |

---

## 2. Install UUID

The per-install unique identifier is used for license activation and theme catalog access.

- **Function:** `getThemeServerInstallUuid()` in `src/main.js` (≈ line 4946)
- **Preload bridge:** exposed via `settingsapi.getInstallUuid()` → IPC `get-install-uuid`
- **Typical value shape:** `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` (UUID v4)

To look up a user's install UUID in code:

```js
// From the renderer:
const uuid = await window.settingsapi.getInstallUuid();

// From the main process:
const { getThemeServerInstallUuid } = require('./src/main.js');
const uuid = getThemeServerInstallUuid();
```

---

## 3. How to help users

- **"What are my current settings?"** → Read `src/settings.js`, explain each top-level key.
- **"What is my install UUID?"** → Call `window.settingsapi.getInstallUuid()` in the renderer, or
  use `getThemeServerInstallUuid()` in the main process.
- **"How do I change X setting?"** → Explain the setting and the correct field name. Note
  if the setting is **locked** (theme server URL, refresh interval, TLS setting — these cannot
  be changed via the settings UI).
- **"What theme am I using?"** → `settings.general.themeId`
- **"What LLM provider do I have configured?"** → `settings.llm.provider` + `settings.llm.ollamaModel`
