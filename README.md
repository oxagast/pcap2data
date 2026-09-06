![PacketSnitch](https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/720p-packetsnitch-oxasploits-bluebg.png)


<p align="center"><a href="https://github.com/oxasploits/PacketSnitch">
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/packet-snitch-tag-transp-whitetext.png" alt="PacketSnitch" width="400"></a>
</p>

<p align="center">
  <a href="https://github.com/oxasploits/PacketSnitch/releases">
    <img src="https://img.shields.io/github/v/release/oxasploits/PacketSnitch?include_prereleases&label=Release" alt="Release">
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img src="https://img.shields.io/github/license/oxasploits/PacketSnitch?label=License" alt="License">
  </a>
  <a href="https://github.com/oxasploits/PacketSnitch/releases">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue" alt="Platform">
  </a>
  <a href='https://github.com/MShawon/github-clone-count-badge'><img alt='GitHub Clones' src='https://img.shields.io/badge/dynamic/json?color=success&label=Clone&query=count&url=https://gist.githubusercontent.com/oxagast/d5fe94fe6cfbdc41be9d590f51411020/raw/clone.json&logo=github'></a>
</p>

---

## What is it?

What would happen if Wireshark, BurpSuite, and Graylog got together and had a super-mutant-orgy-baby.  It's that. Of protocol aware, stream centric, network analysis tools.

## Why use PacketSnitch?

PacketSnitch transforms raw network traffic into actionable intelligence, enabling security professionals, developers, and researchers to rapidly uncover hidden patterns, threats, and insights from packet captures. Whether you're investigating breaches, analyzing protocols, or building network monitoring tools, PacketSnitch provides the comprehensive analysis capabilities you need to turn data into understanding.

**Analyze. Investigate. Understand.**

## Primary Features Overview

PacketSnitch delivers comprehensive network analysis through five core capabilities that transform raw network data into actionable intelligence:

### Integrated Intelligence & LLM Workflow

PacketSnitch combines advanced protocol decoding with AI-powered analysis. The integrated intelligence aggregation engine works in tandem with a provider-agnostic LLM layer — choose **Ollama** (local, default model `minimax-m3:cloud`) or **OpenRouter** (`openrouter.ai`, with five shipped defaults: `openai/gpt-4o-mini`, `openai/gpt-4o`, `anthropic/claude-3.5-sonnet`, `google/gemini-pro-1.5`, `meta-llama/llama-3.1-405b-instruct`) from Settings → LLM — for contextual summaries, anomaly detection, and automated reporting. An in-app inactive-LLM dialog surfaces when the active provider fails its reachability probe. Researchers can leverage both traditional analysis tools and AI insights for comprehensive investigation.

### Stream Reconstruction to Protocol-Aware Analysis

Transform raw packet streams into fully reconstructed protocol conversations. PacketSnitch performs deep stream reassembly, allowing you to see complete HTTP exchanges, TLS handshakes, DNS queries, and other protocol interactions in their natural context. The **Conv** workspace ships dedicated stream decoders for HTTP, FTP, SMB/Samba, Telnet, SSH/OpenSSH (with keystroke-timing reconstruction), POP3, IMAP, SMTP, DNS, SNMP, DHCP, DHCPv6, EPMAP, LLMNR, NBNS, NBDGM, LDAP (typed attribute tree), SIP, SMPP, Soulseek, BitTorrent, Kerberos (krb5), ISO 8583 (financial), and generic JSON / XML / YAML / Protobuf / MessagePack / BSON / ASN.1 BER / ASN.1 DER. This protocol-aware analysis reveals relationships and patterns that are invisible in raw packet dumps.

### Powerful Search Architecture

Search through terabytes of network data with pinpoint accuracy. PacketSnitch's search architecture supports a vast array of filter keys including ports, countries, entropy values, MIME types, and custom expressions. The system uses dot-notation filtering and supports complex boolean operations to help you quickly isolate specific network flows, hosts, or conversations.

### Advanced Visualization & Heatmap Analysis

From stream dissection to geolocation heatmaps, PacketSnitch provides comprehensive visual analytics. Watch traffic patterns unfold in real-time, explore network topology, and identify geographic distribution of connections. The visualization engine transforms complex network data into intuitive, interactive displays that make analysis and reporting effortless.

### Threat Intel Aggregation & Anomoly Evaluation

PacketSnitch's threat intelligence module aggregates and evaluates security indicators across your network traffic. It correlates known threat feeds, behavioral patterns, and anomaly detection to provide actionable security insights. The **Session Threat Score** card (0-100 score with `Clean` / `Low` / `Medium` / `High` / `Critical` banded pill, color-graded weight breakdown of every contributing indicator, and a **Capture Footprint** summary) leads the Threat Intel sub-tab. The VirusTotal results panel keeps every lookup as a stacked result card across the session, with the full VirusTotal attribute surface and a new `analysis`-id lookup type. The **Stats → Anomalies** sub-tab runs four structured detectors (portscan, brute-force login bursts, baseline packet-length / per-minute outliers, high-entropy cleartext payloads) that share the same engine as the Session Threat Score, so the two views never disagree. The system scores and prioritizes threats based on severity, confidence levels, and potential impact, enabling security teams to focus on the most critical risks first.

## What is PacketSnitch?

PacketSnitch is a network analysis platform that transforms packet captures into searchable, protocol-aware intelligence, helping security professionals, developers, and researchers rapidly uncover hosts, credentials, certificates, files, locations, protocols, anomalies, and other actionable insights.

| Component | Description |
| --------- | ----------- |
| **Backend** | Python script (`snitch.py`) that parses `.pcap` files and extracts rich per-packet metadata into JSON |
| **Frontend** | Electron-based desktop application for loading, browsing, filtering, and visualizing traffic |

### Key Features

- **Load PCAP files** — Point the backend at a capture, then explore interactively in the desktop app
- **Powerful filtering** — Filter by port, country, entropy, MIME type, and more using dot-notation expressions
- **Full IPv6 support** — Native IPv6 parsing, shared `ip.*` filter keys (with `network.proto` / `ip.proto.num` for family disambiguation), bracketed endpoint display, BigInt-backed subnet math, and IPv6 enrichment for GeoIP, WHOIS, Tor, Shodan, and VirusTotal
- **GeoIP integration** — See source/destination locations with country, city, and timezone
- **Payload analysis** — Shannon entropy visualization, MIME type detection, hex dump with ASCII view, and a dedicated **Data Transformations** block in Conv (Invert / 16- or 32-bit Endianness swap / Bit-order reversal / Transpose row-major → column-major) with non-destructive **Reset Output**
- **LLM summaries** — Generate AI-powered analysis reports using the provider-agnostic `llm:generate` IPC channel. Choose **Ollama** or **OpenRouter** in Settings → LLM; per-call `{ maxTokens, temperature, think }` overrides flow through both providers
- **Protocol decoding** — DNS, HTTP, SSL/TLS, DHCP, DHCPv6, NTP, SIP, IPv6, ICMPv6, Kerberos 5 (krb5), ISO 8583 (financial), EPMAP, LLMNR, NBNS, NBDGM, SNMP, LDAP (typed attribute tree), and more — backed by dedicated backend decoders and a Conv Decodes sub-tab with front-end stream decoders
- **Plugin engine** — Install zip plugins, manage runtime safety thresholds, and extend UI workflows from the built-in Plugins manager
- **Theme storefront (Settings → Themes)** — in-app catalog with per-theme previews, license-tier badges, developer / standard / pro licensing, Paddle checkout, and a `packetsnitch://checkout-success` deeplink that re-conciles your licenses and pre-caches newly-owned themes

---

## Quick Start

### Installation

Download a pre-built release from the [releases](https://github.com/oxasploits/PacketSnitch/releases) page:

- **Windows:** `.exe` installer
- **Linux:** `.deb` or `.rpm` packages

Launch the app with `packetsnitch` or click the desktop icon.

### Basic Workflow

1. **Load PCAP** — Click **Load PCAP** to run the backend on a `.pcap` file
2. **Browse packets** — Use **Prev / Next** buttons or select a host from the dropdown
3. **Filter** — Type expressions like `tcp.dst.port:443` and press **Enter**
4. **Summarize** — Click **Summary** for LLM-generated analysis (set your provider under Settings → LLM: Ollama or OpenRouter)

## Documentation

- 🚀 [Startup Docs](https://packetsnitch.oxasploits.com/)  — Quickstart Documentation
- 📖 [Frontend Docs](https://packetsnitch.oxasploits.com/frontend/) — UI reference, conversions, encryption, notes
- 🎨 [Plugins + Themes Docs](https://packetsnitch.oxasploits.com/plugins/) — Combined themes reference and complete plugin engine tutorial with hello-snitch sample code
- 🎯 [Context Menu Reference](https://packetsnitch.oxasploits.com/context-menu/) — Right-click options for copying, converting, filtering, and exporting
- ⚙️ [Backend Docs](https://packetsnitch.oxasploits.com/backend/) — `snitch.py` usage, arguments, output structure
- 🔎 [Filter Reference](https://packetsnitch.oxasploits.com/filters/) — Complete filter keys, operators, examples

---

## License

**GNU GPLv3** — See [LICENSE.md](LICENSE.md) for details.

---

## Author

### Marshall Whittaker

---

## Support the Project

If you find PacketSnitch useful, please consider supporting its development:

<p align="center">
  <a href="https://github.com/sponsors/oxagast">
  Sponsor on Github
  </a>
  <br>
  <a href="https://thanks.dev/oxasploits">
    Sponsor on Thanks.Dev
  </a><br>
  <a href="https://buymeacoffee.com/oxagast">
    Sponsor on Buy me a Coffee
  </a>
</p>
