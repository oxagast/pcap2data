
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
</p>

---

## What is PacketSnitch?

PacketSnitch is a network analysis platform that transforms packet captures into searchable, protocol-aware intelligence, helping security professionals, developers, and researchers rapidly uncover hosts, credentials, certificates, files, locations, protocols, anomalies, and other actionable insights.


| Component | Description |
| --------- | ----------- |
| **Backend** | Python script (`snitch.py`) that parses `.pcap` files and extracts rich per-packet metadata into JSON |
| **Frontend** | Electron-based desktop application for loading, browsing, filtering, and visualizing traffic |

### Key Features

- 📂 **Load PCAP files** — Point the backend at a capture, then explore interactively in the desktop app
- 🔍 **Powerful filtering** — Filter by port, country, entropy, MIME type, and more using dot-notation expressions
- 🌐 **Full IPv6 support** — Native IPv6 parsing, shared `ip.*` filter keys (with `network.proto` / `ip.proto.num` for family disambiguation), bracketed endpoint display, BigInt-backed subnet math, and IPv6 enrichment for GeoIP, WHOIS, Tor, Shodan, and VirusTotal
- 🌍 **GeoIP integration** — See source/destination locations with country, city, and timezone
- 📊 **Payload analysis** — Shannon entropy visualization, MIME type detection, hex dump with ASCII view
- 🤖 **LLM summaries** — Generate AI-powered analysis reports using Ollama
- 📑 **Protocol decoding** — DNS, HTTP, SSL/TLS, DHCP, NTP, SIP, IPv6, ICMPv6, DHCPv6, and more
- 🧩 **Plugin engine** — Install zip plugins, manage runtime safety thresholds, and extend UI workflows from the built-in Plugins manager

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
4. **Summarize** — Click **Summary** for LLM-generated analysis (requires Ollama)

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

**Marshall Whittaker**

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
