# PacketSnitch

<p align="center">
  <img src="https://github.com/oxasploits/PacketSnitch/blob/main/Logo/packet-snitch-tag-transp-whitetext.png" alt="PacketSnitch" width="400">
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

PacketSnitch is a **network packet analysis tool** that combines a Python backend with an Electron frontend to help you explore and filter captured network traffic — no command line required after initial setup.

| Component | Description |
| --------- | ----------- |
| **Backend** | Python script (`snitch.py`) that parses `.pcap` files and extracts rich per-packet metadata into JSON |
| **Frontend** | Electron-based desktop application for loading, browsing, filtering, and visualizing traffic |

### Key Features

- 📂 **Load PCAP files** — Point the backend at a capture, then explore interactively in the desktop app
- 🔍 **Powerful filtering** — Filter by port, country, entropy, MIME type, and more using dot-notation expressions
- 🌍 **GeoIP integration** — See source/destination locations with country, city, and timezone
- 📊 **Payload analysis** — Shannon entropy visualization, MIME type detection, hex dump with ASCII view
- 🤖 **LLM summaries** — Generate AI-powered analysis reports using Ollama
- 📑 **Protocol decoding** — DNS, HTTP, SSL/TLS, DHCP, NTP, SIP, and more

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

---

## The Interface

<p align="center">
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/screenshots/packetsnitch_ss24.png" alt="PacketSnitch main view" width="950">
</p>

### Left Sidebar

| Element | Description |
| ------- | ----------- |
| **Target Host** | Select which IP stream to inspect |
| **Bookmarks** | Save and jump to specific packets |
| **Save JSON** | Export current dataset |
| **PCAP size** | File size of the capture |
| **Load time** | Time to parse and load data |
| **Total Packets** | Total packets in dataset |
| **Filtered Packets** | Packets matching active filter |
| **Timestamp** | Current packet's capture time |

### Toolbar

| Control | Description |
| ------- | ----------- |
| **Summary** | Switch to LLM analysis view |
| **Data** | Return to packet data view |
| **Prev / Next** | Step through packet list |
| **Filter bar** | Enter filter expressions |
| **Load JSON** | Load previously generated `hosts.json` |
| **Load PCAP** | Run backend on a `.pcap` file |
| **Use LLM** | Toggle Ollama-powered summaries |

### Packet Info Pane

- **IP Routing** — Source → destination addresses
- **Network Info** — Ports with ICANN service names
- **Data Type** — MIME type, charset, encoding, magic file type
- **Active Recon** — SSL/TLS details, server banners, DNS hostnames, web page titles (with `-a` flag)

### Packet Payload Pane

- **ASCII View** — Printable character runs from payload
- **Hex Grid** — Interactive hex dump; click to highlight bytes and see ASCII

### Right Sidebar

| Panel | Description |
| ----- | ----------- |
| **Datagram Frame** | Protocol fields (checksums, DNS, HTTP, DHCP, etc.) |
| **Location** | GeoIP: country, city, postal code, timezone |
| **Payload Entropy** | Shannon entropy as number + visual indicator |

---

## Filtering

Filter expressions use dot-notation keys, comparison operators, and boolean combinators:

```bash
# HTTPS traffic only
tcp.dst.port:443

# Traffic from China
loc.src.country:China

# High-entropy payloads (encrypted/compressed)
payload.entropy:>=7.0

# HTTP POST with JSON
http.method:POST && payload.mime:application/json

# Large encrypted payloads from external IPs
tcp.dst.port:443 && payload.len:>500 && payload.entropy:>=7.0 && ip.src.class:!=Localnet
```

- String comparisons are **case-insensitive**
- Press **Enter** to apply, clear and press **Enter** again to reset

See the [Filter Reference](Documentation/Filters.md) for the complete list of keys and syntax.

<p align="center">
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/main/Documentation/screenshots/comparison-operator-packetsnitch-ss21.png" alt="Filter example" width="600">
</p>

---

## Documentation

- 📖 [Frontend Docs](Documentation/Frontend.md) — UI reference, installation, developer setup
- ⚙️ [Backend Docs](Documentation/Backend.md) — `snitch.py` usage, arguments, output structure
- 🔎 [Filter Reference](Documentation/Filters.md) — Complete filter keys, operators, examples

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
  <a href="https://thanks.dev/oxasploits">
    <img src="https://img.shields.io/badge/Thanks.dev-Donate-orange" alt="Thanks.dev">
  </a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/bitcoin-qr.png" width="120" alt="Bitcoin">
  &nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/paypal-qr.png" width="120" alt="PayPal">
  &nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/venmo-qr.png" width="120" alt="Venmo">
</p>
