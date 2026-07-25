# PacketSnitch

## Overview

A network analysis platform that transforms packet captures into searchable, protocol-aware intelligence, helping security professionals, developers, and researchers rapidly uncover hosts, credentials, files, locations, protocols, anomalies, threat intel, and other actionable insights.

<p align="center"><a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.png">
<img alt="PacketSnitch Stats Workspace" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.png" width="1000" >
</a></p>

## What's New in v2.3

- **Manual file carving** in Conv with a clickable offset picker; carved files are surfaced in Stats.
- **Stream / archive extraction** — extract files from compressed or archive payloads directly into the carved files list.
- **Threat Intel sub-tab** in Conv with a **VirusTotal** card (auto-select, detection ratio, last analysis, community score) plus **IPSum** and **Tor** reputation lookups. **Cross Reference Hash** on the Hashes sub-tab sends any focused / selected hash straight to Threat Intel.
- **Filter autocomplete** in the filter bar.
- **Better IPv6 support** with bracketed endpoints and queries that work with raw IPv6 literals.
- **Big-endian nanosecond-resolution pcap** support and a fix for the single-host blank List panel.
- **Analyze Subnet (Conv)** for IPv4/IPv6 subnet math with WHOIS, GeoIP, Shodan, IPSum, and Tor lookups, plus optional **Nmap `-sV`** service enumeration (off by default).
- **Backend HTTP service** (`/process`, `/control`, `/version`, `/status`, `/geoip`, `/whois`, `/ipsum`, `/tor`, `/shodan`) replacing per-run spawn.
- **Worldmap / Internet heatmap** in Stats (Entire Capture / Filtered scope, Packets / Bytes intensity).
- **PGP workspace** in the Crypt tab with armor / binary conversions, OpenPGP decrypt/verify, packet-derived passphrase candidates, and keystore promotion of validated private keys.
- **Plugin engine** with sandboxed VM runtime and dot-notation capabilities (`fs`, `net`, `backend`, `ui.dom`, `notes`, `settings`, `themes`, etc.).
- **Settings workspace** with General, Backend, LLM, Debug, and About sub-tabs, persisted to `userData/config/settings.json`.
- **LLM moved to the frontend** (gated by `llm.activeByDefault` and Ollama startup checks), with **Export Summary as HTML** including inline carved images.
- **Keystore auto-build** for HTTP Basic/form/cookies, FTP, SMTP, IMAP, RDP, and SIP credentials, plus hostnames, IPv4s, emails, and URLs from packet text.
- **Saved-filter library** with labeled entries, in-app modal dialogs, and right-click save/remove on the filter bar.
- **Filter bookmark expressions** (`bookmark:true` / `bookmark:false`) with a **Bookmarked** virtual option in Target Host.
- **Lazy / progressive capture loading** with packet stub index, hydration on demand, and a partial-data warning until completion.
- **Notes workspace** with `marked` Markdown preview (GFM tables) and LLM-generated notes added collapsed by default.

See [RELEASE_NOTES.md](https://github.com/oxasploits/PacketSnitch/blob/main/RELEASE_NOTES.md) for the full changelog.

## Documentation

- [**Backend Documentation**](backend.md) — Python backend (`snitch.py`) plus the Electron bridge HTTP service mode: usage, arguments, output structure, transport modes, and searchable attributes.
- [**Frontend Documentation**](frontend.md) — Electron frontend: UI workspaces, worldmap/heatmap, PGP tooling, settings, LLM flows, and bridge controls.
- [**Plugins Documentation**](plugins.md) — Combined Themes + Plugins reference: theme engine schema plus complete plugin engine tutorial and hello-snitch sample code.
- [**Context Menu Reference**](context-menu.md) — Right-click context menu: copy, convert, filter, keystore, notes, and export options.
- [**Filter Reference**](filters.md) — Complete guide to the filter bar: all filter keys, search syntax, operators, boolean combinators, and examples.

## Demo

<p align="center">
<iframe width="1000" height="562" src="https://www.youtube.com/embed/WCEZkubllg8?si=3GnLIt4y4CxvIjmK" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
</p>

### If you would like to follow along with the video here are the necessary links to set up your own environment!

* The [pcap with the captured exploitation](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/exploit.pcap).
* Also here is the [source code](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hustoj_problem_import_rce.rb) to the exploit.
* Here is the [vulnerable software](https://github.com/zhblue/hustoj/releases/tag/25.12.10)


## Quick Start

**Download** -- grab the latest prod release:

The latest release can be found on the [releases page](https://github.com/oxasploits/PacketSnitch/releases).

_OR..._

**Build** -- build it from source code:

1. Clone the repository, this can be done via: `git clone https://github.com/oxasploits/PacketSnitch.git`.
2. Move into the PacketSnitch direcotry: `cd PacketSnitch`.
3. Use NPM to install build dependancies: `npm install`.
4. If on Linux (specifically Fedora) run: `npm run patch-rpm-build`.
5. Build the project, this compiles the backend and frontend: `npm run make`.
6. You can now launch the dev version using: `npm start`!
7. Note: _The installer is also packaged at_: `./out/make/*`

**Install** -- install the package:

Linux:

```bash
sudo dnf install ./out/make/*/packetsnitch-*.rpm  # redhat/centos/fedora
sudo apt install ./out/make/*/packetsnitch-*.deb  # debian/kali/ubuntu
```

Windows:

Click: `PacketSnitchInstaller.exe`

**Launch** — launch the desktop app:

```bash
packetsnitch                      # Linux
packetsnitch.exe (or click)       # Windows
```

## Samples

**Load a capture and start analyzing!**

In the samples folder there are some sample captures for you to play with.  PacketSnitch is compatible with both
pcap *and* pcapng style captures.

Note: *Some of the samples folder captures are for internal testing purposes, and their protocols have varying coverage as far as
compatibility goes inside PacketSnitch.  Some may even crash PacketSnitch or any number of other things!  You have been warned!*

Some captures you can test the code with:

* [HTTP with compression](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/pcaps/http_gzip.pcap)
* [HTTP with images to carve](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/pcaps/http_with_jpegs.pcap)
* [FTP with some tranferred files and creds](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/pcaps/ftp.pcap)
* [Some BGP packets](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/pcaps/bgp.pcapng)
* [Some ATM packets from an DSL modem](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/pcaps/atm.pcap)


If you want to test anything else, a great resource is the [Wireshark Sample Captures Page](https://wiki.wireshark.org/SampleCaptures), I would get started there.

Have fun!

## License

[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Contact Resources

Project Head: Marshall Whittaker <marshall@oxasploits.com>

## Thanks / Contibutions

- Marshall Whittaker (project design, primary frontend/backend dev)
- Vesteria (backend tor node detection code)
- blissfulboy (frontend design suggestions and feedback)
- kusanagi (frontend feedback and some sponsorship stuff)
- Martin Ollivere (Rat on wheel spinning gif)
- tiamo64 (Performance optimizations)
- aestetix (inspiration on how this documentation page should be formatted)
- 2600net staff (hosting the irc server where our dev channel resides)
- Everyone else who has tested or contributed in some way, big or small, thank you!

## Sponsors

- <a href="https://buymeacoffee.com/oxagast">Sponsor PacketSnitch!</a>

_If you sponsor PacketSnitch, your name and a link of your choice will be added here!_
