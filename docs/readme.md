

## Overview

PacketSnitch is a network packet analysis tool consisting of a Python backend for extracting payloads and rich metadata from `.pcap` files, and an Electron-based frontend for browsing, filtering, visualizing, and post-processing the results. Recent frontend additions include the Internet Heatmap worldmap view, the PGP workspace, expanded Settings and bridge controls, saved-filter library workflows, context-menu manual Conv file import, and frontend-driven LLM workflows.

## Screenshot

<a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.png">
<img alt="PacketSnitch Stats Workspace" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.png" width="1280">
</a>


## Documentation

- [**Backend Documentation**](backend.md) — Python backend (`snitch.py`) plus the Electron bridge HTTP service mode: usage, arguments, output structure, transport modes, and searchable attributes.
- [**Frontend Documentation**](frontend.md) — Electron frontend: UI workspaces, worldmap/heatmap, PGP tooling, settings, LLM flows, and bridge controls.
- [**Themes Documentation**](themes.md) — Theme engine reference: theme JSON schema, custom logos, color variables, and opacity controls.
- [**Context Menu Reference**](context-menu.md) — Right-click context menu: copy, convert, filter, keystore, notes, and export options.
- [**Filter Reference**](filters.md) — Complete guide to the filter bar: all filter keys, search syntax, operators, boolean combinators, and examples.

## Demo

<p align="center"><iframe width="1280" height="720" src="https://www.youtube.com/embed/fSeLVu0ElZk" title="" frameBorder="0"   allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"  allowFullScreen></iframe></p>


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

* [HTTP with compression](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/http_compressions.pcap)
* [HTTP with images to carve](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/http_with_jpegs.pcap)
* [FTP with some tranferred files and creds](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/ftp.pcap)
* [Some BGP packets](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/bgp.pcapng)
* [Some ATM packets from an DSL modem](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/atm.pcap)
* [An exploit working against HUSTOJ](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/exploit.pcap)

If you want to test anything else, a great resource is the [Wireshark Sample Captures Page](https://wiki.wireshark.org/SampleCaptures), I would get started there.

Have fun!

## License

[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

Marshall Whittaker <marshall@oxasploits.com>

## Thanks / Contibutions

- blissfulboy (frontend design suggestions and feedback)
- kusanagi (frontend feedback and some sponsorship stuff)
- Martin Ollivere (Rat on wheel spinning gif)
- tiamo64 (Performance optimizations)
- Everyone else who has tested or contributed in some way, big or small, thank you!

## Sponsors

- <a href="https://github.com/sponsors/oxagast">Sponsor on Github</a>
- <a href="https://thanks.dev/oxasploits">Sponsor on Thanks.Dev</a>
- <a href="https://buymeacoffee.com/oxagast">Sponsor on Buy me a Coffee</a>

_If you sponsor PacketSnitch, your name and a link of your choice will be added here!_
