<p align="center">
<a href="https://oxasploits.github.io/PacketSnitch/" alt="PacketSnitch by oxasploits"><img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-tagline-flicker.gif"></a>
</p>

### Overview

PacketSnitch is a network packet analysis tool consisting of a Python backend for extracting payloads and rich metadata from `.pcap` files, and an Electron-based frontend for browsing, filtering, and visualizing the results.

### Screenshot

<p align="center">
<img alt="packetsnitch works!" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/ps-working2.gif" width=1200>
</p>

### Documentation

- [**Backend Documentation**](Backend.md) — Python backend (`snitch.py`): usage, arguments, output structure, and the full list of searchable attributes produced in the JSON output.
- [**Frontend Documentation**](Frontend.md) — Electron frontend: UI output frames, query box, and data type conversions.
- [**Context Menu Reference**](ContextMenu.md) — Right-click context menu: copy, convert, filter, keystore, notes, and export options.
- [**Filter Reference**](Filters.md) — Complete guide to the filter bar: all filter keys, search syntax, operators, boolean combinators, and examples.

### Quick Start

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

Load a pcap or pcapng file, and start analyzing!

### License

GPL v3

### Author

Marshall Whittaker <marshall@oxasploits.com>

### Thanks / Contibutions

- blissfulboy (frontend design suggestions and feedback)
- kusanagi (frontend feedback and some sponsorship stuff)
- Martin Ollivere (Rat on wheel spinning gif)
- tiamo64 (Performance optimizations)
- Everyone else who has tested or contributed in some way, big or small, thank you!

### Sponsors

- <a href="https://github.com/sponsors/oxagast">Sponsor on Github</a>
- <a href="https://thanks.dev/oxasploits">Sponsor on Thanks.Dev</a>
- <a href="https://buymeacoffee.com/oxagast">Sponsor on Buy me a Coffee</a>

_If you sponsor PacketSnitch, your name and a link of your choice will be added here!_
