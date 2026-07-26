# PacketSnitch

## Overview

A network analysis platform that transforms packet captures into searchable, protocol-aware intelligence, helping security professionals, developers, and researchers rapidly uncover hosts, credentials, certificates, files, locations, protocols, anomalies, threat intelligence, and other actionable insights.



<p align="center"><a href="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.png">
<img fetchpriority="high" alt="PacketSnitch Stats Workspace" src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/docs/screenshots/packetsnitch-preview.webp" width="1000" height="562" >
</a></p>

## Documentation

- [**Backend Documentation**](backend.md) — Python backend (`snitch.py`) plus the Electron bridge HTTP service mode: usage, arguments, output structure, transport modes, and searchable attributes.
- [**Frontend Documentation**](frontend.md) — Electron frontend: UI workspaces, worldmap/heatmap, PGP tooling, settings, LLM flows, and bridge controls.
- [**Plugins Documentation**](plugins.md) — Combined Themes + Plugins reference: theme engine schema plus complete plugin engine tutorial and hello-snitch sample code.
- [**Context Menu Reference**](context-menu.md) — Right-click context menu: copy, convert, filter, keystore, notes, and export options.
- [**Filter Reference**](filters.md) — Complete guide to the filter bar: all filter keys, search syntax, operators, boolean combinators, and examples.

## Demo

<p align="center">
<iframe loading="lazy" width="1000" height="562" src="https://www.youtube.com/embed/WCEZkubllg8?si=3GnLIt4y4CxvIjmK" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
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

* [HTTP with compression](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/http_compressions.pcap)
* [HTTP with images to carve](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/http_with_jpegs.pcap)
* [FTP with some tranferred files and creds](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/ftp.pcap)
* [Some BGP packets](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/bgp.pcapng)
* [Some ATM packets from an DSL modem](https://github.com/oxasploits/PacketSnitch/raw/refs/heads/main/samples/atm.pcap)


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
- Anupam Mediratta (path traversal bugfix)
- 2600net staff (hosting the irc server where our dev channel resides)
- Everyone else who has tested or contributed in some way, big or small, thank you!

## Sponsors

- <a href="https://buymeacoffee.com/oxagast">Sponsor PacketSnitch!</a>

_If you sponsor PacketSnitch, your name and a link of your choice will be added here!_
