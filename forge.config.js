const { FusesPlugin } = require("@electron-forge/plugin-fuses");
const { FuseV1Options, FuseVersion } = require("@electron/fuses");
const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");
const desc =
  "A network traffic analysis tool, designed to help users understand and monitor network activity on their devices.";
const vendor = "oxasploits, llc";
const author = "Marshall Whittaker";
const copyright = `Copyright (c) 2026 ${vendor}`;
const homepage = "https://oxasploits.github.io/PacketSnitch/";
const maintainer = "Marshall Whittaker <marshall@oxasploit.com>";

function detectPlatformFamily() {
  switch (process.platform) {
    case "win32":
      return "windows";

    case "linux":
      try {
        const osRelease = fs.readFileSync("/etc/os-release", "utf8");

        if (
          osRelease.includes("ID=debian") ||
          osRelease.includes("ID=ubuntu") ||
          osRelease.includes("ID_LIKE=debian")
        ) {
          return "debian";
        }

        if (
          osRelease.includes("ID=fedora") ||
          osRelease.includes("ID=rhel") ||
          osRelease.includes("ID=centos") ||
          osRelease.includes('ID_LIKE="rhel fedora"') ||
          osRelease.includes("ID_LIKE=fedora") ||
          osRelease.includes("ID_LIKE=rhel")
        ) {
          return "redhat";
        }
      } catch {
        // ignore
      }

      return "linux";

    default:
      return process.platform;
  }
}

const platform = detectPlatformFamily();
const makers = [];
if (platform === "windows") {
  makers.push({
    name: "@electron-forge/maker-squirrel",
    config: {
      loadingGif: path.resolve(__dirname, "logo/ps-install-loop.gif"),
      iconUrl:
        "https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-icon.ico",
      setupIcon: path.resolve(__dirname, "logo/ps-installer-icon.ico"),
      name: "PacketSnitch",
      setupExe: `PacketSnitch-${require("./package.json").version}-Installer.exe`,
      vendor: vendor,
      authors: author,
      copyright: copyright,
      primaryIcon: path.resolve(__dirname, "logo/ps-icon.ico"),
      productName: "PacketSnitch",
      description: desc,
    },
  });
}

if (platform === "debian") {
  makers.push({
    name: "@electron-forge/maker-deb",
    config: {
      primaryIcon: path.resolve(__dirname, "logo/ps-icon.png"),
      name: "packetsnitch",
      authors: author,
      copyright: copyright,
      productName: "PacketSnitch",
      description: desc,
      homepage: homepage,
      maintainer: maintainer,
      categories: [
        "Utility",
        "Network",
        "kali-network-information",
        "kali-network-service-discovery",
        "kali-network-sniffing",
      ],

      vendor: vendor,
      icon: path.resolve(__dirname, "logo/ps-icon-rounded.png"),
      desktopTemplate: path.resolve(__dirname, "desktop.ejs"),
    },
  });
}

if (platform === "redhat") {
  makers.push({
    name: "@electron-forge/maker-rpm",
    config: {
      options: {
        name: "packetsnitch",
        authors: author,
        copyright: copyright,
        productName: "PacketSnitch",
        description: desc,
        homepage: homepage,
        maintainer: maintainer,
        categories: ["Utility", "Network"],
        vendor: vendor,
        icon: path.resolve(__dirname, "logo/ps-icon-rounded.png"),
        desktopTemplate: path.join(__dirname, "desktop.ejs"),
      },
    },
  });
}

module.exports = {
  packagerConfig: {
    icon: path.join(__dirname, "logo", "ps-icon"),
    asar: true,
    // Register the ``packetsnitch://`` URL scheme at the OS level so
    // clicking a deeplink in the user's browser (e.g. from the catalog
    // server's checkout-success page) launches PacketSnitch and routes
    // the URL into the main process for license reconciliation.
    protocols: [
      {
        name: "PacketSnitch Deeplink",
        schemes: ["packetsnitch"],
      },
    ],
    extraResource: [
      // PyInstaller produces `snitch` on Linux/macOS and `snitch.exe` on Windows,
      // placed directly in src/backend/ (not in a subdirectory). Reference the
      // correct binary for the current platform so forge doesn't try to lstat
      // a non-existent directory on Windows.
      process.platform === "win32"
        ? "src/backend/snitch.exe"
        : "src/backend/snitch",
      "src/backend/common/",
      "src/data/new_session.json",
      "src/data/goodies.txt",
      "src/data/valid-keys.txt",
      "config/models.json",
      "themes",
      "src/ui/fragments",
    ],
  },
  rebuildConfig: {},
  makers,
  plugins: [
    {
      name: "@electron-forge/plugin-auto-unpack-natives",
      config: {},
    },
    {
      name: "@electron-forge/plugin-webpack",
      config: {
        mainConfig: "./webpack.main.config.js",
        renderer: {
          config: "./webpack.renderer.config.js",
          entryPoints: [
            {
              html: "./src/index.html",
              js: "./src/renderer.js",
              name: "main_window",
              preload: {
                js: "./src/preload.js",
              },
            },
          ],
        },
      },
    },
    // Fuses are used to enable/disable various Electron functionality
    // at package time, before code signing the application
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
    }),
  ],
};
