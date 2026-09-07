# Contributing to PacketSnitch

Thank you for your interest in contributing to PacketSnitch!

## Build Environment Setup

PacketSnitch is an **Electron + Python** desktop application. To compile from source you need:

### System Requirements

- **Node.js** ≥ 12.11.0
- **npm** (latest, comes with Node.js)
- **Python** 3.8+ (for the backend analyzer)
- **pip** (latest, for Python dependencies)
- **PyInstaller** (installed via `requirements.txt`)

### Linux Build Dependencies

```bash
# Debian/Ubuntu/Kali
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv
sudo apt-get install -y libusb-1.0-0-dev libusb-dev libudev-dev
sudo apt-get install -y rpm             # only for RPM package builds

# Fedora/RHEL
sudo dnf install -y python3-pip python3-venv
sudo dnf install -y libusbx-devel libudev-devel

# Install uv (optional, speeds up Python dependency installation)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Windows Build Dependencies

- [Node.js LTS](https://nodejs.org/) (includes npm)
- [Python 3.8+](https://www.python.org/downloads/) (add to PATH)
- [Git for Windows](https://gitforwindows.org/)

### Quick Start Build

```bash
# Clone the repository
git clone git@github.com:oxasploits/PacketSnitch.git
cd PacketSnitch

# Full build (installs deps, patches, builds backend + frontend)
npm run make

# For RPM-based distros (Fedora/RHEL), apply RPM patches first
npm run patch

# Run in development mode
npm start
```

### Build Output

After a successful `npm run make`:

- **Linux (DEB):** `out/make/deb/x64/` → `sudo dpkg -i ./packetsnitch-*.deb`
- **Linux (RPM):** `out/make/rpm/x64/` → `sudo dnf install ./packetsnitch-*.rpm`
- **Windows:** `out/make/squirrel.windows/x64/` → run `packetsnitch-installer.exe`

### Testing Your Build

```bash
# Run all tests (backend + frontend)
npm run tests

# Backend tests (Python/pytest)
npm run test:backend

# Frontend tests (Jest)
npm run test:frontend

# Or run backend tests directly with pytest
pytest tests/test_backend_compile.py tests/test_backend_json.py tests/test_backend_server.py --maxfail=1
```

### Optional: Faster Python Installs with `uv`

If you have [`uv`](https://github.com/astral-sh/uv) installed, the build scripts will use it automatically:

```bash
# Install uv (Linux/macOS)
curl -LsSf https://astral.sh/uv/install.sh | sh

# The build:deps script detects uv and uses it automatically
npm run build:deps
```

### Troubleshooting

**Python dependency errors on Linux:**  
If `pip3 install` fails with `externally-managed-environment`, use `--break-system-packages`:

```bash
pip3 install -r src/backend/requirements.txt --break-system-packages
```

**PyInstaller build fails:**  
Ensure `src/backend/snitch` is executable and all Python dependencies are installed.

## Project Philosophy

PacketSnitch is **open source**, distributed under the terms of the [GPL-3.0 license](./LICENSE.md). That said, not everything is open source in practice:

- **Themes, plugins, and premium features** may be distributed in binary form and are **not subject to the GPL** in the sense that the project maintainer reserves the right to keep those portions closed source. See the [EULA](https://packetsnitch.com/EULA) for full terms.
- If you contribute a theme, plugin, or similar component, be aware that it may be incorporated into a closed-source product tier without obligation to disclose the source.
- When in doubt about whether something is open to contribution, open an issue or reach out before investing significant effort.

## Ground Rules

### Be decent

**Don't be an asshole.** Racism, sexism, homophobia, transphobia, anti-Semitism, harassment, or any form of hate speech will not be tolerated. If you wouldn't say it in a professional workplace, don't say it here. Your code will be pulled and your contributions rejected — full stop.

### Marshall Whittaker is the primary project maintainer

Marshall Whittaker (`oxagast`) is the sole project maintainer. **What Marshall says goes.** If there is a disagreement about direction, design, or policy, his decision is final. Please respect that.

### You own what you write — but we can use it

By submitting a pull request, you retain copyright to your contributions. You grant the project a perpetual, irrevocable license to use, modify, and distribute your code — including in closed-source products as described above.

### Contributors are free to make their own decisions

Outside of the maintainer's final say on project direction, **contributors are trusted to make their own calls** about how to structure and implement the parts of the codebase they are working on. You do not need approval for every detail — use your judgment and be prepared to discuss it if asked.

## How to Contribute

1. **Fork the repository** and create a branch for your change.
2. **Make your change** — keep patches focused and minimal.
3. **Test** — run `npm test` and make sure both backend and frontend tests pass.
4. **Open a pull request** — describe *why* the change is needed, not just *what* it does.
5. **Be responsive** — maintainers may request changes before merging.

## Pull Request Process

### Before You Start

- Check the [issue tracker](https://github.com/oxasploits/PacketSnitch/issues) to see if the issue or feature is already being addressed.
- For large changes, open an issue first to discuss the approach before investing significant effort.

### Creating Your Pull Request

1. **Fork the repo** via GitHub.

2. **Clone your fork:**

   ```bash
   git clone git@github.com/your-username/PacketSnitch.git
   cd PacketSnitch
   ```

3. **Add the upstream remote:**

   ```bash
   git remote add upstream git@github.com/oxagast/PacketSnitch.git
   ```

4. **Create a feature branch:**

   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

5. **Make your changes** following the [style guides](#style).

6. **Run tests** to ensure nothing is broken:

   ```bash
   npm run tests
   ```

7. **Push to your fork:**

   ```bash
   git push origin feature/your-feature-name
   ```

8. **Open a pull request** on GitHub against `main`:

   - Use a clear title describing *why* the change is needed.
   - Reference any related issues (e.g., "Closes #123").
   - If your change introduces new behavior, add or update tests.

### PR Checklist

- [ ] Code follows the project's ESLint and style conventions.
- [ ] Backend changes include tests (if applicable).
- [ ] New features are documented.
- [ ] New features are checked off in [ROADMAP.md](./ROADMAP.md) (if applicable).
- [ ] `npm run tests` passes locally.
- [ ] PR description explains *why*, not just *what*.

### What Gets Merged

- Changes that improve PacketSnitch without breaking existing functionality.
- Bug fixes with tests.
- Improvements that align with the project's goals.
- Changes the maintainer agrees with.

## Bug Reports & Feature Requests

Use the [issue templates](./.github/ISSUE_TEMPLATE/) to report bugs or request features. For security-sensitive issues, email directly:

- **Bugs:** <bugs@packetsnitch.com>
- **Support:** <support@packetsnitch.com>

## Style

- JavaScript follows the ESLint rules in [`.eslintrc.js`](.eslintrc.js).
- Python follows PEP 8 with a soft 120-character line limit.
- Commit messages should be concise and descriptive.

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0. Your code is yours, but by contributing you give the maintainer permission to use it as described above.
