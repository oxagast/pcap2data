# Contributing to PacketSnitch

Thank you for your interest in contributing to PacketSnitch!

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
