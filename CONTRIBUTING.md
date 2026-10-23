# Contributing

Issues and pull requests are welcome, in English or Japanese.

## Before you start

- **Security problems go to [SECURITY.md](SECURITY.md)**, not to public issues.
- For a large change, open an issue first so we can agree on the approach.

## Protecting your own identity

This is an anonymity project, and git records who you are.

- Commit with GitHub's no-reply address, not your personal email: `git config user.email "<id>+<username>@users.noreply.github.com"`. You can find it under GitHub **Settings → Emails**, where you can also turn on **Keep my email addresses private** and **Block command line pushes that expose my email**.
- Check that logs, screenshots and test output you attach do not contain IPs, peer IDs, Worker URLs or paths with your user name.

## Development

Requires Node.js 22.

```sh
npm ci
npm run build:core
npm run dev            # web app on http://localhost:3000
npm run dev:desktop    # desktop app
npm run check          # build core, typecheck everything, run all tests
```

## Ground rules for changes

- No shared infrastructure. Apart from the tracker, which only introduces peers and can be replaced in the settings, do not add a central server, directory, index or default relay that every user depends on. Everything goes over the P2P network or through relays run by participants.
- Anything that leaves the device must go through the onion layer unless there is a documented reason it cannot.
- Changes to the wire format, cryptography or routing need tests. When a format changes on purpose, regenerate the vectors in `packages/core/tests/protocol/vectors` (see the header of `generateVectors.ts`) and say so in the pull request.
- The UI is dark, flat and square: Google greys, no rounded corners, shadows, glass effects or animations.
- Comments and UI text in the existing code are in Japanese. Follow the style of the file you are editing.

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
