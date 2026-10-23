# Security policy

OZ is an anonymity tool, so a bug can expose who someone is. Please report vulnerabilities privately.

## How to report

Use GitHub's private vulnerability reporting: open the [Security tab](https://github.com/jkfujinami/Oz/security) of this repository and choose **Report a vulnerability**. Do not open a public issue or pull request for an unfixed vulnerability.

Please include:

- what an attacker can learn or do (for example, link a post to an IP, identify an uploader, read sealed local data),
- what the attacker needs (a Guard, a middle node, the tracker, a relay Worker, a file host, network position),
- steps or code to reproduce it, and the version or commit you tested.

You can report anonymously. A new GitHub account that is not tied to your identity is fine.

## What is in scope

- De-anonymisation: anything that lets an observer or a malicious node link a user's IP to their posts, uploads or downloads beyond the limits listed in the README.
- Weaknesses in onion routing, cover traffic, cell padding or the Dandelion++ stem.
- Key handling, local encryption, lock and panic wipe.
- Trusted Guard list signing and verification.
- The desktop app's Electron hardening and IPC.
- The relay Worker (`packages/r2-worker`) and the tracker.

Known limits described in the README (a global passive adversary, a colluding Guard and middle node, the tracker seeing IPs) are not vulnerabilities by themselves, but ways to make them worse are.

## What to expect

This is a small project run by one person. I will acknowledge a report as soon as I can, keep it private until a fix is released, and credit you in the release notes unless you would rather stay anonymous.

## Supported versions

Only the latest release gets security fixes.
