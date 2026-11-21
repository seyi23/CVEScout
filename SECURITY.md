# Security Policy

CVEScout is a security tool, so vulnerabilities in CVEScout itself are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** in this repository
(<https://github.com/seyi23/CVEScout/security/advisories/new>).

Please include the affected version, steps to reproduce and the impact. You will get an answer within
7 days. Fixed issues are credited in the release notes unless you prefer otherwise.

## Scope

In scope: the app, the `cvescout` CLI, the build/release scripts and workflows – for example code execution
through crafted advisory data, unsafe handling of downloaded files, leaking local data to the network.

Out of scope: wrong or missing vulnerability matches (please use the *False positive* or *Add software*
issue templates), and vulnerabilities in the data sources themselves (BSI, NVD, CISA).

## Supported versions

Only the latest release receives fixes.
