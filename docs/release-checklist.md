---
title: Release checklist
description: A maintainer-only checklist for validating and shipping keepass-agent releases.
---

# Release checklist

This page is for **maintainers**, not first-time users. Complete each gate and keep evidence for any test that cannot run.

## 1. Prepare the release

- [ ] Update `package.json` version and verify supported Node versions (22.18+ or 23.6+).
- [ ] Confirm English and Korean feature claims match the actual implementation.
- [ ] Write release notes with user-facing changes and configuration upgrade warnings.
- [ ] Review changes to `config.toml` format and agent permissions.

## 2. Run quality checks

```sh
npm ci
npm run typecheck
npm test
npm run lint:py
npm run docs:build
```

- [ ] Windows and Linux CI pass on Node 22.18 and 24.
- [ ] Python dependencies install in a clean environment.
- [ ] No required tests are failed or skipped without a documented reason.

::: warning Unverified is not passing
If a real KeePass/KPScript test, a separate OS-account test, or a supported platform check could not run, record it as **NOT_VERIFIED**. Do not label a release production-ready based only on mocked tests.
:::

## 3. Verify installation and recovery

- [ ] Windows and Linux installer dry-runs show the expected changes.
- [ ] `kp doctor` produces actionable diagnostics on a fresh profile.
- [ ] Configuration migration preserves existing policies.
- [ ] Hardened Mode can be provisioned, verified, and safely rolled back where supported.
- [ ] Existing KDBX files survive upgrades and uninstall operations.

## 4. Check the release artifact

```sh
npm run verify:artifact
npm pack --dry-run
```

- [ ] No KeePass/KPScript GPL binaries are bundled.
- [ ] No KDBX files, private keys, logs, `.env` files, `node_modules`, or temporary test files ship.
- [ ] Required launchers, documentation, and license files are included.

## 5. Review security

- [ ] Credential paths keep plaintext out of ordinary CLI/MCP output.
- [ ] Worker allowlists, destination checks, and per-agent access rules remain enforced.
- [ ] Hardened Mode remains fail-closed when isolation is missing.
- [ ] Test-only overrides such as `KEEPASS_AGENT_SERVICE_SELFTEST` are not recommended for production.
- [ ] Document remaining limitations in [Security](/security).

## 6. Publish

- [ ] Required reviews and CI gates pass on the release commit.
- [ ] Tag the reviewed version (`vX.Y.Z`).
- [ ] Attach or publish a verified artifact under the intended distribution process.
- [ ] Link [Installation](/installation), [Operations](/operations), and the release notes.
