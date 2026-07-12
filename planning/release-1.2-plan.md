# Rustinel 1.2 Release Plan

Status: **release candidate green** — `v1.2.0-rc.4` published; only close-out work remains
Target: Rustinel 1.2.0
Tracking issue: https://github.com/Karib0u/rustinel/issues/106
Last updated: 2026-07-11

All engineering fixes and RC validation are done. What remains is documentation
close-out, the landing page, and the final `v1.2.0` promotion.

## Goal

Ship Rustinel 1.2 with a simple, trustworthy path: `test it -> keep it -> check it`.

Final user-facing flow (live only after `v1.2.0` + website install URLs):

```bash
# Linux and macOS
curl -fsSL https://rustinel.io/install.sh | sh -s -- --run
sudo rustinel setup --yes
rustinel doctor
```

```powershell
# Windows PowerShell
irm https://rustinel.io/install.ps1 | iex
rustinel setup --yes
rustinel doctor
```

## Where we are

- `Cargo.toml` is at `1.2.0-rc.4`. RCs 1–4 are published as GitHub prereleases;
  `latest`/stable remains `v1.1.4` (intended — no RC took `latest`).
- CI on `main` HEAD is green (CI, Docs, RSigma Engine Parity).
- **Full RC smoke matrix is green:** Linux and Windows portable+managed passed on
  official RC2; macOS portable+managed passed on official RC4. RC3/RC4 only
  changed macOS setup and docs, so the Linux/Windows binaries are functionally
  unchanged.
- **Official RC4 macOS validation passed (2026-07-11):** archive checksum and
  version, deep managed-app signature, Apple notarization, the exact
  `./rustinel setup --yes --force` flow, launchd reaching `running`, `doctor`
  clean (expected Full Disk Access detectability warning only), restart/stop/start
  lifecycle, and manual Sigma hot reload from the official asset.

### RC history (brief)

- RC1: first prerelease. Found portable rule-path and managed catalog-path
  defects incompatible with the published package layout.
- RC2: fixed portable/managed paths, catalog validation, and Linux `CAP_PERFMON`.
  Linux and Windows passed; macOS managed failed (setup copied only the
  executable, producing an invalid app bundle).
- RC3: macOS bundle-copy fix (PR #154). Still failed via the documented
  `./rustinel` symlink path, which resolved to copying only the executable.
- RC4: macOS symlink-resolution fix (PR #157) + onboarding/operations docs
  (PR #156, closed #110) + release prep (PR #158). **Viable release candidate.**

## Issue status

- #109 (installer UX) — CLOSED.
- #110 (onboarding docs) — CLOSED via PR #156.
- #130 (Windows VC++ runtime docs) — CLOSED; documented in PR #156.
- #106 (tracking, p0) — OPEN. Remaining criteria to confirm and check off:
  one-command promotion, cross-platform managed consistency, doctor
  diagnosability, README simplification. Close after `v1.2.0` ships.
- Everything else open (#135–#151, #32, #35, PR #153, etc.) is post-1.2 backlog,
  not a release blocker.

## Remaining work to ship v1.2.0

1. [x] **Installer output: feature-detect the promotion command (decided).**
   In `scripts/install/install.sh` and `install.ps1`, only print the
   `sudo ./rustinel setup --yes` promotion block when the installed binary
   actually supports `setup` (probe `./rustinel setup --help` and print the
   block only on success). This is the clean fix for the `main`-served installer
   advertising the 1.2-only `setup` command to older/stable `--version`
   installs. Chosen over a hard-coded version check so it self-corrects across
   releases. Land before the website points at these scripts.
   Done: `setup_supported()` in `install.sh` and `Test-SetupSupported` in
   `install.ps1` gate the promotion block on a successful `setup --help` probe.
2. [ ] **Landing page (Phase 6).** Publish only after final assets exist.
   Code is written and build-verified (redirects + `QuickStart.astro` rewrite);
   publish is still gated on `v1.2.0` being `latest`.
3. [x] **Reconcile and close #106.** Confirmed all acceptance criteria and
   closed the tracking issue with a reconciliation comment
   (comment 4950069426).
4. [x] **Write `v1.2.0` release notes** covering installer, setup, doctor,
   service, rules, and macOS status. Composed; to be applied to the GitHub
   release body after the tag publishes (workflow auto-generates Downloads +
   Installer + PR list, highlights prepended on top).
5. [ ] **Cut and promote `v1.2.0` (Phase 8).** Version bump `1.2.0-rc.4` ->
   `1.2.0` committed to `release/1.2.0` (PR #172, ready). Remaining: merge to
   `main`, then tag + push `v1.2.0` (irreversible — awaiting go-ahead).
6. [ ] **Post-release close-out (Phase 9).**
7. [ ] *(Optional, low risk)* Re-confirm Linux/Windows portable+managed on the
   RC4 asset — binaries are unchanged, so this is belt-and-suspenders.

## Release decision rule

Ship `v1.2.0` only when:

- #106, #109, #110 user-visible acceptance criteria pass. *(#109/#110 done.)*
- At least one clean Linux VM passes portable and managed flows. *(done, RC2)*
- Windows passes portable and managed flows. *(done, RC2)*
- macOS passes portable evaluation and has documented managed status. *(done, RC4)*
- Release assets install from GitHub without local build dependencies. *(done)*
- Website install URLs work for the stable release path. *(pending — Phase 6)*

## Phase 6: Landing page

Repo: `/Users/theo/src/rustinel-front-final` (Astro + Cloudflare Workers static
assets, `trailingSlash: 'always'`). Publish only after `v1.2.0` is `latest`.

Site facts that shape this work:

- Version is read from GitHub `/releases/latest` (`src/lib/github.ts`,
  `getGitHubMeta`), which ignores prereleases. The site therefore cannot display
  an RC version — no gating change is needed, just confirm it flips to `1.2.0`
  once `v1.2.0` is `latest`.
- `public/_redirects` already serves Cloudflare redirects (trailing-slash 301s);
  add the install-script routes there.
- `src/components/QuickStart.astro` currently shows a download-extract-run flow
  with `releases/latest/download/...` archive URLs and no `setup` step. This is
  the component to rewrite for the `test it / keep it / check it` story.

Tasks:

- [x] Add install-script routes to `public/_redirects`:

```text
/install.sh   https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh   302
/install.ps1  https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.ps1  302
```

- [x] Rewrite `QuickStart.astro` to lead with the three-command flow per
  platform tab, keeping the existing tab switcher and `__VERSION__` token:
  - Linux/macOS: `curl -fsSL https://rustinel.io/install.sh | sh -s -- --run`,
    then `sudo rustinel setup --yes`, then `rustinel doctor`.
  - Windows: `irm https://rustinel.io/install.ps1 | iex`, then
    `rustinel setup --yes`, then `rustinel doctor`.
  - Keep the macOS experimental note and Full Disk Access callout.
- [x] Keep direct release-archive downloads and build-from-source as secondary
  (demote the current archive steps rather than delete them). Archive steps now
  live in a collapsed `<details>` disclosure below the three-command tabs.
- [ ] Confirm the displayed version resolves to `1.2.0` after promotion.

Test locally before promoting:

```bash
cd /Users/theo/src/rustinel-front-final && pnpm install && pnpm build && pnpm dev
```

Pass criteria: `curl -fsSL https://rustinel.io/install.sh` and the `install.ps1`
URL return the installer scripts (302 to raw `main`), Quick Start leads with the
three-command flow and references no RC, the displayed version is `1.2.0`, and
mobile/desktop layouts remain readable.

## Phase 8: Final 1.2.0 release

Only after the landing page is ready and the release notes are written.

- [ ] Bump version `1.2.0-rc.4` -> `1.2.0`, commit, merge to `main`.
- [ ] Tag and push the final release:

```bash
git fetch origin && git checkout main && git pull --ff-only
git tag -a v1.2.0 -m "Rustinel v1.2.0"
git push origin v1.2.0
```

- [ ] Confirm the release is not a prerelease and is marked `latest`.
- [ ] Confirm every asset and checksum exists.
- [ ] Run installer smoke with `--version 1.2.0`, then with the stable
  `https://rustinel.io/install.sh` and `install.ps1` URLs. Verify the Windows
  VC++ runtime prerequisite or that the installer gives a clear diagnostic.

## Phase 9: Post-release

- [x] Confirm `releases/latest` resolves to `v1.2.0` and the frontend shows it.
  `releases/latest` -> `v1.2.0`; `/api/github-meta` returns `1.2.0`
  (`isFallback: false`); site renders "Download v1.2.0".
- [x] Confirm website install commands use stable URLs. `rustinel.io/install.sh`
  and `install.ps1` 302 -> raw `main` and deliver the scripts; QuickStart leads
  with the `rustinel.io` three-command flow. README + docs migrated to
  `rustinel.io` URLs in PR #173 (follow-up).
- [x] Close #106 with links. Closed with a reconciliation comment referencing
  #109/#110 and the close-out work.
- [x] `v1.2.0` release notes / changelog written and applied to the release body
  (curated highlights + full change list from `v1.1.4`).
- [ ] File follow-up issues for anything deferred. Deferred items already
  tracked (#111 Phase 2, backlog). Optional new follow-up: migrate the Release
  workflow body install commands to `rustinel.io` (flagged in PR #173).
- [ ] Remove RC test directories and managed test installs on local hosts.
  (Local machine task — run the cleanup block below manually.)

Cleanup:

```bash
# Linux / macOS
sudo ./rustinel service uninstall || true
sudo rm -rf /opt/rustinel /etc/rustinel /var/lib/rustinel /var/log/rustinel   # Linux
sudo rm -rf /usr/local/var/rustinel "/Library/Application Support/Rustinel"    # macOS
rm -rf ~/rustinel ~/rustinel-rc-test
```

```powershell
# Windows
.\rustinel.exe service uninstall
Remove-Item -Recurse -Force "C:\Program Files\Rustinel" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\ProgramData\Rustinel" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\rustinel-rc-test" -ErrorAction SilentlyContinue
```

## Non-goals for 1.2

No package-manager integration, no fleet management, no rules-catalog trust-model
change, no RC as the default website download, no docs that make unreleased
commands look stable.
