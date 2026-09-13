# Dogfooding checklist — v1.0 pre-release

One week of running psm against my own machines before tagging v1.0.
The goal is to catch the class of issues automated tests miss: usability
snags, real-world event volume, docs that read fine in a vacuum but are
wrong on a fresh box.

Log annoyances in the "notes" column and mirror the important ones into
`todo.md` under a "v1.0 blockers" heading before tagging.

## Daily loop

Every morning:

```powershell
psm scan this-pc
psm scan mbp --ssh user@mbp.local
psm scan pixel
psm report daily --last 24h
psm db verify
```

If any command errors out, snapshot the DB (`copy %LOCALAPPDATA%\psm\psm.sqlite
psm-snap-YYYYMMDD.sqlite`) and investigate before continuing.

## Per-platform matrix

### Windows (day 1–7)

| Day | Action to intentionally trigger | Expected event | Expected alert |
|---|---|---|---|
| 1 | Install baseline; do nothing | — | — |
| 2 | Drop `test.exe` in `%APPDATA%`, add to Run key | `file:*` added + `persist:*` added | unsigned-in-run-key |
| 3 | Modify an existing file under the walk path | `file:*` changed | none, unless unsigned |
| 4 | Install a Chrome extension with broad host permissions | `ext:chrome:*` added | new-browser-extension-all-urls |
| 5 | Remove the Run key from day 2 | `persist:*` removed | none |
| 6 | Elevated scan — first time | new modules appear as *added* (they weren't in the baseline capabilities), NOT as false positives | — |
| 7 | Delete `test.exe`, `psm scan` | `file:*` removed | none |

### macOS (day 1–7)

| Day | Action | Expected event | Expected alert |
|---|---|---|---|
| 1 | Baseline via SSH | — | — |
| 2 | Install a LaunchAgent that runs a shell script | `persist:macos:LaunchAgent:*` added | (rule pending — verify raw event) |
| 3 | Grant `Full Disk Access` to a new app in System Settings | `perm:<pkg>:FDA` added | (rule pending) |
| 4 | Change the shim modules list (`--modules apps,persistence`) — verify gaps surface | scan report shows `permissions/files/processes/network` as gaps | — |
| 5 | Remove the LaunchAgent from day 2 | `persist:*` removed | — |
| 6 | Ingest a manually-collected envelope via `psm ingest macos` instead of SSH | same events as SSH mode | same alerts |
| 7 | Kill sshd's Full Disk Access → run scan | `permissions: fda-missing` gap | — |

### Android (day 1–7)

| Day | Action | Expected event | Expected alert |
|---|---|---|---|
| 1 | Baseline | — | — |
| 2 | Sideload a known-clean APK via `adb install` | `pkg:*` added, `installer=sideload` | sideloaded-install |
| 3 | Grant that app runtime permission (e.g. RECORD_AUDIO) | `perm:<pkg>:RECORD_AUDIO` added | (not by itself — sideload rule already fired) |
| 4 | Enable accessibility service for that app | `perm:<pkg>:special:accessibility` added | new-accessibility-grant |
| 5 | Uninstall the app | `pkg:*` removed | — |
| 6 | Disconnect USB mid-scan | scan errors cleanly with orchestrator error, no partial event insertion | — |
| 7 | `adb kill-server`; run scan; expect a clean re-connect | scan succeeds after adb restarts server | — |

## Cross-cutting checks

- [ ] `psm db verify` — clean after every scan of the week.
- [ ] `psm timeline --last 7d --export events.jsonl` — file loads in Timesketch.
- [ ] `psm alerts --status open` after a week — is the count what you'd expect,
      or is a rule too noisy?
- [ ] `psm alerts --ack N` / `--close N` — lifecycle works.
- [ ] `psm explain <event-id>` — a random sample per category renders the right
      template with the right payload.
- [ ] `psm enrich import known-good.txt` then `psm scan --enrich known_good` —
      confirm suppression only affects alerts, not the event stream.
- [ ] `psm enrich capture --source clean-image` on a known-clean baseline day.
- [ ] `pipx install` on a fresh Windows profile per `docs/release.md` §5.
- [ ] Every doc under `docs/setup/` walked start-to-finish on a machine that
      hasn't seen psm before.

## Annoyances → v1.0 blockers

Track here and copy into `todo.md`:

- [ ] …
- [ ] …
- [ ] …

## Sign-off

- [ ] All matrix rows pass or have a documented deferral.
- [ ] `psm db verify` clean at the end of the week.
- [ ] Zero annoyances remain in the "blockers" list (deferrals are OK, but
      not blockers).

When all three boxes are ticked: tag `v1.0.0`.
