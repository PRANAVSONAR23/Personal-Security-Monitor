# psm — Personal Security Monitor

A local, deterministic security monitoring tool for two devices I own: a MacBook
(controller **and** target) and a POCO M2 Pro Android phone (target, non-rooted).

It answers three different questions with three different subsystems:

| Question | Subsystem | How |
|---|---|---|
| *What changed?* | `inventory` | snapshot → diff → events |
| *Is anything bad?* | `hunt` | artifact → analyzers → findings |
| *What is it talking to?* | `flowlog` | continuous capture → flows |

No cloud. No daemon on the controller beyond the capture legs. No TLS
interception. VirusTotal is hash-only and opt-in.

## Status

**v2 rewrite in progress** on `v2/mac-controller`. Phase 0 of 8. Not yet
installable — see `TODO.md`.

v1 (`main`) was a working Windows-controlled tool. Its core is being ported; its
Windows collector and SSH shim are not. v1 docs live in `docs/v1/`.

## Docs

- [`AIM.md`](AIM.md) — scope, and the limits that are platform properties
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — subsystems, collection modes, data flow
- [`HLD.md`](HLD.md) — module map, decisions D1–D14, tiers, error philosophy
- [`LLD.md`](LLD.md) — schema, interfaces, CLI spec, testing strategy
- [`PLAN.md`](PLAN.md) — eight phases with exit criteria
- [`TODO.md`](TODO.md) — live progress

## License

MIT.
