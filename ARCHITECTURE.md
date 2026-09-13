# PSM v2 — Architecture

## 1. System overview

The Mac owns all state, logic, and interaction. It is also a monitored target —
its collection runs in-process with no transport layer. The phone is a data
source reached over wireless ADB plus two network capture legs.

```text
┌──────────────────────────── MacBook (controller + target) ─────────────────────────┐
│                                                                                    │
│   CLI (psm)                                                                        │
│      │                                                                             │
│      ├── inventory ──▶ Collector ──▶ Normalizer ──▶ Snapshot ──▶ diff() ──▶ events │
│      ├── hunt ───────▶ Artifact  ──▶ Analyzers  ──────────────────────▶ findings   │
│      └── flowlog ────▶ StreamSource ──▶ FlowWriter ──▶ rollup ────────▶ flows      │
│                                                              │                     │
│                                                              ▼                     │
│                            ┌──────────────────────────────────────────┐            │
│                            │  SQLite (WAL)                            │            │
│                            │  events(chained) · findings · flows      │            │
│                            │  items · snapshots · artifacts · alerts  │            │
│                            └──────────────────────────────────────────┘            │
│                                          │                                         │
│                            rules engine ─┴─▶ alerts ──▶ report / timeline          │
└────────────────────────────────────────────────────────────────────────────────────┘
        │                        │                          │
        │ in-process             │ wireless adb             │ capture legs
   ┌────┴─────┐            ┌─────┴──────┐            ┌──────┴───────────────────┐
   │ macOS    │            │ Android    │            │ A. Mac-as-router (pcap)  │
   │ collector│            │ collector  │            │ B. on-device VpnService  │
   │ + eslogger│           │ (non-root) │            │    (per-app attribution) │
   └──────────┘            └────────────┘            └──────────────────────────┘
```

## 2. Two collection modes

This is the central structural decision. Everything else follows from it.

**Poll mode** — produces a *snapshot*: a complete set of inventory items at a
point in time. Diffed against the previous snapshot to produce events.
Used by: macOS inventory collector, Android inventory collector.

**Stream mode** — produces an unbounded sequence of *records*. There is no
"previous" to diff against; records are evaluated by rules as they arrive.
Used by: `eslogger` (macOS ESF), network capture (both legs).

```text
poll   : collect() → items → diff(prev, cur) → events → rules → alerts
stream : subscribe() → records → (write to detail table) → rules → alerts
```

A stream never goes through `diff()`. Forcing continuous telemetry into a
snapshot-diff model is the mistake this rewrite exists to avoid.

## 3. Components

### 3.1 CLI (`psm`)
Single entry point. Command groups mirror the subsystems: `psm scan` /
`psm watch` (inventory), `psm hunt` (hunt), `psm flow` (flowlog), plus shared
`device`, `doctor`, `timeline`, `report`, `explain`, `alerts`, `db`.

### 3.2 Collectors (poll) — *Adapter pattern*
One adapter per target platform, behind a single interface. Each declares which
modules it can produce **right now**, for **this device, at this tier**.

```python
class Collector(ABC):
    platform: str
    def capabilities(self, device: Device) -> set[str]: ...
    def collect(self, device: Device, modules: set[str]) -> RawBundle: ...
```

`capabilities()` must be derived from what was *actually* collected, never
declared optimistically. v1 got this wrong and produced 64 phantom "removed"
events in a single scan; see HLD D6.

### 3.3 Stream sources (stream) — *Producer pattern*

```python
class StreamSource(ABC):
    kind: str                      # "esf" | "netflow"
    def subscribe(self, device: Device) -> Iterator[Record]: ...
```

Long-lived, restartable, backpressure-aware. A source that dies is restarted by
the supervisor and the gap is recorded — the phone's VPN leg *will* die under
MIUI memory pressure, so this is a normal path, not an error path.

### 3.4 Analyzers (hunt) — *Strategy pattern*

```python
class Analyzer(ABC):
    id: str
    version: str
    def analyze(self, artifact: Artifact) -> list[Finding]: ...
```

Each analyzer is independent and versioned. A `Finding` records which analyzer
at which version produced it, so re-running after a rule update is idempotent
and the delta is meaningful.

### 3.5 Normalizer
Converts platform-raw output into canonical inventory items. All *format*
knowledge lives here; nothing above it knows what `dumpsys` looks like.

### 3.6 Store
Single SQLite file, WAL. Content-addressed items dedupe across snapshots. Three
write paths with different volume and durability profiles — see §4.

### 3.7 Rules engine
YAML predicates plus restricted joins, no `eval`. Ported from v1 largely intact,
extended to evaluate over three record types (events, findings, flows) rather
than one.

### 3.8 Report / timeline
The timeline is the join point across all three subsystems: an inventory event,
a hunt finding, and a flow alert all land there in time order, which is what
makes the correlation legible.

## 4. What gets hash-chained, and what doesn't

```text
events    (chained)   inventory diffs, hunt findings promoted to events,
                      flow alerts.  Low volume. Conclusions.
findings  (unchained) per-artifact analyzer output. Re-evaluable by design,
                      so immutability would be wrong.
flows     (unchained) raw network telemetry. High volume, rolled up, retention-
                      capped. Chaining these would make `db verify` O(millions)
                      and protect nothing an attacker cares about.
```

The chain protects the *narrative* — what the tool concluded and when. That is
the thing worth proving wasn't rewritten after the fact.

## 5. Data flow — the three commands

```text
psm scan phone
  1. resolve device → AndroidCollector, tier=unrooted
  2. adb: pm list packages / dumpsys package (one pass) / settings / dpm
  3. normalize → inventory items
  4. persist snapshot N, capabilities = what actually returned
  5. diff(N-1, N) → events
  6. rules → alerts;  append events (chained)
  7. render

psm hunt phone --new
  1. select artifacts: files + APKs added since last hunt
  2. pull APKs over adb to a staging dir
  3. run analyzers: yara, apk_manifest, apk_signer, known_good, vt(opt-in)
  4. persist findings; promote alert-severity findings to chained events
  5. render

psm flow start
  1. supervisor launches enabled legs:
       A. router leg  — pcap on the Internet Sharing interface (needs root)
       B. device leg  — poll the VpnService app's log over adb
  2. each leg writes flows to its own staging buffer
  3. correlator joins on (ts window, dst ip/host) → attributed flows
  4. rollup compacts to per-(app, host, hour) aggregates
  5. rules over flows → alerts → chained events
```

## 6. Trust model

- The Mac is assumed clean and is the root of trust. It is also a target, and
  self-inspection has a known ceiling: a sufficiently deep compromise can lie to
  a tool running on the same machine. The before/after diff still catches the
  common cases. `eslogger` raises that ceiling but does not remove it.
- The phone is assumed **possibly compromised**. Everything it returns is data,
  never code: schema-validated, size-capped, timeout-bounded. No `eval`, no
  dynamic import, no shelling out with phone-supplied strings.
- The on-device VPN app is the one piece of our code running on an untrusted
  host. It is local-only (no remote endpoint), and the Mac treats its output
  exactly as hostile as any other phone output.
- No listening service on the Mac. The router leg is the one exception and it is
  inbound by nature — it is firewalled to the hotspot interface only.
- Privacy: nothing leaves the Mac by default. VT is hash-only and opt-in per run.

## 7. Non-goals

Real-time blocking or prevention · TLS interception · kernel extensions
requiring Apple entitlements · iOS · Windows · any third device · cloud sync ·
a GUI · AI/ML classification.
