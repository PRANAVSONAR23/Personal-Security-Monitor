# Android setup

Android collection is driven by **`adb`** from the Windows controller. No root
required. No agent installed on the phone. The controller reads `pm list`,
`dumpsys package`, and settings/dpm output over USB.

## 1. Install ADB

**Option A — Android SDK Platform-Tools** (recommended, official):

Download from <https://developer.android.com/tools/releases/platform-tools> and
extract, e.g. to `C:\adb\`. Add that folder to PATH, or point psm at it:

```powershell
$env:PSM_ADB = "C:\adb\adb.exe"
```

**Option B — bundled `vendor/adb/adb.exe`** in a psm release (not shipped in
v1.0; planned for v1.1). If present, psm falls back to it automatically.

Verify:

```powershell
adb version
```

## 2. Turn on USB debugging on the phone

*Settings → About phone → tap "Build number" 7 times → developer mode enabled.*
*Settings → System → Developer options → USB debugging → On.*

Some OEMs (Xiaomi, Oppo, Realme) also require:

- *Developer options → Install via USB → On*
- *Developer options → USB debugging (Security settings) → On*
- Signing in to the OEM account first.

Connect the phone by USB. Prefer a **data-capable cable** (many charge-only
cables don't carry USB data — a common cause of "device not detected").

## 3. Install OEM drivers (Windows only)

Windows needs the correct USB driver to talk to the phone in ADB mode.

| Vendor | Driver source |
|---|---|
| Google (Pixel) | Google USB Driver, bundled with SDK Platform-Tools or install from Device Manager |
| Samsung | Samsung USB Driver for Mobile Phones |
| Xiaomi / Redmi / POCO | Mi USB Driver |
| OnePlus | OnePlus USB Drivers |
| Oppo / Realme | Vendor site — search "USB drivers <model>" |
| OEM not listed | Universal ADB Driver by ClockworkMod (works for most) |

Symptoms of missing / wrong driver:

- `adb devices` shows nothing.
- Device Manager shows the phone under *Other devices* with a yellow bang.
- `psm doctor <name>` prints the driver guidance list.

## 4. Authorize the controller on the phone

The first time you connect with USB debugging on:

- The phone pops up an **"Allow USB debugging?"** dialog with the RSA
  fingerprint of your controller's `~/.android/adbkey.pub`.
- Tick **"Always allow from this computer"** and Allow.

If you dismissed it accidentally, `adb devices` will show state `unauthorized`.
Revoke and re-prompt:

*Developer options → Revoke USB debugging authorizations* → replug the cable →
accept the dialog.

## 5. Register the device

Find the serial:

```powershell
adb devices
# List of devices attached
# 24081XYZ  device
```

Register it:

```powershell
psm device add --name pixel --platform android --identifier 24081XYZ
psm doctor pixel
```

`psm doctor` verifies `adb.exe` is reachable, lists visible devices, reports the
`adb devices` state for your serial, and probes the SDK level.

## 6. Baseline & scan

```powershell
psm baseline pixel
# ... install an app, grant a permission ...
psm scan pixel
```

What appears as events:

| Event | Where it comes from |
|---|---|
| Sideloaded install | `pm list packages -f -i --show-versioncode` — installer classified as `sideload` when it's not a known store |
| Runtime permission grant | `dumpsys package <pkg>` — the `runtime permissions:` block |
| Accessibility service enabled | `settings get secure enabled_accessibility_services` |
| Device Admin enabled | `dpm list-owners` |

Built-in rules will fire on: any new sideloaded install (medium severity), and
any new accessibility grant (high severity — accessibility is the single most
abused Android permission).

## 7. Modules

Requested modules are hard-coded in v1.0. Not-yet-implemented:

- `downloads` (shared storage listing) — deferred to v1.1.
- `netstats` (`dumpsys netstats`) — deferred to v1.1.

Both appear as gaps in the scan report so their absence isn't silent.

## 8. Multiple phones / one controller

Register each with a distinct name and identifier:

```powershell
psm device add --name pixel --platform android --identifier 24081XYZ
psm device add --name test-phone --platform android --identifier ABCDEF12
psm scan pixel
psm scan test-phone
```

## 9. Troubleshooting

- **`adb devices` shows `unauthorized`** — the "Always allow" dialog on the
  phone was dismissed. Revoke authorizations on the phone and re-plug.
- **`adb devices` shows `offline`** — the phone is asleep, or ADB is in a wedged
  state. `adb kill-server` on the controller, then `adb devices` again.
- **`no permissions (verify udev rules)`** — Linux only; not relevant on
  Windows. Ignore in doctor output if you see it from a mixed environment.
- **`psm doctor` says "adb.exe not found"** — set `PSM_ADB`, or drop `adb.exe`
  onto PATH.
- **A store-installed app shows up as sideload** — the `installer` field on
  that package genuinely says something unrecognized. Read the raw event
  (`psm explain <event-id>`) — `payload.installer` shows what dumpsys reported.
- **Scans are slow on a phone with 400+ apps** — the `dumpsys package` walk is
  linear. Nothing to tune in v1.0; runtime scales roughly with app count.
