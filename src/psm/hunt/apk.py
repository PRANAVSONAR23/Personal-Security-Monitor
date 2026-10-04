"""APK analyzers — all driven by the bulk `dumpsys package packages` output that
the inventory scan already fetched. No APK is pulled and no network is touched.

What the dump gives for free, measured on the POCO M2 Pro:

    flags=[ ... DEBUGGABLE ... TEST_ONLY ... ALLOW_BACKUP ... ]
    apkSigningVersion=1|2|3|4
    installerPackageName=...
    plus every granted runtime permission

Pulling the APK would add signer certificate detail and nothing else these
analyzers need, so it is a separate opt-in step.
"""

from __future__ import annotations

from typing import Any

from psm.core.models import Artifact, Finding
from psm.hunt.base import Analyzer

# Permission clusters that are unremarkable alone and meaningful together.
# Each entry: rule id, required permissions, what the combination enables.
COMBOS: tuple[tuple[str, frozenset[str], str], ...] = (
    (
        "sms-exfiltration",
        frozenset({"android.permission.READ_SMS", "android.permission.INTERNET"}),
        "can read SMS (including one-time codes) and send them off-device",
    ),
    (
        "call-and-sms-control",
        frozenset({"android.permission.READ_SMS", "android.permission.CALL_PHONE"}),
        "can read SMS and place calls without user interaction",
    ),
    (
        "location-tracking-background",
        frozenset(
            {
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.INTERNET",
            }
        ),
        "can track location while backgrounded and report it off-device",
    ),
    (
        "audio-surveillance",
        frozenset({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"}),
        "can record audio and send it off-device",
    ),
    (
        "contact-harvesting",
        frozenset({"android.permission.READ_CONTACTS", "android.permission.INTERNET"}),
        "can read the contact list and send it off-device",
    ),
    (
        "self-installer",
        frozenset({"android.permission.REQUEST_INSTALL_PACKAGES"}),
        "can install further packages itself",
    ),
)

# Accessibility is the single most abused Android capability: it can read screen
# content and synthesise input for every other app.
ACCESSIBILITY = "special:accessibility"
DEVICE_ADMIN = "special:device-admin"


class ApkFlagsAnalyzer(Analyzer):
    """Manifest flags that should never ship in a release build."""

    id = "apk_flags"
    version = "1"
    accepts = ("apk",)

    def analyze(self, artifact: Artifact, payload: dict[str, Any]) -> list[Finding]:
        flags = {str(f) for f in payload.get("flags", ())}
        out: list[Finding] = []
        system = bool(payload.get("system"))

        if "DEBUGGABLE" in flags:
            out.append(
                self.finding(
                    artifact,
                    rule_id="debuggable",
                    verdict="suspicious",
                    confidence="high",
                    detail=(
                        "built debuggable — any local process can attach a debugger "
                        "and read or drive it"
                    ),
                    flags=sorted(flags),
                )
            )
        if "TEST_ONLY" in flags:
            out.append(
                self.finding(
                    artifact,
                    rule_id="test-only",
                    verdict="suspicious",
                    confidence="medium",
                    detail="marked test-only; normally installable only via `adb install -t`",
                    flags=sorted(flags),
                )
            )
        # Weak signing schemes. v1-only signing is forgeable (Janus, CVE-2017-13156)
        # and Android 11+ requires v2 for new installs, so seeing it on a
        # non-system app means a very old or hand-built APK.
        signing = payload.get("signing_version")
        if isinstance(signing, int) and signing < 2 and not system:
            out.append(
                self.finding(
                    artifact,
                    rule_id="weak-signing-scheme",
                    verdict="suspicious",
                    confidence="medium",
                    detail=f"signed with APK scheme v{signing}; v1 signatures are forgeable",
                    signing_version=signing,
                )
            )
        return out


class ApkSourceAnalyzer(Analyzer):
    """How the package got onto the device."""

    id = "apk_source"
    version = "1"
    accepts = ("apk",)

    def analyze(self, artifact: Artifact, payload: dict[str, Any]) -> list[Finding]:
        source = payload.get("source")
        if source == "sideload":
            return [
                self.finding(
                    artifact,
                    rule_id="sideloaded",
                    verdict="suspicious",
                    confidence="medium",
                    detail="installed outside any app store",
                    installer=payload.get("installer"),
                )
            ]
        # `unknown` is not reported: it means the installer was not one we
        # recognise, not that anything is wrong. Alerting on our own ignorance is
        # not detection.
        return []


class ApkPermissionsAnalyzer(Analyzer):
    """Granted-permission clusters, and the two special accesses.

    Reads `granted_permissions`, which the runner attaches to the artifact payload
    from the permission inventory — so this stays a pure function of data already
    collected.
    """

    id = "apk_permissions"
    version = "1"
    accepts = ("apk",)

    def analyze(self, artifact: Artifact, payload: dict[str, Any]) -> list[Finding]:
        granted = {str(p) for p in payload.get("granted_permissions", ())}
        if not granted:
            return []
        out: list[Finding] = []

        if ACCESSIBILITY in granted:
            out.append(
                self.finding(
                    artifact,
                    rule_id="accessibility-service",
                    verdict="suspicious",
                    confidence="high",
                    detail=(
                        "holds an accessibility service — can read screen content and "
                        "synthesise input in every other app"
                    ),
                )
            )
        if DEVICE_ADMIN in granted:
            out.append(
                self.finding(
                    artifact,
                    rule_id="device-admin",
                    verdict="suspicious",
                    confidence="high",
                    detail="holds device-admin rights — can lock, wipe, or enforce policy",
                )
            )

        # INTERNET is an install-time permission, so it is not in the runtime set.
        # Treat every app as network-capable: on Android that is the safe default
        # and essentially always true.
        effective = granted | {"android.permission.INTERNET"}
        for rule_id, required, detail in COMBOS:
            if required <= effective:
                out.append(
                    self.finding(
                        artifact,
                        rule_id=rule_id,
                        verdict="suspicious",
                        confidence="low" if payload.get("system") else "medium",
                        detail=detail,
                        matched=sorted(required),
                    )
                )
        return out


ANALYZERS: tuple[Analyzer, ...] = (
    ApkFlagsAnalyzer(),
    ApkSourceAnalyzer(),
    ApkPermissionsAnalyzer(),
)
