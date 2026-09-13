## Accessibility service granted: {pkg}

Android's accessibility API can read every screen and inject taps and text.
Malware families abuse it to log credentials, click through prompts, and defeat
2FA. Grant it only to apps that need to narrate the UI for you.

**Verify:** Settings → Accessibility → Installed apps. If `{pkg}` is not one
you intentionally installed for accessibility, disable it there — the toggle
takes effect immediately.
