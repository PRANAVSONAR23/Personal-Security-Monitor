# psm — Testing Steps

A smallest-possible-step Windows self-test. Run each block one at a time in
PowerShell in the project directory. Committing to git is **not** required —
this is a local smoke test.

---

## Part A — Install

**Step 1.** Check pipx is on your system.
```powershell
pipx --version
```
If "not recognized": `python -m pip install --user pipx` then
`python -m pipx ensurepath` and reopen PowerShell.

**Step 2.** Install psm from the wheel you just built.
```powershell
pipx install .\dist\psm-0.1.0-py3-none-any.whl
```

**Step 3.** Confirm the `psm` command is on PATH.
```powershell
psm --version
```
Expect: `0.1.0`. If "not recognized", run `pipx ensurepath` and reopen PowerShell.

---

## Part B — First run

**Step 4.** Register your PC as a device.
```powershell
psm device add --name this-pc --platform windows
```
Expect: `registered device #1 name=this-pc platform=windows`.

**Step 5.** Run doctor.
```powershell
psm doctor this-pc
```
Expect: elevation status, file walk paths listed.

**Step 6.** Point psm at a *small* folder for the file walk (so the first
baseline finishes in seconds instead of minutes).
```powershell
$env:PSM_FILE_WALK_PATHS = "$env:USERPROFILE\Downloads"
```

**Step 7.** Take the baseline.
```powershell
psm baseline this-pc
```
Expect: `baseline captured  snapshot=#1  modules=[...]`.

**Step 8.** Run a scan immediately — nothing should have changed.
```powershell
psm scan this-pc
```
Expect: empty tables, exit code 0. Confirm with:
```powershell
echo $LASTEXITCODE
```
Expect: `0`.

---

## Part C — Plant something and detect it

**Step 9.** Drop a fake "malicious" file in Downloads.
```powershell
"echo hello" | Out-File -Encoding ascii "$env:USERPROFILE\Downloads\suspicious.bat"
```

**Step 10.** Add a Run-key entry pointing at it (this is what real malware does
for persistence).
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v psm-test /d "%USERPROFILE%\Downloads\suspicious.bat" /f
```

**Step 11.** Scan again.
```powershell
psm scan this-pc
```
Expect: a `file` event (suspicious.bat *added*), a `persist` event (Run key
*added*), possibly a red alert row at the bottom.

**Step 12.** Check the exit code.
```powershell
echo $LASTEXITCODE
```
Expect: `3` if an alert fired, otherwise `0`.

---

## Part D — Explain, timeline, verify

**Step 13.** Explain one of the events (use an id from step 11's report —
probably `1` or `2`).
```powershell
psm explain 1
```
Expect: a Markdown blurb about what that event means.

**Step 14.** List the timeline.
```powershell
psm timeline --last 1h
```
Expect: rows for both events.

**Step 15.** List open alerts.
```powershell
psm alerts
```
Expect: any correlation alerts, with ids.

**Step 16.** Verify the hash chain.
```powershell
psm db verify
```
Expect: `chain ok  events=2  head=<hex>`.

---

## Part E — Reverse the changes and confirm removal detection

**Step 17.** Delete the file and the Run key.
```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v psm-test /f
Remove-Item "$env:USERPROFILE\Downloads\suspicious.bat"
```

**Step 18.** Scan one more time.
```powershell
psm scan this-pc
```
Expect: `file` and `persist` events, both *removed* this time.

**Step 19.** Verify the chain is still clean.
```powershell
psm db verify
```
Expect: `chain ok  events=4  head=<hex>`.

---

## Part F — Cleanup (optional)

**Step 20.** If you want to start over, uninstall psm and delete the database.
```powershell
pipx uninstall psm
Remove-Item -Recurse "$env:LOCALAPPDATA\psm"
```

---

## If a step fails

Paste the exact command + error and debug from there. Most likely stumbling
blocks:

- **Step 2 fails** → dependency issue in the wheel; report what `pipx install`
  printed.
- **Step 7 hangs** → the Downloads folder is huge; override with a smaller
  path like a fresh scratch directory:
  ```powershell
  mkdir "$env:USERPROFILE\psm-test-scratch"
  $env:PSM_FILE_WALK_PATHS = "$env:USERPROFILE\psm-test-scratch"
  ```
- **Step 11 shows the file event but no persistence event** → the Run key
  command didn't take effect; re-run step 10 and check with:
  ```powershell
  reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
  ```
- **Step 16 says "chain broken"** → snapshot the DB first
  (`copy "$env:LOCALAPPDATA\psm\psm.sqlite" psm-broken.sqlite`) before doing
  anything else, then investigate.
