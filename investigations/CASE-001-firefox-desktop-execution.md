# CASE-001 — Firefox Executing from Desktop

**Case type:** Endpoint threat hunting / process investigation  
**Initial priority:** Medium investigation lead  
**Final disposition:** Benign / likely legitimate software update activity  
**Data source:** Sysmon XML telemetry in Splunk  
**Host:** `DESKTOP-05LIGD5`

## 1. Initial finding

A process-frequency hunt for Sysmon Event ID 1 identified an executable running from a user-writable directory:

```text
C:\Users\Harrycode\Desktop\Firefox.exe
```

Executables launched directly from a Desktop can deserve investigation because the location is writable by the user and is outside the normal application installation path.

The file was **not** classified as malicious from the path alone.

## 2. Process execution evidence

Sysmon Event ID 1 showed:

- User: `DESKTOP-05LIGD5\\Harrycode`
- Image: `C:\Users\Harrycode\Desktop\Firefox.exe`
- Command line: `"C:\Users\Harrycode\Desktop\Firefox.exe"`
- Parent: `C:\Windows\explorer.exe`
- Execution time: `2026-09-07 16:00:26.860`

The `explorer.exe` parent is consistent with an interactive user launch, but parent context alone was not considered sufficient to close the investigation.

## 3. File creation pivot

A Sysmon Event ID 11 search identified file activity involving the same Desktop executable:

- Time: `2026-09-07 16:01:14.228`
- Target: `C:\Users\Harrycode\Desktop\Firefox.exe`
- Writing process: `C:\Program Files\Mozilla Firefox\uninstall\helper.exe`

The file event occurred approximately 47 seconds after the observed execution event. Because Event ID 11 can represent file creation/overwrite activity, this timing was not interpreted as proof that the helper originally downloaded or created the executable before the first execution.

## 4. Parent-process pivot

Sysmon Event ID 1 showed the Firefox helper process:

```text
C:\Program Files\Mozilla Firefox\uninstall\helper.exe
```

with parent:

```text
C:\Program Files\Mozilla Firefox\updater.exe
```

The helper command line included:

```text
/PostUpdate /DesktopLauncher
```

The updater command line also referenced Mozilla's update data and Firefox installation paths.

## 5. Process chain

```text
Firefox.exe
    │
    └── Mozilla Firefox updater.exe
            │
            └── uninstall/helper.exe
                    │
                    └── Desktop/Firefox.exe file activity
```

The exact ordering of individual file and process events was retained rather than assuming that the Event ID 11 write preceded the first observed execution.

## 6. Assessment

The strongest evidence supporting benign activity was the combination of:

- legitimate Mozilla Firefox installation paths for the updater/helper
- Firefox updater as the parent of the helper
- `/PostUpdate /DesktopLauncher` in the helper command line
- `explorer.exe` as the parent of the Desktop Firefox execution
- no observed PowerShell/cmd/script-host parent for the Desktop executable in the investigated event
- no evidence from this investigation of a DLL being loaded from an anomalous path

## 7. Disposition

**Benign / likely legitimate Firefox update or desktop-launcher activity.**

No alert was created for this event because the observed behavior was explainable and the available telemetry did not establish malicious execution.

## 8. Analyst lesson

A useful hunting lead does not have to become a detection.

The investigation demonstrates the sequence:

**Rare/unusual path → process context → parent process → file activity → timeline → disposition.**

That workflow reduces false positives and produces a defensible analyst conclusion.
