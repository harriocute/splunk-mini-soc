# CASE-002 — Benign Process Hunting Findings

**Case type:** Threat hunting / false-positive analysis  
**Final disposition:** Benign / no detection created  
**Data source:** Sysmon Event ID 1 in Splunk

## Finding A — `auditpol.exe`

A process-frequency review showed 54 `auditpol.exe` process-creation events in the examined period.

Observed context included:

- User: `NT AUTHORITY\\SYSTEM`
- Image: `C:\Windows\SysWOW64\auditpol.exe`
- Parent: `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`
- Commands: `auditpol.exe /get /subcategory:...`

The parent process and read-only audit-policy queries provided a coherent explanation: the Wazuh agent was checking Windows audit-policy state.

**Disposition:** Benign. No alert created.

## Finding B — `rundll32.exe`

`rundll32.exe` was investigated because it is a legitimate Windows binary that can also be abused for proxy execution of DLL exports.

The examined events included commands referencing Windows DLLs such as:

- `AppXDeploymentExtensions.OneCore.dll,ShellRefresh`
- `CapabilityAccessManager.dll,CapabilityAccessManagerDoStoreMaintenance`
- `Windows.StateRepositoryClient.dll,StateRepositoryDoMaintenanceTasks`
- `PcaSvc.dll,PcaPatchSdbTask`
- `sysmain.dll,PfSvwsSwapAssessmentTask`

Recurring parent context included `C:\Windows\System32\svchost.exe`, and the DLLs were located under normal Windows system directories.

A follow-up hunt for `rundll32.exe` command lines outside `C:\Windows\System32\` and `C:\Windows\SysWOW64\` returned zero events during the examined 24-hour period.

**Disposition:** Benign / expected Windows activity. No alert created.

## Analyst lesson

These findings were deliberately documented as investigations rather than detections. A SOC that alerts on every occurrence of `auditpol.exe` or `rundll32.exe` would generate unnecessary noise.

The analyst decision was based on **process path + parent process + command line + DLL location + frequency/context**, not the executable name alone.
