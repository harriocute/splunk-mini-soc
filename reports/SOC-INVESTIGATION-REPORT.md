# Splunk SOC Investigation Report

## Executive Summary

This project implemented a Windows-focused SOC monitoring environment using Splunk Enterprise, Splunk Universal Forwarder, and Sysmon. The lab successfully collected Windows telemetry, created behavioral detections, validated alerting, and performed analyst-led threat hunting.

The project intentionally included both positive detection validation and benign investigations. This allowed the analyst workflow to demonstrate not only detection, but also triage and false-positive reduction.

## Environment

- Windows 11 Pro endpoint
- Ubuntu 24.04.4 LTS Splunk VM
- Splunk Enterprise 10.4.2
- Splunk Universal Forwarder 10.4.2
- Sysmon
- VirtualBox Host-Only networking
- TCP 9997 for forwarder-to-Splunk ingestion

## Detection Results

### D01 — Possible Brute-Force Authentication

Windows Security Event ID 4625 events were grouped by five-minute buckets, target account, source IP, and host. Five controlled failed authentication attempts produced a matching result. A scheduled Splunk alert was configured and subsequently observed in Triggered Alerts.

### D02 — PowerShell Execution Policy Bypass

Sysmon Event ID 1 was used to identify actual Windows PowerShell processes containing `-ExecutionPolicy Bypass`. A controlled harmless command generated the expected telemetry and validated the search. Splunk's own `splunk-powershell.exe` process was explicitly excluded to reduce false positives.

## Hunting Results

### Audit Policy Activity

`auditpol.exe` was observed at high frequency. Investigation showed execution under `NT AUTHORITY\\SYSTEM` with the Wazuh agent as parent and audit-policy queries in the command line. The activity was assessed as benign security telemetry collection.

### Rundll32 Activity

`rundll32.exe` activity was reviewed because the binary can be abused for signed-binary proxy execution. Observed commands referenced Windows DLLs under normal system directories, and parent-process analysis showed recurring Windows system activity. A follow-up search for rundll32 command lines outside `System32` and `SysWOW64` returned no events during the examined period.

### Firefox Desktop Execution

A process hunt found `C:\Users\Harrycode\Desktop\Firefox.exe`. The event was investigated through process lineage and file creation. The Desktop execution was associated with `explorer.exe`, while Firefox updater/helper activity under `C:\Program Files\Mozilla Firefox\` included `/PostUpdate /DesktopLauncher` and wrote the Desktop executable. The evidence supported a benign Firefox update/desktop-launcher explanation.

## SOC Methodology Demonstrated

1. Establish telemetry visibility.
2. Baseline event and process activity.
3. Identify an anomaly or behavioral lead.
4. Pivot into contextual fields.
5. Correlate process and file activity.
6. Assess whether the behavior is expected.
7. Validate detections with controlled activity.
8. Tune out known benign activity where appropriate.
9. Record the evidence and final disposition.

## Limitations

This is a home-lab environment rather than a production enterprise SOC. The dataset is limited to the configured Windows endpoint and generated/normal endpoint activity. The project does not claim to provide complete enterprise coverage.

Email alert delivery and a full SOC dashboard were not completed during this phase and remain future enhancements.

## Recommended Next Enhancements

- Add email notification through a configured SMTP provider.
- Build a focused SOC dashboard from validated searches.
- Add more behavioral detections with controlled validation.
- Add network telemetry and process-to-network correlation.
- Add a formal incident-response case with containment/recovery steps.
- Add screenshots and exported evidence as the project evolves.

## Conclusion

The Splunk SOC demonstrates practical security monitoring rather than tool installation alone. The lab collected real endpoint telemetry, produced validated detections, and required analyst judgment to distinguish suspicious-looking behavior from legitimate software and security-agent activity.
