# Validated Splunk Detections

These detections were built and validated in the home SOC lab. They are intentionally behavioral and contextual rather than treating a single process name as proof of compromise.

---

## D01 — Possible Brute-Force Authentication

**Status:** Validated  
**Data source:** Windows Security Event Log  
**Event:** 4625 — failed logon  
**Severity:** Medium  
**Alert schedule:** Every 5 minutes  
**Trigger:** Number of results > 0  
**Validation:** Controlled repeated wrong-password attempts

### Detection logic

The search groups failed logons by five-minute time bucket, host, target account, and source IP. Five or more failures in the bucket are treated as a lead for investigation.

```spl
index=windows sourcetype="XmlWinEventLog:Security" "4625"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex "<Data Name='IpAddress'>(?<SourceIP>[^<]+)</Data>"
| rex "<Data Name='LogonType'>(?<LogonType>[^<]+)</Data>"
| bin _time span=5m
| stats count values(LogonType) as LogonType by _time host TargetUserName SourceIP
| where count >= 5
| sort - _time
```

### Validation

The lab generated five incorrect authentication attempts for the test account. Splunk returned a matching result with:

- Count: 5
- Target account: `Harrycode`
- Source IP: `127.0.0.1`
- Logon Type: `2` (interactive)

The local source address reflected the controlled lab simulation rather than a remote attacker.

### Analyst considerations

Potential benign causes include:

- User repeatedly entering an incorrect password
- Stale credentials
- Scheduled tasks/services using old credentials
- Authorized security testing
- Local lab validation

The alert should therefore be investigated rather than automatically treated as confirmed compromise.

---

## D02 — PowerShell Execution Policy Bypass

**Status:** Validated  
**Data source:** Sysmon Event ID 1 — Process Creation  
**Severity:** Medium / investigation lead  
**Validation:** Controlled PowerShell execution using `-ExecutionPolicy Bypass`

### Detection logic

The detection focuses on **actual Windows PowerShell** execution containing `-ExecutionPolicy Bypass` and excludes Splunk's own `splunk-powershell.exe` helper process.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]+)</Data>"
| rex "<Data Name='IntegrityLevel'>(?<IntegrityLevel>[^<]+)</Data>"
| search EventID=1
| search Image="*powershell.exe"
| search NOT Image="*splunk-powershell.exe"
| search CommandLine="*-ExecutionPolicy Bypass*"
| table _time host User Image CommandLine ParentImage ParentCommandLine IntegrityLevel
| sort - _time
```

### Validation

A harmless controlled PowerShell command was executed in the Windows lab:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC_TEST_POWERSHELL'"
```

The resulting Sysmon Event ID 1 telemetry was ingested into Splunk and matched the detection logic.

### Analyst considerations

`ExecutionPolicy Bypass` is **not proof of malicious activity**. It is a useful behavioral indicator because attackers may use PowerShell with altered execution-policy behavior, but legitimate administration, deployment software, troubleshooting, and security testing can produce the same signal.

Analysts should review:

- User
- Parent process
- Full command line
- Integrity level
- Child processes
- Network activity
- Nearby process/file events

---

## Why only two detections?

The project deliberately avoids creating alerts merely because a process looks unusual. During hunting, `auditpol.exe`, `rundll32.exe`, and a Desktop-launched `Firefox.exe` were investigated and explained through process lineage, command lines, file activity, and expected software behavior.

That distinction demonstrates a core SOC skill: **detection engineering should balance useful coverage with false-positive control.**
