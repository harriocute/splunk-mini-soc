# SPL Queries Used in the Mini SOC

This file records the searches used during the project. They are grouped by analyst purpose rather than presented as a list of commands to memorize.

## 1. Telemetry baseline

### Events by sourcetype

```spl
index=windows
| stats count by sourcetype
| sort - count
```

Purpose: establish what telemetry is actually arriving in Splunk.

### Sysmon Event ID distribution

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| stats count by EventID
| sort - count
```

Purpose: understand which Sysmon event types are present before hunting.

---

## 2. Process creation hunting

### Process frequency

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search EventID=1
| search NOT Image="*SplunkUniversalForwarder*"
| stats count by Image
| sort - count
```

Purpose: identify common and uncommon process images while removing Splunk's own forwarder activity from the baseline.

### Rare process images

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search EventID=1
| rare Image limit=10
```

Purpose: surface rare processes as investigation leads. Rarity alone is not maliciousness.

---

## 3. Parent/child process analysis

### `rundll32.exe` parent analysis

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| search EventID=1 Image="*rundll32.exe"
| stats count by ParentImage CommandLine
| sort - count
```

Purpose: determine whether `rundll32.exe` is being launched by an expected Windows process or a more concerning parent.

### Desktop executable investigation

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]+)</Data>"
| search EventID=1 Image="*\\Desktop\\Firefox.exe"
| table _time host User Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

Purpose: investigate an executable discovered in a user-writable location.

---

## 4. File/process correlation

### File creation for the Desktop executable

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| search EventID=11 TargetFilename="*\\Desktop\\Firefox.exe"
| table _time host User Image TargetFilename
| sort - _time
```

Purpose: identify which process wrote/created the file and build a timeline around its execution.

---

## 5. Authentication failure detection

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

Purpose: detect bursts of failed authentication attempts.

---

## 6. PowerShell behavioral detection

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| search EventID=1
| search Image="*powershell.exe"
| search NOT Image="*splunk-powershell.exe"
| search CommandLine="*-ExecutionPolicy Bypass*"
| table _time host User Image CommandLine
| sort - _time
```

Purpose: identify a specific PowerShell behavior rather than alerting on every PowerShell execution.

---

## 7. Network telemetry baseline

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='DestinationIp'>(?<DestinationIP>[^<]+)</Data>"
| rex "<Data Name='DestinationPort'>(?<DestinationPort>\\d+)</Data>"
| rex "<Data Name='Protocol'>(?<Protocol>[^<]+)</Data>"
| search EventID=3
| stats count by Image DestinationIP DestinationPort Protocol
| sort - count
```

Purpose: establish process-to-network visibility. This query was prepared as the next hunting phase; no network detection was created from it.

---

## Analyst principles

1. Establish a baseline before calling activity anomalous.
2. Prefer behavior and context over process-name blacklists.
3. Correlate parent process, command line, user, file activity, and network activity.
4. Treat rarity as a lead, not a verdict.
5. Record benign findings and false positives as part of the investigation.
6. Create detections only when the signal is useful enough to justify an alert.
