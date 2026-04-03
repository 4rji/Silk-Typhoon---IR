# Incident Report – Domain Compromise, Credential Dumping, and Data Exfiltration

## Executive Summary
An attacker gained initial access to the network via SSH using valid Administrator credentials obtained through brute force or password reuse. After gaining access, the attacker executed PowerShell scripts, deployed tools, dumped credentials using Mimikatz, moved laterally across internal systems using SMB, accessed the Microsoft Exchange server, exported a mailbox to a PST file, collected sensitive files from user directories, staged data, and cleared Windows Event Logs to evade detection.

This incident resulted in credential compromise and potential data exfiltration including emails and user files.

---

## Timeline of Events

| Time | Event |
|------|------|
| External | Brute force attempts from 211.56.98.146 |
| 08:46 | Successful SSH login as Administrator from 10.10.254.1 |
| 08:55 | Malware/tool procduwp.exe created in C:\Users\Public |
| 08:55–08:59 | PowerShell scripts executed |
| 08:59 | Mailbox exported to PST file |
| 09:02 | Windows Security logs cleared (Event ID 1102) |

---

## Attack Chain

1. Initial Access – SSH login using Administrator credentials
2. Execution – PowerShell scripts executed
3. Credential Access – Mimikatz used to dump credentials
4. Discovery – Attacker enumerated logged-in users
5. Lateral Movement – SMB connections using net use
6. Privilege Escalation – Malware executed as Administrator
7. Collection – Files and emails collected
8. Staging – Data stored in Windows staging directories
9. Exfiltration – Data encoded and prepared for exfiltration
10. Defense Evasion – Logs cleared

---

## Evidence

### SSH Login
```
Accepted password for administrator from 10.10.254.1 port 42526 ssh2
```

### Credential Dumping (Mimikatz)
```
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
```

### Malware Execution
```
C:\Users\Public\procduwp.exe
```

### Exchange Mail Export
```
New-MailboxExportRequest -Mailbox jefferson.livingston -FilePath \\mailserver\C$\backup.pst
```

### Lateral Movement
```
net use \\dev-win10-2 /user:administrator
```

### File Collection
```
Get-ChildItem C:\Users -Recurse -Include *.txt, *.csv, *.dat
```

### Log Clearing
```
Event ID 1102 – Security log cleared
```

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Valid Accounts | T1078 |
| PowerShell Execution | T1059.001 |
| Credential Dumping (LSASS) | T1003.001 |
| Account Discovery | T1033 |
| SMB Lateral Movement | T1021.002 |
| File Discovery | T1083 |
| Data Collection | T1005 |
| Archive/Encoding | T1560 |
| Exfiltration | T1048 |
| Clear Logs | T1070 |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|------|
| External IP | 211.56.98.146 |
| Internal IP | 10.10.254.1 |
| Internal IP | 172.16.5.102 |
| Malware | C:\Users\Public\procduwp.exe |
| Output File | C:\Users\Public\out |
| Staging Folder | C:\Windows\Tasks |
| PST File | C:\backup.pst |
| Malicious URL | http://proxy.east2south.simonxu.cc/mimi.txt |
| Tool | Mimikatz |
| Account | Administrator@site |

---

## Root Cause

The attacker gained access due to:
- SSH service exposed to the internet
- Weak or reused Administrator password
- No multi-factor authentication (MFA)
- No account lockout policy
- Administrator account allowed remote login

---

## Impact

The attacker was able to:
- Obtain administrator credentials
- Dump credentials from memory
- Move laterally across the network
- Access Microsoft Exchange
- Export a user mailbox
- Collect sensitive files
- Clear logs to evade detection

This represents a full domain compromise and data exfiltration incident.

---

## Recommendations

- Reset all administrator and privileged account passwords
- Implement MFA for all remote access
- Disable direct Administrator login
- Restrict SSH access to VPN only
- Implement account lockout policies
- Monitor Event ID 4625 (failed logins)
- Monitor Event ID 4688 (process creation)
- Monitor Event ID 7045 (service creation)
- Monitor Event ID 1102 (log clearing)
- Block malicious IP 211.56.98.146
- Review outbound traffic for data exfiltration
- Deploy EDR to monitor PowerShell and credential dumping activity

---

## Conclusion

This incident involved a multi-stage attack including brute force authentication, credential dumping using Mimikatz, lateral movement via SMB, data collection, email exfiltration, and log clearing. The attacker successfully compromised administrative credentials and accessed sensitive data within the environment.
