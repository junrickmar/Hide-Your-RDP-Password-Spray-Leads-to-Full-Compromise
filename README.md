<img width="1536" height="1024" alt="unnamed" src="https://github.com/user-attachments/assets/0ecb5576-a1dc-41be-af0c-6d213a0ca20b" />

# Threat Hunt Report: Hide Your RDP- Password Spray Leads to Full Compromise

## Platforms and Languages Leveraged
- Microsoft Sentinel
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Incident Response Scenario - where DeviceName contains "flare" Incident Date 14-September-2025

Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach.

### Executive Summary
On September 16, 2025, at approximately 18:40:57 UTC, an external threat actor gained unauthorized access to host flare through a Remote Desktop Protocol (RDP) brute-force attack against the user account "slflare". The intrusion originated from IP address 159.26.106.84.
Following the compromise, the attacker executed malicious PowerShell commands, established multiple persistence methods, conducted system reconnaissance, collected files, and exfiltrated data to a command-and-control (C2) server located at 185.92.220.87:8081.
The threat actor employed several evasion tactics, including process injection into msedge.exe, creating Defender exclusions, and setting up deceptive Windows services and scheduled tasks to maintain access. Among the exfiltrated data were network_credentials.txt, financial_report_Q4.pdf, and backup_sync.zip.
No evidence of lateral movement or credential dumping was identified during the investigation. Notably, Microsoft Defender for Endpoint (MDE) did not generate any alerts throughout the attack, indicating the adversary successfully bypassed its detections.


## Initial Access

Attack Vector: RDP Brute Force (T1110.001)
Entry Point: Remote Desktop Protocol (Port 3389)
Attack Source IP: 159.26.106.84
Compromised Account: slflare
Successful Login Time: 2025-09-16T18:40:57.3785102Z

###  Searched the `DeviceLogonEvents` Table

Review the authentication telemetry and look for signs of repeated failed logins followed by a successful one. Focus on logins that originated from external IP addresses.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where AccountName == "slflare"
| where Timestamp between (datetime(2025-09-14) .. datetime(2025-09-18))
| project Timestamp, AccountName, ActionType, RemoteIP, LogonType
| order by Timestamp asc 
```
<img width="961" height="562" alt="Screenshot 2025-10-15 at 12 59 53 PM" src="https://github.com/user-attachments/assets/87036d43-e7b9-4cba-b839-f3671643de02" />

##Attack Details
The attacker conducted a RDP brute-force attack against host `flare` from external IP 159.26.106.84. 

- 10 failed login attempts** targeting multiple accounts (slflare, admin)
- 5 successful logins** for account `slflare`
- 2 distinct user accounts** targeted during the attack
  
**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-14) .. datetime(2025-09-18))
| summarize Failures = countif(ActionType=="LogonFailed"),
          Successes = countif(ActionType=="LogonSuccess"),
          Users = dcount(AccountName)
        by RemoteIP
| where Failures > 3 and Successes > 0 and Users > 1
| order by Failures desc
```
<img width="1004" height="340" alt="Screenshot 2025-10-15 at 12 42 49 PM" src="https://github.com/user-attachments/assets/9a53ef25-06f2-4d16-9070-e5a6264a145f" />

## Execution

### PowerShell and CMD execution for discovery commands & Suspicious script execution
After attacker successfully authenticate. Immediately run reconnaissance command at 2025-09-16T19:38:40.063299Z and suspicious scripts commands.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where AccountName == "slflare"
| where Timestamp between (datetime(2025-09-14) .. datetime(2025-09-18))
| where InitiatingProcessAccountName != "system"
| project Timestamp, AccountName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1630" height="882" alt="Screenshot 2025-10-16 at 9 17 01 AM" src="https://github.com/user-attachments/assets/43589346-7c44-414c-975e-80f67576db39" />
The attacker used this command line to launch the binary  - msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1

- Attacker choses C:\ProgramData\Microsoft\Windows\Update** to blend in with legitimate Microsoft processes.
- Mixed user-writable locations (`C:\Users\Public\`) with system folders.
- Used temp directories for data staging before exfiltration

<img width="1616" height="361" alt="Screenshot 2025-10-16 at 8 01 42 AM" src="https://github.com/user-attachments/assets/243aa64c-713e-4976-8466-0f95c5f53a4a" />

## Persistence
The Threat Actor is trying to maintain their foothold.

The attacker established persistence on the system to maintain access. In this case, they created a scheduled task to ensure their payload would execute even after reboot or logoff.

### Mechanisms Deployed

1. Fake Windows Service — **MSUpdateService**
A fake Windows service named MSUpdateService was identified, configured under the registry path
**HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSUpdateService.**
This service points to the binary path **C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1**, which is executed on system boot.
The service is masquerading as a legitimate Microsoft Update service to avoid detection and maintain persistence.

2. Registry Run Key — **MSCloudSync**
A malicious registry run key named MSCloudSync was found under
**HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run.**
Its value data launches a PowerShell script (mscloudsync.ps1) to execute the payload each time a user logs in.
This entry imitates a Microsoft cloud synchronization service, serving as an additional persistence mechanism.

3. Scheduled Task — **MicrosoftUpdateSync**
A scheduled task titled MicrosoftUpdateSync was created and registered in
**TaskCache\Tree\MicrosoftUpdateSync** on 2025-09-16 19:39:45.
This task provides an extra trigger for payload execution and is disguised as a Windows Update scheduling process to blend in with legitimate system operations.

![image copy](https://github.com/user-attachments/assets/b4de6d67-235f-4d0c-b537-956f469c5f11)

✅ Summary:
The attacker implemented three persistence mechanisms — a fake service, a registry run key, and a scheduled task — all designed to masquerade as legitimate Microsoft update or synchronization components, ensuring payload execution on system startup or user login while maintaining stealth and persistence.




