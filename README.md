# Threat Hunt Report: Nov 2025 Cyber Range Challenge

**Cybersecurity Analyst:** Dion Alexander

**Date Completed:** 2025-11-15  

**Environment Investigated:** gab-intern-vm  

**Timeframe:** October 9, 2025

---

## Targeted Hunt Parameters

- **Lab Environment:** Cyber Range  
- **Platform:** Azure Sentinel Log Analytics Workspace  
- **Primary Endpoint Investigated:** gab-intern-vm  
- **Telemetry Sources Reviewed:**  
  - DeviceProcessEvents  
  - DeviceFileEvents  
  - DeviceNetworkEvents  
- **Analysis Window:** 2025-10-01 through 2025-10-15  
- **Hunt Focus:** Identify early indicators of compromise, detect reconnaissance activity, analyze persistence methods, and investigate any signs of staging or attempted data exfiltration.

---

## Report Summary

This investigation began with a key realization: what initially appeared to be routine remote support activity on **gab-intern-vm** between **October 1–15, 2025** was actually a deliberate intrusion engineered to look like technical assistance.

The threat hunt revealed a structured, multi-stage operation that aligned with a full attack lifecycle:
- **Initial Entry** through suspicious PowerShell execution from the Downloads directory
- **Host & User Reconnaissance** disguised as “support diagnostics”
- **Defense Evasion** using staged tamper artifacts and misleading file names
- **Persistence Establishment** to maintain long-term access beyond the session
- **Data Staging** in preparation for potential exfiltration
- **Deception Artifacts** planted to fabricate a false support narrative

The accumulated evidence makes it clear that this activity was not legitimate troubleshooting. Instead, it was a calculated intrusion leveraging the appearance of remote support to perform unauthorized reconnaissance, prepare for data removal, and maintain covert persistence within the environment.

---

# Adversary Activity Timeline

| **Time (UTC)** | **Flag** | **Adversary Behavior** | **Artifact** |
|----------------|----------|---------------------|------------------|
| *12:22* | Flag 1 | Initial execution initiated | `-ExecutionPolicy` CLI parameter |
| *12:34* | Flag 2 | Defense tampering | `DefenderTamperArtifact.lnk` |
| *12:22* | Flag 3 | Clipboard data access attempt | PowerShell `Get-Clipboard` command |
| *12:50* | Flag 4 | System context reconnaissance | Host enumeration commands |
| *12:51* | Flag 5 | Storage mapping | `wmic logicaldisk get name,freespace,size` |
| *12:51* | Flag 6 | Network connectivity validation | `RuntimeBroker.exe` network checks |
| *12:50* | Flag 7 | Interactive session enumeration | Session enumeration commands |
| *12:51* | Flag 8 | Active process and application inventory | `tasklist.exe` execution |
| *12:52* | Flag 9 | Privilege level assessment | Privilege enumeration commands |
| *12:55* | Flag 10 | Egress validation | `www.msftconnecttest.com` connection |
| *12:58* | Flag 11 | Exfiltration staging activity | `C:\Users\Public\ReconArtifacts.zip` |
| *13:00* | Flag 12 | Outbound data transfer attempt | IP `100.29.147.161` |
| *13:01* | Flag 13 | Scheduled task-based persistence | `SupportToolUpdater` task |
| *13:01-13:02* | Flag 14 | Registry-based autorun persistence | `RemoteAssistUpdater` registry entry |
| *13:02* | Flag 15 | Decoy artifact creation | `SupportChat_log.lnk` |

---

## Starting Point – Identifying the Initial System

**Objective:**  
Identify the appropriate starting point for the hunt by analyzing indicators suggesting that support-themed scripts and helpdesk-style files were executed directly from the Downloads directory in early October.

- **Primary Endpoint:** `gab-intern-vm`  
- **Reasoning:** This system displayed the earliest and most consistent signs of suspicious support-tool activity, including an execution event from the Downloads folder on October 9th, 2025, at 12:22 PM—aligning with the suspected point of initial compromise.
- **KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between(datetime(2025-10-01)..datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| where ProcessCommandLine matches regex @"(?i)(support|help|desk|tool)"
    or FileName matches regex @"(?i)(support|help|desk|tool)"
    or FolderPath matches regex @"(?i)(support|help|desk|tool)"
| project TimeGenerated, DeviceName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="1889" height="834" alt="Screenshot 2025-11-15 005615" src="https://github.com/user-attachments/assets/0904d4e9-65c2-47b3-8c51-2d59c7b90e33" />

---

## Flag Analysis

### Flag 1 – Initial execution initiated
- **Objective:** Determine which command-line argument was used during the earliest execution of the suspicious script.
- **Hypothesis:** Threat actors frequently invoke PowerShell with modified or relaxed execution policies to bypass default security controls.
- **KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between(datetime(2025-10-01)..datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| where ProcessCommandLine matches regex @"(?i)(support|help|desk|tool)"
    or FileName matches regex @"(?i)(support|help|desk|tool)"
    or FolderPath matches regex @"(?i)(support|help|desk|tool)"
| project TimeGenerated, DeviceName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1884" height="790" alt="Screenshot 2025-11-15 010925" src="https://github.com/user-attachments/assets/60541c77-43b2-40a1-8cc8-3e7f179558e8" />


- **Finding:** The first notable execution event was the user on gab-intern-vm running SupportTool.ps1 via PowerShell while explicitly setting -ExecutionPolicy, making it the initial command-line switch seen in the malicious execution chain.
- **Evidence Collected:** `-ExecutionPolicy` in CLI

### Flag 2 – Defense tampering
- **Objective:** Determine whether any files were created to mimic or suggest security control modifications.
- **Hypothesis:** The presence of staged “tamper” artifacts may signal an adversary attempting to imply or facilitate defense bypassing.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:15:00Z)..datetime(2025-10-09T13:10:00Z))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe") and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1900" height="841" alt="Screenshot 2025-11-15 130350" src="https://github.com/user-attachments/assets/4f635c4d-eb6c-430d-922b-bec6299813eb" />

- **Finding:** A shortcut called DefenderTamperArtifact.lnk was found and opened through Explorer.exe on gab-intern-vm, suggesting deliberate interaction. No Defender settings were actually altered, indicating this file functioned purely as a staged tamper decoy.
- **Evidence Collected:** `DefenderTamperArtifact.lnk`


### Flag 3 – Clipboard data access attempt
- **Objective:** Identify quick, low-effort attempts to access sensitive data sources.
- **Hypothesis:** Brief clipboard access is a typical precursor to early-stage data collection.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:15:00Z)..datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine has "Get-Clipboard" or ProcessCommandLine has "clip.exe" or ProcessCommandLine has "Get-Clip"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1842" height="775" alt="Screenshot 2025-11-15 130850" src="https://github.com/user-attachments/assets/8fb5887b-492c-4f1b-897b-92f5ba02f829" />

- **Finding:** The adversary ran a PowerShell one-liner to quietly inspect clipboard contents, representing a short, low-effort data grab typical of early recon for quickly harvesting any exposed credentials or sensitive text.
- **Evidence Collected:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

### Flag 4 – System context reconnaissance
- **Objective:** Detect early attempts to gather fundamental host and user context.
- **Hypothesis:** Adversaries typically enumerate system and account details before progressing to additional actions.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:45:00Z) .. datetime(2025-10-09T13:05:00Z))
| extend cmd = tolower(ProcessCommandLine)
| where cmd has "qwinsta" or cmd has "quser" or cmd has "query"
       or FileName in ("qwinsta.exe","quser.exe","cmd.exe")
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="1917" height="993" alt="Screenshot 2025-11-15 131835" src="https://github.com/user-attachments/assets/e659dec7-7544-42f6-bc82-2bd666a1d71d" />

- **Finding:** The attacker ran qwinsta to enumerate terminal sessions, revealing which users were logged in and how their sessions were stateful or disconnected. The final instance of this session reconnaissance was recorded at 2025-10-09T12:51:44.3425653Z.
- **Evidence Collected:** 2025-10-09T12:51:44.3425653Z

### Flag 5 – Storage mapping
- **Objective:** Identify attempts to discover local or network-accessible storage locations.
- **Hypothesis:** Storage enumeration is often performed before collecting or staging data.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated >= datetime(2025-10-09T12:15:00Z)
      and TimeGenerated <= datetime(2025-10-09T13:10:00Z)
| extend cmd = tolower(ProcessCommandLine), exe = tolower(FileName)
| where cmd contains "logicaldisk" 
      or cmd contains "wmic"
      or exe contains "wmic"
      or cmd contains "get-psdrive"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1894" height="813" alt="Screenshot 2025-11-15 135920" src="https://github.com/user-attachments/assets/bd19dd1f-08f1-46fc-b557-121266e7c6c7" />

- **Finding:** The adversary issued a WMIC query to list local drives and available space, clearly surveying storage options ahead of staging data. The specific command used was:
"cmd.exe" /c wmic logicaldisk get name,freespace,size".
- **Evidence Collected:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

### Flag 6 – Network connectivity validation
- **Objective:** Identify outbound connectivity tests and domain resolution checks.
- **Hypothesis:** Threat actors commonly verify external egress paths prior to attempting data exfiltration.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated >= datetime(2025-10-09T12:50:00Z)
      and TimeGenerated <= datetime(2025-10-09T13:05:00Z)
| extend cmd = tolower(ProcessCommandLine), exe = tolower(FileName)
| where cmd contains "nslookup"
       or exe contains "ping"
       or cmd contains "tracert"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="1775" height="702" alt="Screenshot 2025-11-15 144726" src="https://github.com/user-attachments/assets/6edaf29a-3054-455f-9ccc-d704829f845d" />

- **Finding:** The outbound network traffic traced back to a process spawned under RuntimeBroker.exe, showing that the attacker piggybacked on a common user-context broker process to perform connectivity checks.
- **Evidence Collected:** `RuntimeBroker.exe`
  
### Flag 7 – Interactive session enumeration
- **Objective:** Identify commands used to enumerate active or interactive user sessions.
- **Hypothesis:** Adversaries often check session activity to determine optimal timing and stealth for follow-on actions.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated >= datetime(2025-10-09T12:00:00Z)
      and TimeGenerated <= datetime(2025-10-09T13:05:00Z)
| extend cmd = tolower(ProcessCommandLine), exe = tolower(FileName)
| where cmd contains "qwinsta"
    or cmd contains "quser"
    or cmd contains "query user"
    or cmd contains "query session"
    or cmd contains "whoami"
    or exe contains "qwinsta"
    or exe contains "quser"
| project TimeGenerated,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessUniqueId
| order by TimeGenerated desc
```
<img width="1746" height="890" alt="Screenshot 2025-11-15 145949" src="https://github.com/user-attachments/assets/3f684b2e-45da-4f80-a154-1396b25a6589" />

- **Finding:** Multiple session-discovery commands (query user, query session, qwinsta, quser) ran on gab-intern-vm, all tying back to a single initiating process chain identified by the unique ID 2533274790397065.
- **Evidence Collected:** `2533274790397065`

### Flag 8 – Active process and application inventory
- **Objective:** Identify commands used to list active processes and services on the host.
- **Hypothesis:** Adversaries enumerate running applications to understand defenses, discover targets, and plan subsequent actions.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T15:00:00Z))
| where ProcessCommandLine contains "task"
   or ProcessCommandLine contains "list"
   or ProcessCommandLine contains "sc "
   or FileName contains "task"
   or FileName =~ "sc.exe"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc

```
<img width="1771" height="710" alt="Screenshot 2025-11-15 152048" src="https://github.com/user-attachments/assets/f7f12a0d-fb30-4663-acf6-992ee0c4d0bb" />

- **Finding:** After mapping sessions and privileges, the attacker ran tasklist.exe to list processes, using this native utility as the primary means of building a live inventory of what was running on the host.
- **Evidence Collected:** `tasklist.exe`

### Flag 9 – Privilege level assessment
- **Objective:** Detect attempts to enumerate the account’s security groups and privilege level.
- **Hypothesis:** Understanding available privileges helps an attacker decide whether escalation is needed and which routes are viable.
- **KQL Query Used:**
```
let priv_terms = dynamic(["whoami", "net user"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T15:00:00Z))
| where ProcessCommandLine has_any (priv_terms)
      or FileName has_any (priv_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc

```
<img width="1914" height="837" alt="Screenshot 2025-11-15 153837" src="https://github.com/user-attachments/assets/ff6aa760-429a-41be-b944-115d2a9b6992" />

- **Finding:** The adversary ran whoami /groups to list all security groups tied to the current user, effectively mapping available privileges. The earliest recorded privilege check was at 2025-10-09T12:52:14.3135459Z.
- **Evidence Collected:** 2025-10-09T12:52:14.3135459Z

### Flag 10 – Egress Validation
- **Objective:** Identify early outbound traffic used to confirm external connectivity and validate that the host can communicate outside the environment.
- **Hypothesis:** Adversaries often pair basic egress tests with lightweight host-state actions to ensure conditions are suitable for later data transfer.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (
        datetime(2025-10-09T12:00:00Z) ..
        datetime(2025-10-09T13:20:00Z)
  )
| where FileName contains "support"
    or FolderPath contains "RemoteAssist"
    or FolderPath contains "SupportTool"
| project TimeGenerated, FileName, FolderPath,
         ActionType, InitiatingProcessFileName,
         InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1803" height="753" alt="Screenshot 2025-11-15 154758" src="https://github.com/user-attachments/assets/95d1d071-2244-4093-88df-e7f4d489ea3b" />

```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (
        datetime(2025-10-09T12:00:00Z) ..
        datetime(2025-10-09T13:20:00Z)
  )
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where RemoteUrl !contains "microsoft"
      and RemoteUrl !contains "windows"
| project TimeGenerated, InitiatingProcessFileName,
         RemoteIP, RemoteUrl, RemotePort,
         InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="1870" height="791" alt="Screenshot 2025-11-15 155242" src="https://github.com/user-attachments/assets/8de803a2-f33e-455e-9a16-4088ba029e17" />


- **Finding:** The initial external host reached during the activity was www.msftconnecttest.com, a standard Windows connectivity test endpoint that the attacker repurposed to verify outbound internet access while appearing benign.
- **Evidence Collected:** First outbound: `www.msftconnecttest.com`


### Flag 11 – Exfiltration staging activity
- **Objective:** Identify when the actor gathered previously collected data into a single package or archive.
- **Hypothesis:** Adversaries commonly stage files before extraction, bundling recon outputs to streamline exfiltration and reduce operational noise.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z)..datetime(2025-10-09T13:20:00Z))
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".zip" or FileName has "ReconArtifacts"
| project TimeGenerated,
          FileName,
          FolderPath,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1849" height="809" alt="Screenshot 2025-11-15 155511" src="https://github.com/user-attachments/assets/1aa555d6-d9ca-406d-a8f3-6d8c27a46f30" />

- **Finding:** The attacker bundled collected reconnaissance data into ReconArtifacts.zip, placing it in the shared Public profile at C:\Users\Public\ReconArtifacts.zip as a staging point for potential exfiltration.
- **Evidence Collected:** `C:\Users\Public\ReconArtifacts.zip`

### Flag 12 – Outbound data transfer attempt
- **Objective:** Identify outbound activity that reflects an attempt to send staged data to an external destination.
- **Hypothesis:** Even unsuccessful transfer attempts help adversaries validate which egress channels are open and which paths can be used for full exfiltration.
- **KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z)..datetime(2025-10-09T14:00:00Z))
| where ActionType == "ConnectionSuccess"
| where RemoteIP has "."
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows"
| project TimeGenerated,
          InitiatingProcessFileName,
          RemoteIP,
          RemoteUrl,
          RemotePort,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1875" height="738" alt="Screenshot 2025-11-15 160058" src="https://github.com/user-attachments/assets/5e1aa3ad-b606-444e-a3af-5ae26044f806" />


- **Finding:** Soon after creating ReconArtifacts.zip, the adversary attempted to reach external IP 100.29.147.161, signaling a test or attempt to move the staged data off the host.
- **Evidence Collected:** `100.29.147.161`

### Flag 13 – Scheduled task-based persistence
- **Objective:** Identify persistence mechanisms that ensure the attacker’s tooling will automatically run again after reboot or user sign-in.
- **Hypothesis:** Scheduled tasks allow adversaries to re-establish access without needing to repeat the initial intrusion steps.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z)..datetime(2025-10-09T13:20:00Z))
| where FileName =~ "schtasks.exe"
       or ProcessCommandLine has_any ("schtasks", "Register-ScheduledTask")
| project TimeGenerated,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine,
          InitiatingProcessFileName
| order by TimeGenerated asc

```
<img width="1880" height="836" alt="Screenshot 2025-11-15 160421" src="https://github.com/user-attachments/assets/7f1773d0-cf71-4e06-92fa-36678fed4757" />

- **Finding:** A scheduled task called SupportToolUpdater was set to fire at user logon, guaranteeing that the support-themed script would automatically rerun whenever the user signs in.
- **Evidence Collected:** `SupportToolUpdater`
  
### Flag 14 – Registry-based autorun persistence
- **Objective:** Identify user-level autorun entries created to ensure the attacker’s tooling launches automatically.
- **Hypothesis:** Adversaries often add fallback autorun keys as a secondary persistence method to maintain access if primary mechanisms fail.
- **KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T13:20:00Z))
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1888" height="869" alt="Screenshot 2025-11-15 161241" src="https://github.com/user-attachments/assets/e8e3caf6-ebcf-46cc-b1a8-352c13c961c3" />

- **Finding:** A user-level autorun entry labeled RemoteAssistUpdater served as backup persistence. Even though the raw registry events had aged out of telemetry, scenario owners confirmed this value was created to re-launch the tooling if other mechanisms failed.
- **Evidence Collected:** `RemoteAssistUpdater` as query returned no result, so used this instead.

### Flag 15 – Decoy artifact creation
- **Objective:** Detect artifacts intentionally created to shape or distort the narrative of what occurred on the host.
- **Hypothesis:** Adversaries may plant text or shortcut files that falsely “explain” prior activity, attempting to legitimize or conceal malicious actions.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T13:20:00Z))
| where ActionType in ("FileCreated", "FileModified")
| extend FileExt = tostring(split(FileName, ".")[-1])
| where FileExt in ("txt","log","lnk")
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```

<img width="1919" height="775" alt="Screenshot 2025-11-15 161916" src="https://github.com/user-attachments/assets/59eabaff-9d11-4154-bc9e-f78296219a78" />


- **Finding:** The shortcut SupportChat_log.lnk was found and opened on gab-intern-vm, strongly indicating a deliberately planted “support chat log” meant to reinforce a fake remote-assistance story and disguise the underlying malicious activity.
- **Evidence Collected:** `SupportChat_log.lnk`

---

## MITRE ATT&CK MAPPING

### Phase 1: Initial Compromise (Flag 1)
- **T1059.001 – PowerShell**: Script execution using a relaxed execution policy to bypass safeguards.

### Phase 2: Defense Evasion & Persistence Setup (Flags 2, 13, 14, 15)
- **T1562.001 – Impair Defenses**: Use of staged tamper-themed artifacts to imply security modification.
- **T1053.005 – Scheduled Task**: Persistence achieved through logon-triggered scheduled tasks.
- **T1547.001 – Registry Run Keys / Startup Folder**: Backup autorun persistence added via registry.
- **T1036 – Masquerading**: Deceptive naming and cover artifacts used to disguise malicious activity.

### Phase 3: Comprehensive Discovery (Flags 3–10)
- **T1033 – System Owner/User Discovery**: Enumeration of users and active sessions (Flags 3, 7).
- **T1082 – System Information Discovery**: Gathering system state, privileges, and basic configuration (Flags 4, 9).
- **T1083 – File and Directory Discovery**: Storage enumeration and drive mapping (Flag 5).
- **T1046 – Network Service Discovery**: Network probing and basic connectivity checks (Flag 6).
- **T1057 – Process Discovery**: Enumeration of processes and running applications (Flag 8).
- **T1049 – System Network Connections Discovery**: Inspection of active network paths and outbound communication (Flag 10).

### Phase 4: Collection & Staging (Flags 3, 11, 12)
- **T1560.001 / T1560.002 – Archive Collected Data**: Data collection and compression into an archive.
- **T1074.001 – Local Data Staging**: Staged ZIP file prepared for possible extraction.

### Phase 5: Exfiltration Attempts (Flags 10, 12)
- **T1071.001 – Application Layer Protocol: Web**: Use of HTTP(S)-like outbound traffic for potential C2 or data transfer.
- **T1041 – Exfiltration Over Command Channel**: Attempted movement of staged data to an external endpoint.


---
# Recommendations

## 1. Strengthen PowerShell Controls and Script Execution Policies

**Recommendation**  
Enforce strict PowerShell execution controls and improve script visibility to prevent unauthorized execution.

**Actions**
- Enforce **AllSigned** or **RemoteSigned** execution policies via GPO
- Enable:
  - PowerShell **Module Logging**
  - **Script Block Logging**
  - **PowerShell Transcription**
- Forward all PowerShell logs to SIEM for real-time detection

**Rationale**  
The attacker leveraged PowerShell with `-ExecutionPolicy` to bypass restrictions. Stronger logging and policy enforcement would have identified this behavior earlier.

---

## 2. Restrict Script Execution in User-Controlled Directories

**Recommendation**  
Block executable scripts from user-writable directories such as **Downloads**.

**Actions**
- Deploy AppLocker or WDAC rules to block:
  - `.ps1`, `.bat`, `.cmd`, `.vbs` from untrusted paths
- Enable **Protected Folders** for high-risk directories

**Rationale**  
Initial access originated from a script launched from the Downloads folder—one of the most common user-error attack vectors.

---

## 3. Improve Endpoint Protection and Behavioral Detection Rules

**Recommendation**  
Strengthen EDR/Defender configurations to detect reconnaissance, tamper attempts, and persistence behaviors.

**Actions**
- Enable **Defender Tamper Protection**
- Add alerting for:
  - Suspicious `.lnk` file creation
  - Reconnaissance commands (`whoami`, `qwinsta`, `wmic logicaldisk`)
  - Unexpected scheduled task creation
- Monitor abnormal privilege checks and runtime inventory behaviors

**Rationale**  
The attacker planted fake "support" artifacts and executed multi-phase recon without generating alerts.

---

## 4. Enforce Least Privilege Access

**Recommendation**  
Minimize the permissions available to standard users to reduce post-compromise capability.

**Actions**
- Review and remove unnecessary group memberships
- Apply least-privilege baselines to intern/standard endpoints
- Require MFA for privileged operations

**Rationale**  
The compromised user context was able to run enumeration and persistence commands without elevation.

---

## 5. Strengthen Egress Controls and Outbound Monitoring

**Recommendation**  
Control outbound traffic to prevent adversaries from validating external communications or exfiltrating data.

**Actions**
- Restrict outbound access to only approved domains
- Alert on:
  - Unknown IP connections
  - Non-corporate HTTP traffic
- Enable DNS logging and anomaly detection

**Rationale**  
The adversary validated connectivity using `msftconnecttest.com` and attempted exfiltration to `100.29.147.161`.

---

## 6. Monitor for File Staging and Public Directory Abuse

**Recommendation**  
Detect the aggregation and staging of data in globally writable paths.

**Actions**
- Monitor `C:\Users\Public\` for:
  - ZIP creation
  - Recon data aggregation
  - Anomalous file activity
- Apply hardened ACLs
- Run automated scans for suspicious archives

**Rationale**  
`ReconArtifacts.zip` was staged in a predictable, publicly writable location.

---

## 7. Remove and Detect Persistence Mechanisms

**Recommendation**  
Eliminate existing persistence and establish alerting for new attempts.

**Actions**
- Remove `SupportToolUpdater` scheduled task
- Remove `RemoteAssistUpdater` autorun key
- Alert on:
  - `schtasks /Create` usage
  - Registry writes under `HKCU\...\Run`

**Rationale**  
The attacker established redundant persistence paths to ensure re-entry.

---

## 8. Strengthen User Security Awareness

**Recommendation**  
Educate users on social engineering patterns involving "support" themes and malicious scripts.

**Actions**
- Conduct targeted user training
- Teach safe handling of unexpected scripts/downloads
- Run phishing/support impersonation simulations

**Rationale**  
The intrusion relied on believable support-themed naming to appear legitimate.

---

## 9. Improve Telemetry Retention and SIEM Coverage

**Recommendation**  
Extend telemetry retention to support full forensic investigations.

**Actions**
- Increase EDR retention to **30–90 days**
- Forward endpoint, PowerShell, and registry logs to SIEM
- Archive high-value telemetry long-term

**Rationale**  
Certain persistence events were missing due to low retention windows.

---

## Indicators of Compromise (IoCs)

| IoC Type | Value |
|----------|-------|
| Files | `DefenderTamperArtifact.lnk`, `ReconArtifacts.zip`, `SupportTool.ps1`, `SupportToolUpdater`, `SupportChat_log.lnk` |
| Process | `RuntimeBroker.exe`, `powershell.exe`, `tasklist.exe` |
| Scheduled Task | `SupportToolUpdater` |

---

# Summary

The intrusion followed a structured attack chain disguised as a remote-support workflow.  
The attacker gained initial access through user-executed script activity in **Downloads**, followed by:

- Host and privilege reconnaissance  
- Runtime and storage enumeration  
- Staging data into `C:\Users\Public\`  
- Testing outbound connectivity  
- Establishing multiple persistence mechanisms  
- Placing decoy artifacts such as `SupportChat_log.lnk`

The adversary relied on **living-off-the-land techniques**, using native Windows tools like `PowerShell`, `WMIC`, `whoami`, `qwinsta`, and `tasklist` to avoid detection.  
While exfiltration was unsuccessful, file staging clearly indicates intent to collect and transfer reconnaissance data.

Implementing the above controls will materially improve detection, harden endpoints, and reduce exposure to user-driven compromise scenarios.

---

# Conclusion

The activity observed on **gab-intern-vm** reflects a realistic, multi-stage intrusion leveraging support-themed deception to blend malicious activity into legitimate workflows.

The adversary executed a complete operational chain:

- Untrusted script execution  
- Host and user/session enumeration  
- Privilege and storage discovery  
- Artifact staging  
- Egress validation and simulated exfiltration  
- Multi-layer persistence  
- Deployment of deceptive artifacts  

This hunt highlights the importance of correlating low-signal events into a cohesive narrative.  
Strengthening execution controls, enhancing telemetry, enforcing least privilege, and detecting recon behaviors early will significantly reduce risk and improve response capability.

