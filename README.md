<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

1. Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "monad" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop. 
   
   These events began at : 2025-02-08T14:08:15.5126112Z
   
   Query to locate events: 
   
```
DeviceFileEvents
| where DeviceName == "vm-monad-mde"
| where InitiatingProcessAccountName == "monad"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-08T14:08:15.5126112Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```   
   
2. Searched the DeviceProcessEvents table for any string that contains "tor-browser-windows-x86_64-portable-14.0.6.exe". Based on the logs returned, on 2025-02-08T14:09:56.6984175Z, the user 'monad' on the device 'vm-monad-mde' executed the file 'tor-browser-windows-x86_64-portable-14.0.6.exe' located in 'C:\Users\Monad\Downloads'. The process was initiated with the '/S' command-line parameter, indicating a silent installation of the Tor Browser.
   
   Query to locate events:
``` 
DeviceProcessEvents
| where DeviceName == "vm-monad-mde"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

3. Searched the DeviceProcessEvents table for any indication that user "monad" actually opened the tor browser. There was evidence that they did open it at: 2025-02-08T14:10:36.4346016Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.
   
   Query used to locate event:
```   
DeviceProcessEvents
| where DeviceName == "vm-monad-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
4. Searched the DeviceNetworkEvents table for commonly known Tor port numbers to investigate if there was any Tor network activity. The logs show that from 2025-02-08T14:10:47.0647187Z, the user 'monad' on the device 'vm-monad-mde' successfully established a connection using the 'tor.exe' application located in 'C:\Users\Monad\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'. There were multiple connections made using Tor.
   
   Query used to locate event:
```   
DeviceNetworkEvents
| where DeviceName == "vm-monad-mde"
| where InitiatingProcessAccountName == "monad"
| where RemotePort in ("9001","9030","9040","9050","9051","9150", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
---

## Chronological Events

**8:08:15 AM - File Renamed**

- Initial detection of Tor Browser installer
- File: tor-browser-windows-x86_64-portable-14.0.6.exe
- Location: C:\Users\Monad\Downloads
- SHA256: 8396d2cd3859189ac38629ac7d71128f6596b5cc71e089ce490f86f14b4ffb94

**8:09:56 AM - Process Created**

- Silent installation of Tor Browser initiated
- User 'monad' executed the installer with '/S' parameter
- Command: tor-browser-windows-x86_64-portable-14.0.6.exe /S

**8:10:11 AM - 8:10:12 AM - Files Created**

- Installation process created multiple Tor-related files:
    - Tor.txt (License file)
    - Tor-Launcher.txt (License file)
    - Torbutton.txt (License file)
    - tor.exe (Core Tor executable)
        - SHA256: 02282ab31d10e230f545e67f3b4c1a9a67362bedbf7fe5ed7de7d1fcd1e45d12

**8:10:21 AM - File Created**

- Creation of Tor Browser shortcut
- File: Tor Browser.lnk
- Location: C:\Users\Monad\Desktop\Tor Browser

**8:10:36 AM - 8:10:41 AM - Processes Created**

- Initial launch of Tor Browser
- Multiple Firefox processes spawned (Firefox is the base browser for Tor)
- Tor service initialization
    - Process: tor.exe
    - Location: C:\Users\Monad\Desktop\Tor Browser\Browser\TorBrowser\Tor
    - Configuration: Using local SOCKS port 9150 and Control port 9151

**8:10:47 AM - 8:10:58 AM - Connection Success**

- Tor network connectivity established
- Multiple connection attempts observed:
    - 194.160.170.222:9001
    - 37.120.184.36:9001
    - 85.215.152.106:9001
    - 212.237.217.108:9001
    - Local connection to 127.0.0.1:9150 (SOCKS proxy)

**8:22:25 AM - Files Created**

- Creation of suspicious file and shortcut
- File: tor-shopping-list.txt
- Location: C:\Users\Monad\Documents
- SHA256: 000c12032ad8800bdc0f8c093e39ec1d8fb9c21203a4940eea36723e46a88dde
- Shortcut created in Recent files folder
---
## Summary of Events

The analysis reveals a clear sequence of events showing intentional installation and use of the Tor Browser:

1. The user 'monad' obtained and executed the Tor Browser installer, choosing a silent installation method to minimize visibility.
2. The installation successfully completed, creating necessary components including the core Tor executable and associated documentation.
3. The user launched the Tor Browser, which established multiple connections to known Tor nodes using port 9001, indicating successful connection to the Tor network.
4. After approximately 12 minutes of browsing activity, the user created a file named "tor-shopping-list.txt", which may indicate potential suspicious activity given the context of anonymous browsing.

## Security Concerns

1. The use of silent installation parameters suggests possible attempts to avoid detection.
2. The creation of a "shopping list" file in conjunction with Tor usage could indicate attempts to conduct transactions on dark web marketplaces.
3. Multiple successful connections to Tor nodes confirm actual usage of the anonymous network, not just installation.
  ---
## Response Taken

TOR usage was confirmed on endpoint **vm-monad-mde** by the user **monad**. The device was isolated and the user's direct manager was notified.
