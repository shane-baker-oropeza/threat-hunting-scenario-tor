<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/shane-baker-oropeza/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

### 1. Searched the `DeviceFileEvents` Table

I Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuser” downloaded a tor installer.  This resulted in many tor-related files being copied to the desktop and a file named “tor-shopping-list.txt” being created at 2026-02-26T02:47:54.4446054Z.  These events began at: 2026-02-26T02:16:11.3562341Z.


**Query used to locate events:**

```kql
 DeviceFileEvents
| where DeviceName == "srbo-vm-win11"
| where InitiatingProcessAccountName == "labuser"
| where FileName startswith "tor"
| where Timestamp >= datetime(2026-02-26T02:16:11.3562341Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
```
<img width="1154" height="334" alt="image" src="https://github.com/user-attachments/assets/5fd5829a-3ba8-479a-a094-5e43a59485bd" />


---

### 2. Searched the `DeviceProcessEvents` Table

I searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.7.exe”.  Based on the logs returned, at 2026-02-26T02:32:40.8539521Z, a user on the Windows 11 virtual machine "srbo-vm-win11" opened the Tor Browser.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "srbo-vm-win11"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1264" height="171" alt="image" src="https://github.com/user-attachments/assets/10d414e6-a3bc-4326-9eda-83f70aa79397" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that the user “labuser” actually opened the tor browser.  There was evidence that they did open it at: 2026-02-26T02:41:06.4872682Z  There were several other instances of firefox.exe (Tor) and tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "srbo-vm-win11"
| where ProcessCommandLine has_any("firefox.exe", "tor-browser.exe", "tor.exe", "tor-browser-portable.exe", "tor-browser-windows-x86_64-portable.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1258" height="370" alt="image" src="https://github.com/user-attachments/assets/d24ae18c-da51-4790-91aa-f0def2e1e11e" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents table for any indication that the tor browser was used to establish a connection using any of the known tor ports.  At 2026-02-26T02:41:41.2309794Z, after opening the browser, the user labuser was actively surfing the web on the srbo-vm-win11 virtual machine. While the process appears as firefox.exe on their desktop, it was actually routing all its traffic through a local "middleman" at port 9150—the signature gateway to the Tor network—to keep their online tracks hidden.  There were a couple of other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "srbo-vm-win11"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443, 80)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1427" height="375" alt="image" src="https://github.com/user-attachments/assets/bdf3d81c-3f35-47d2-8045-e40d209f490e" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-26T02:16:11.3562341Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-26T02:32:40.8539521Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-26T02:41:06.4872682Z `
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-26T02:41:41.2309794Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-26T02:41:35.4444888Z` - Connected to `96.9.98.57` on port `443`.
  - `2026-02-26T02:41:41.2309794Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-26T02:47:54.4446054Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "srbo-vm-win11" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on endpoint srbo-vm-win11 by the user “labuser”. The device was isolated and the user's direct manager was notified.

---
