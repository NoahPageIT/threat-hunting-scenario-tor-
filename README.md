# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="1312" height="784" alt="image" src="https://github.com/user-attachments/assets/b74c3ca3-aee9-47cb-805b-dc6e8bde196f" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/NoahPageIT/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "noah-vm-lab"
| where InitiatingProcessAccountName == "noahlab"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-03T05:00:03.2059052Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1606" height="356" alt="image" src="https://github.com/user-attachments/assets/47c45713-5d72-41ea-a5d3-1442738bca2e" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "noah-vm-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1461" height="95" alt="image" src="https://github.com/user-attachments/assets/c7b88de2-875f-42e7-a930-4ed4e8979fd7" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "noah-vm-lab"
| where FileName has_any ("tor.exe", "torbrowser.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1450" height="819" alt="image" src="https://github.com/user-attachments/assets/71b00854-df9c-4310-bc59-02bf667a1983" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "noah-vm-lab" 
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9002", "9030", "9031", "9040", "9050", "9051", "9150", "9151", "9999", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1614" height="362" alt="image" src="https://github.com/user-attachments/assets/e118ede4-b48e-48ef-a787-95984db5e19b" />


---

## Chronological Event Timeline 

## 05:02:36 AM UTC — Silent Tor Browser Installation
User noahlab executed the Tor Browser installer directly from their Downloads folder using a silent install flag, bypassing any visible installation prompt or UAC warning. This was a deliberate and covert action.
Command executed:
tor-browser-windows-x86_64-portable-15.0.8.exe /S


Source: DeviceProcessEvents

## 05:03:14 AM UTC — Tor Establishes Live Network Connection
Within seconds of installation, tor.exe successfully established an outbound connection to external IP 79.194.243.79 over port 9001 — a known Tor relay port — confirming Tor was live and actively connected to the Tor network. Additional connections were made over ports 80 and 443 consistent with Tor bridge traffic blending into normal web traffic.
Process path:
C:\Users\noahlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe


Source: DeviceNetworkEvents

## 05:07:36 AM UTC — Tor Browser Opened by User
User noahlab manually launched the Tor Browser. Multiple instances of firefox.exe (Tor's underlying browser engine) and tor.exe were spawned as child processes, confirming active browser usage, not just a background process.
Source: DeviceProcessEvents

## 05:12:42 AM UTC — Tor Files Copied to Desktop & Suspicious File Created
A large number of Tor-related files were copied to the Desktop. Notably, a file named "tor-shoppinglist" was created on the Desktop at this exact timestamp, suggesting the user was actively using the Tor Browser to conduct activity they deliberately wanted to document or reference.
File created:
C:\Users\noahlab\Desktop\tor-shoppinglist


Source: DeviceFileEvents


---

## Summary

On April 3, 2026, user noahlab on device noah-vm-lab conducted a deliberate and covert sequence of actions consistent with intentional unauthorized use of the Tor Browser.
At 05:02 AM, the user silently installed the Tor Browser from their Downloads folder using the /S flag to suppress any visible installation window. Within 38 seconds at 05:03 AM, Tor had already established a confirmed live connection to the Tor network via a known relay port, indicating the user was familiar with the tool and acted quickly and deliberately.
At 05:07 AM, the user opened the Tor Browser directly, spawning multiple browser and Tor processes, confirming active browsing over the Tor network. By 05:12 AM, Tor-related files had been copied to the Desktop and a file named tor-shoppinglist was created, strongly suggesting the user was actively engaged in Tor-based activity and documenting or planning purchases potentially on dark web marketplaces.
The entire sequence from silent install to active Tor browsing took less than 10 minutes, indicating this was not accidental or exploratory behaviour. The use of a silent install flag, the speed of execution, and the creation of a shopping list file all point to a user who was familiar with Tor, intentionally concealing their activity, and actively using the anonymised network for undisclosed purposes.
This constitutes a confirmed policy violation and warrants immediate escalation, disciplinary review, and further forensic investigation into what was accessed or transacted over the Tor network.

---

## Response Taken

TOR usage was confirmed on endpoint noah-vm-lab By user noahlab. The device was isolated and the user's direct manager was notified.
---
