# Sysmon.md

## 🔹 What is Sysmon?

**Sysmon (System Monitor)** is a Windows system service and device driver from Microsoft (part of the Sysinternals suite) that logs detailed system activity to the Windows Event Log.

It is widely used in:

* Threat detection & hunting
* Incident response
* Malware analysis

Unlike native Windows logs, Sysmon provides **deep visibility** into:

* Process creation
* Network connections
* File modifications
* Registry changes
* Code injection techniques

📍 Logs are written under:

```
Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

## 🔹 Sysmon Event IDs Reference Table

| Event ID | Name                          | Description                                                     |
| -------- | ----------------------------- | --------------------------------------------------------------- |
| 1        | Process Create                | Logs process creation with command-line, parent process, hashes |
| 2        | File Creation Time Changed    | Detects timestomping (file creation time modification)          |
| 3        | Network Connection            | Logs outbound/inbound network connections                       |
| 4        | Sysmon Service State Changed  | Sysmon service started or stopped                               |
| 5        | Process Terminated            | Logs when a process exits                                       |
| 6        | Driver Loaded                 | Logs kernel driver loading                                      |
| 7        | Image Loaded                  | Logs DLL/module loads (useful for detecting injected libraries) |
| 8        | CreateRemoteThread            | Detects process injection via remote thread creation            |
| 9        | RawAccessRead                 | Detects raw disk access (often used in credential dumping)      |
| 10       | Process Access                | Logs access to another process (e.g., LSASS dumping)            |
| 11       | File Created                  | Logs file creation events                                       |
| 12       | Registry Object Added/Deleted | Registry key creation/deletion                                  |
| 13       | Registry Value Set            | Registry value modifications                                    |
| 14       | Registry Object Renamed       | Registry key renaming                                           |
| 15       | FileCreateStreamHash          | Detects alternate data streams (ADS)                            |
| 16       | Sysmon Config State Changed   | Sysmon configuration modified                                   |
| 17       | Pipe Created                  | Named pipe creation                                             |
| 18       | Pipe Connected                | Named pipe connection                                           |
| 19       | WMI Event Filter              | WMI persistence via event filters                               |
| 20       | WMI Event Consumer            | WMI consumer creation                                           |
| 21       | WMI Event Consumer to Filter  | Links WMI filter and consumer                                   |
| 22       | DNS Query                     | Logs DNS queries                                                |
| 23       | File Delete                   | Logs file deletions                                             |
| 24       | Clipboard Change              | Logs clipboard modifications                                    |
| 25       | Process Tampering             | Detects process hollowing / tampering                           |
| 26       | File Delete Detected          | File deletion (alternate method)                                |
| 27       | File Block Executable         | Blocked executable file                                         |
| 28       | File Block Shredding          | Detects secure deletion attempts                                |
| 29       | File Executable Detected      | Logs executable file detection                                  |
| 255      | Sysmon Error                  | Sysmon internal error                                           |

---

## 🔹 Why Sysmon Matters in Security

Sysmon is extremely powerful because it enables detection of:

* 🔐 Credential dumping (Event ID 10)
* 🧠 Process injection (Event ID 8)
* 🌐 Command & Control traffic (Event ID 3)
* 📂 Persistence mechanisms (Registry + WMI events)
* 🕵️ Living-off-the-land techniques (LOLBins)

---

## 🔹 Key High-Value Events to Monitor

| Use Case                          | Event ID     |
| --------------------------------- | ------------ |
| Process execution tracking        | 1            |
| Network activity                  | 3            |
| DLL injection detection           | 7, 8         |
| Credential dumping (LSASS access) | 10           |
| Persistence (Registry/WMI)        | 12–14, 19–21 |
| DNS-based exfiltration            | 22           |

---

## 🔹 Pro Tips

* Always deploy Sysmon with a **custom configuration** (e.g., SwiftOnSecurity config)
* Reduce noise by filtering trusted processes
* Forward logs to SIEM (e.g., Elastic)

---

## 🔹 Summary

Sysmon transforms Windows logging from basic to **enterprise-grade telemetry**, making it a critical tool for modern detection engineering and threat hunting.

---
