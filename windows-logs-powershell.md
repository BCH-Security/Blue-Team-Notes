# Windows-Logs-PowerShell.md

## 🔹 Overview

Windows Event Logs can be queried programmatically using **PowerShell**, leveraging **XML (XPath) queries** for precise filtering.

This is especially useful for:

* Threat hunting
* Incident response
* Automation & scripting
* Event Forwarding / SIEM pipelines

The main cmdlet used is:

```powershell
Get-WinEvent
```

---

## 🔹 What Are XML Event Queries?

Windows Event XML queries:

* Use **XPath syntax**
* Allow deep filtering on:

  * Event IDs
  * Fields inside events
  * Time ranges
  * Users / processes

They are commonly used in:

* Event Viewer (Custom Views)
* Windows Event Forwarding
* PowerShell scripts

---

## 🔹 Basic XML Query Structure

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)]]
    </Select>
  </Query>
</QueryList>
```

### Components:

* **QueryList** → Container
* **Query** → Defines log source (`Security`, `System`, etc.)
* **Select** → XPath filter

---

## 🔹 Common XML Queries + PowerShell Usage

---

### 🔸 Filter by Event ID (Failed Logons)

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625)]]
    </Select>
  </Query>
</QueryList>
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4625)]]</Select></Query></QueryList>"
```

---

### 🔸 Multiple Event IDs

```xml
*[System[(EventID=41 or EventID=6008)]]
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='System'><Select Path='System'>*[System[(EventID=41 or EventID=6008)]]</Select></Query></QueryList>"
```

---

### 🔸 Event ID + Time Range

```xml
*[System[
  (EventID=4624)
  and
  TimeCreated[
    @SystemTime >= '2022-08-03T17:23:25.000Z' and
    @SystemTime <= '2022-08-03T17:23:25.999Z'
  ]
]]
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624) and TimeCreated[@SystemTime&gt;='2022-08-03T17:23:25.000Z' and @SystemTime&lt;='2022-08-03T17:23:25.999Z']]]</Select></Query></QueryList>"
```

---

### 🔸 Event ID + SubjectLogonID

```xml
*[System[EventID=4907]
  and
  EventData[
    Data[@Name='SubjectLogonID']='0x3E7'
  ]
]
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[EventID=4907] and EventData[Data[@Name='SubjectLogonID']='0x3E7']]</Select></Query></QueryList>"
```

---

### 🔸 Event ID + Process + Object

```xml
*[System[EventID=4907]
  and
  EventData[Data[@Name='ProcessName']='C:\Windows\...\TiWorker.exe']
  and
  EventData[Data[@Name='ObjectName']='C:\Windows\...\wpfgfx_v0400.dll']
]
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[EventID=4907] and EventData[Data[@Name='ProcessName']='C:\Windows\...\TiWorker.exe'] and EventData[Data[@Name='ObjectName']='C:\Windows\...\wpfgfx_v0400.dll']]</Select></Query></QueryList>"
```

---

### 🔸 Filter by Event Level (Severity)

| Level | Meaning     |
| ----- | ----------- |
| 1     | Critical    |
| 2     | Error       |
| 3     | Warning     |
| 4     | Information |
| 5     | Verbose     |

```xml
*[System[(Level=2)]]
```

---

### 🔸 Filter by Event Source

```xml
*[System[Provider[@Name='Application Error']]]
```

---

### 🔸 Filter by Time (Last X Minutes)

XPath alone is limited, so use PowerShell:

```powershell
Get-WinEvent -FilterXPath "*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]" -LogName Security
```

➡️ `600000 ms = 10 minutes`

---

### 🔸 Combine Filters (AND / OR)

```xml
*[System[
  EventID=4625
  and
  Provider[@Name='Microsoft-Windows-Security-Auditing']
]]
```

---

### 🔸 Filter by Username

```xml
*[System[EventID=4625]]
and
*[EventData[
  Data[@Name='TargetUserName']='Administrator'
]]
```

```powershell
Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[EventID=4625]] and *[EventData[Data[@Name='TargetUserName']='Administrator']]</Select></Query></QueryList>"
```

---

## 🔹 Practical Tips

* Prefer **FilterXml** over `Where-Object` → much faster
* Use **FilterXPath** for simpler queries
* Always specify `-LogName` when possible
* Combine with:

```powershell
| Format-List *
```

to inspect full event fields

---

## 🔹 When to Use What?

| Method       | Use Case                        |
| ------------ | ------------------------------- |
| FilterXml    | Complex filtering (recommended) |
| FilterXPath  | Lightweight queries             |
| Where-Object | Post-processing only            |

---

## 🔹 Summary

Using **PowerShell + XML queries** gives you:

* High-performance log filtering
* Deep visibility into Windows internals
* SIEM-like querying directly from endpoints

This is a critical skill for:

* Blue Teamers
* SOC Analysts
* Detection Engineers

---
