# Elastic KQL Cheat Sheet



## 🔹 TGT Requests (Event ID 4768)

```kql
event.code: 4768
```

Fields to display:

* `@timestamp`
* `winlog.event_data.Account_Name`
* `source.ip`
* `winlog.event_data.Ticket_Encryption_Type`
* `winlog.event_data.Result_Code`

---

## 🔹 Service Ticket Requests (Event ID 4769)

```kql
event.code: 4769
```

---

## 🔹 Account with Highest Kerberos Requests

```kql
event.code: 4768
```

➡️ Use **Lens**:

* Group by: `Account_Name`
* Metric: Count
* Sort descending
* Top 1

---

## 🔹 DCSync Detection

```kql
event.code: 4662 and winlog.event_data.Access_Mask: "0x100" and not winlog.event_data.Account_Name: *$
```

---

## 🔹 Failed Login Attempts (Brute Force)

```kql
event.code: 4625
```

➡️ Lens:

* Group by: `Account_Name`, `source.ip`
* Metric: Count

---

## 🔹 Logins Within <10 Minutes

```kql
event.code: 4624
```

➡️ Use ES|QL / TSVB:

* Compute time range per `Account_Name`
* Filter ≤ 600 seconds

---

## 🔹 Logins from Multiple IPs

```kql
event.code: 4624
```

➡️ Lens:

* Group by: `Account_Name`
* Metric: Unique count of `source.ip`
* Filter > 3

---

## 🔹 New User Account Created

```kql
event.code: 4720
```

---

## 🔹 Remote Desktop Logins

```kql
event.code: 4624 and winlog.event_data.Logon_Type: "10"
```

---

## 🔹 Lateral Movement (Logon Type 3)

```kql
event.code: 4624 and winlog.event_data.Logon_Type: "3"
```

---

## 🔹 Reconnaissance via Native Windows Binaries

```kql
event.code: 1 and (
  process.name: "ipconfig.exe" or
  process.name: "net.exe" or
  process.name: "whoami.exe" or
  process.name: "netstat.exe" or
  process.name: "nbtstat.exe" or
  process.name: "hostname.exe" or
  process.name: "tasklist.exe"
)
```

### PsExec Detection

```kql
event.code: 1 and process.command_line: "*psexec*"
```

---

## 🔹 Suspicious Process Creation

```kql
event.code: 1 and (
  process.name: "cmd.exe" or
  process.name: "powershell.exe"
)
```

---

## 🔹 Processes Loading .NET Runtime

```kql
event.code: 7 and file.name: "clr.dll"
```

---

## 🔹 LSASS Handle Access

```kql
event.code: 10 and process.name: "lsass.exe"
```

---

## 🔹 Suspicious Memory Injection

```kql
winlog.event_data.CallTrace: "*UNKNOWN*" and
not process.name: "*Microsoft.NET*" and
not winlog.event_data.CallTrace: "*ni.dll*" and
not winlog.event_data.CallTrace: "*clr.dll*"
```

---

## 🔹 Excessive Thread Creation

```kql
event.code: 8
```

➡️ Use TSVB / ES|QL:

* Bucket by 1h
* Compute avg + stddev
* Detect outliers

---

## 🔹 Suspicious IP Activity

```kql
source.ip: "10.0.0.229" or destination.ip: "10.0.0.229"
```

---

# ✅ Summary

* Use **KQL** for filtering
* Use **Lens / TSVB / ES|QL** for:

  * `stats`
  * `count`
  * `distinct count`
  * `time calculations`
  * `anomaly detection`

---
