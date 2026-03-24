
## Splunk's Search Processing Language Cheat Sheet


**TGT Requests (Event ID 4768)**
```
index=* EventCode=4768 | table _time, Account_Name, Client_Address, Ticket_Encryption_Type, Result_Code
```
---


**Service Ticket Requests (Event ID 4769)**
```
index=* EventCode=4769 | table _time, Account_Name, Client_Address, Ticket_Encryption_Type, Result_Code
```
---


**account name with the highest amount of Kerberos authentication ticket requests**
```
index=* EventCode=4768 | stats count by Account_Name | sort -count | head 1
```
---


**Check DCSync attacks**
```
index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```
---


**Failed Login Attempts (Brute Force Detection)**
```
index=* EventCode=4625 | stats count by Account_Name, Client_Address | sort -count
```
---


**accounts whose total login activity occurred within a time range of less than 10 minutes**
```
index=* EventCode=4624 | stats count, range(_time) as TimeRange by Account_Name | where TimeRange <= 600 | sort -count
```
---


**Logins from Multiple IPs (Potential Account Compromise)**
```
index=* EventCode=4624 | stats dc(Client_Address) as unique_ips by Account_Name | where unique_ips > 3
```
---


**New User Account Created**
```
index=* EventCode=4720 | table _time, Target_Account_Name, Subject_Account_Name
```
---


**Remote Desktop Logins**
```
index=* EventCode=4624 Logon_Type=10 | table _time, Account_Name, Client_Address
```
---


**Lateral Movement Detection (Logon Type 3)**
```
index=* EventCode=4624 Logon_Type=3 | stats count by Account_Name, Client_Address | sort -count
```
---



**Detection Of Reconnaissance Activities Leveraging Native Windows Binaries**
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count

index="main" sourcetype="WinEventLog:Sysmon"  EventCode=1 CommandLine: "*psexec*"  | table Image, CommandLine, ParentImage, ParentCommandLine
```


**Suspicious Process Creation**
```
index=* sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
```
---

**Processes that load the .NET runtime**
```
index="main" EventCode=7 ImageLoaded="*clr.dll"  | stats count by Image
```
---


**Processes opening handles to LSASS**
```
index="main" EventCode=10 lsass | stats count by SourceImage
```
---


**Suspicious memory/injection behavior**
```
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* | where SourceImage!=TargetImage | stats count by SourceImage
```
---


**Source process images that are creating an unusually high number of threads in other processes**
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8  | bin _time span=1h | stats count as threads by _time, SourceImage | eventstats avg(threads) as avg_threads, stdev(threads) as stdev_threads | eval Upper_Limit= avg_threads + (2 * stdev_threads) | where threads > Upper_Limit | table _time, SourceImage, threads, avg_threads, stdev_threads, Upper_Limit
```

**Identify events related to a suspicious IP Address**
```
index=* 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host, User
```
---






