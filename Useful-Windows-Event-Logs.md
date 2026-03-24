# Useful-Windows-Event-Logs.md

## 🔹 Overview

Windows Event Logs are a critical source of telemetry for:

* Threat detection
* Incident response
* System troubleshooting

Using tools like **Event Viewer** or **PowerShell**, security analysts can monitor key events that indicate:

* Malicious activity
* System changes
* Authentication behavior

This guide provides a **non-exhaustive list of high-value Windows Event IDs**, including **Kerberos authentication events (TGT / TGS)**.

---

# 🔹 Windows System Logs

| Event ID | Name                      | Description                                           | Why It Matters                                                     |
| -------- | ------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| 1074     | System Shutdown/Restart   | Logs when and why a system was restarted or shut down | Detect unexpected restarts (possible malware or attacker activity) |
| 6005     | Event Log Service Started | Indicates system boot (Event Log service start)       | Establish timeline starting point / detect reboots                 |
| 6006     | Event Log Service Stopped | Logged during shutdown                                | Unexpected stops may indicate log tampering                        |
| 6013     | System Uptime             | Shows uptime in seconds (logged daily)                | Short uptime may indicate forced reboot                            |
| 7040     | Service Status Change     | Startup type of a service changed                     | Detect persistence or service tampering                            |

---

# 🔹 Windows Security Logs

## 🔐 Log Integrity & Defender Events

| Event ID | Name                    | Description                   | Why It Matters                               |
| -------- | ----------------------- | ----------------------------- | -------------------------------------------- |
| 1102     | Audit Log Cleared       | Security log was cleared      | Strong indicator of attacker covering tracks |
| 1116     | Malware Detected        | Defender detected malware     | Detect active infections                     |
| 1118     | Remediation Started     | Malware cleanup started       | Track response actions                       |
| 1119     | Remediation Succeeded   | Malware removed successfully  | Confirm threat neutralization                |
| 1120     | Remediation Failed      | Cleanup failed                | Immediate investigation required             |
| 5001     | Defender Config Changed | Real-time protection modified | Possible defense evasion                     |

---

## 🔑 Authentication & Logon Events

| Event ID | Name                       | Description                          | Why It Matters              |
| -------- | -------------------------- | ------------------------------------ | --------------------------- |
| 4624     | Successful Logon           | User successfully logged in          | Baseline normal behavior    |
| 4625     | Failed Logon               | Login attempt failed                 | Detect brute-force attacks  |
| 4648     | Explicit Credentials Logon | Logon using explicit credentials     | Possible lateral movement   |
| 4672     | Privileged Logon           | Admin-level privileges assigned      | Monitor privileged access   |
| 4771     | Kerberos Pre-Auth Failed   | Kerberos authentication failure      | Detect Kerberos brute force |
| 4776     | Credential Validation      | Domain controller validation attempt | Detect authentication abuse |

---

## 🔐 Kerberos Authentication Events (TGT / TGS)

| Event ID                 | Name                      | Description                                     | Why It Matters                                |
| ------------------------ | ------------------------- | ----------------------------------------------- | --------------------------------------------- |
| 4768                     | TGT Request               | Kerberos Ticket Granting Ticket (TGT) requested | Track initial authentication (user logon)     |
| 4769                     | TGS Request               | Kerberos Service Ticket (TGS) requested         | Detect service access & lateral movement      |
| 4770                     | TGS Renewal               | Kerberos service ticket renewed                 | Monitor long-lived sessions                   |
| 4771                     | Pre-Authentication Failed | Kerberos pre-auth failure                       | Brute-force / password spray detection        |
| 4772                     | TGT Request Failed        | Failed TGT request                              | Suspicious authentication attempts            |
| 4773                     | TGS Request Failed        | Failed service ticket request                   | Service access anomalies                      |
| 4768 (RC4/AES anomalies) | Weak Encryption Usage     | TGT using weak encryption                       | Detect downgrade attacks (Kerberoasting prep) |

---

## 🧠 Account & Policy Changes

| Event ID | Name                 | Description                 | Why It Matters          |
| -------- | -------------------- | --------------------------- | ----------------------- |
| 4719     | Audit Policy Changed | Audit settings modified     | Detect logging evasion  |
| 4738     | User Account Changed | Account properties modified | Detect account takeover |

---

## 🗂️ Object Access & Activity

| Event ID | Name             | Description                                        | Why It Matters                       |
| -------- | ---------------- | -------------------------------------------------- | ------------------------------------ |
| 4656     | Handle Requested | Access request to object (file, registry, process) | Detect access to sensitive resources |

---

## ⚙️ Persistence & Scheduled Tasks

| Event ID | Name                    | Description                | Why It Matters                       |
| -------- | ----------------------- | -------------------------- | ------------------------------------ |
| 4698     | Scheduled Task Created  | New scheduled task created | Common persistence technique         |
| 4700     | Scheduled Task Enabled  | Task enabled               | Detect activation of malicious tasks |
| 4701     | Scheduled Task Disabled | Task disabled              | Possible defense evasion             |
| 4702     | Scheduled Task Updated  | Task modified              | Detect suspicious changes            |

---

## 🌐 Network & Share Activity

| Event ID | Name                   | Description                 | Why It Matters                      |
| -------- | ---------------------- | --------------------------- | ----------------------------------- |
| 5140     | Network Share Accessed | Access to shared resource   | Detect lateral movement/data access |
| 5142     | Network Share Created  | New network share created   | Potential data exfiltration path    |
| 5145     | Share Access Check     | Permission check on share   | Reconnaissance activity             |
| 5157     | Connection Blocked     | Firewall blocked connection | Detect malicious traffic attempts   |

---

## 🛠️ System Changes & Services

| Event ID | Name              | Description           | Why It Matters                          |
| -------- | ----------------- | --------------------- | --------------------------------------- |
| 7045     | Service Installed | New service installed | Strong indicator of malware persistence |

---

# 🔹 Key Detection Use Cases

| Use Case                                          | Important Event IDs          |
| ------------------------------------------------- | ---------------------------- |
| Brute-force attacks                               | 4625, 4771, 4776             |
| Kerberos attacks (Kerberoasting, AS-REP Roasting) | 4768, 4769, 4771, 4772, 4773 |
| Account compromise                                | 4624, 4672, 4738             |
| Persistence detection                             | 4698–4702, 7045              |
| Defense evasion                                   | 1102, 4719, 5001             |
| Malware activity                                  | 1116–1120                    |
| Lateral movement                                  | 4648, 4769, 5140             |

---

# 🔹 Practical Tips

* Monitor **TGT (4768)** + **TGS (4769)** together:

  * Normal: small ratio
  * Suspicious: excessive TGS requests → possible Kerberoasting
* Look for:

  * Many **4769** from a single account
  * Weak encryption (RC4)
  * Unusual service access patterns
* Correlate:

  * **4624 + 4768 + 4769** for full authentication flow

---

# 🔹 Summary

Monitoring the right Windows Event IDs — especially **Kerberos authentication events** — allows you to:

* Detect credential attacks early
* Identify lateral movement
* Understand attacker techniques (Kerberoasting, password spraying)

These logs form the **foundation of Windows security monitoring** and should always be centralized and analyzed.

---
