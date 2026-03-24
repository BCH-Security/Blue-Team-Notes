# 🛡️ Windows & SIEM Detection Cheat Sheets

## 🔹 Overview

This repository is a **practical reference for detection engineering, threat hunting, and SOC analysis**, covering Windows logging and SIEM query languages.

It brings together:

* Native Windows logs
* Sysmon telemetry
* Querying with Splunk and Elastic
* PowerShell-based log hunting

The goal is to provide **quick, actionable cheat sheets** for real-world security investigations.

---

## 📂 Repository Contents

### 🔍 `Elastic KQL Cheat Sheet.md`

* KQL queries for:

  * Authentication events
  * Kerberos activity (TGT / TGS)
  * Lateral movement detection
  * Sysmon-based detections
* Focuses on **filtering in Elastic (Kibana Discover)**
* Designed to be used with **Elastic SIEM**

---

### 🔎 `Splunk SPL Cheat Sheet.md`

* Equivalent detections using Splunk SPL:

  * Brute-force attacks
  * Kerberos abuse
  * Suspicious processes
  * Reconnaissance activity
* Includes:

  * `stats`, `sort`, `table`, `eval`
* Useful for **SOC analysts working with Splunk**

---

### ⚙️ `sysmon events.md`

* Overview of **Sysmon** from Microsoft
* Table of **Sysmon Event IDs (1–29, 255)**
* Covers:

  * Process creation
  * Network connections
  * Code injection
  * Persistence techniques
* Essential for **deep endpoint visibility**

---

### 🪟 `windows events.md`

* High-value **Windows Security & System Event IDs**
* Includes:

  * Authentication logs (4624, 4625, etc.)
  * Kerberos events (4768, 4769, etc.)
  * Persistence indicators
  * Defender alerts
* Focus on **what matters for detection**

---

### 💻 `windows powershell logs.md`

* Using **PowerShell** for log analysis
* XML / XPath query examples
* `Get-WinEvent` usage for:

  * Filtering by Event ID
  * Time-based queries
  * User/activity tracking
* Useful for **automation and endpoint investigations**

---

## 🎯 Use Cases

This repo helps you:

* 🔐 Detect authentication attacks (brute force, Kerberos abuse)
* 🧠 Identify lateral movement
* ⚙️ Detect persistence mechanisms
* 🕵️ Perform threat hunting on endpoints
* 📊 Translate detections between **Splunk ↔ Elastic**
* 💻 Query logs directly with PowerShell

---

## 🔄 How to Use

* Use **Splunk SPL Cheat Sheet** if you're in a Splunk environment
* Use **Elastic KQL Cheat Sheet** for Kibana / Elastic SIEM
* Use **Sysmon + Windows logs** for detection logic
* Use **PowerShell queries** for live investigations on endpoints

---

## ⚠️ Notes

* These cheat sheets are **not exhaustive**
* Field names may differ depending on:

  * Log ingestion method (Winlogbeat, Elastic Agent, etc.)
  * Environment configuration
* Always **baseline normal behavior** before alerting

---

## 🚀 Summary

This repository provides a **solid foundation for Windows detection engineering**, combining:

* Log sources (Windows + Sysmon)
* Query languages (SPL + KQL)
* Investigation techniques (PowerShell)

It is designed to be a **hands-on, real-world toolkit** for blue teamers and SOC analysts.

---
