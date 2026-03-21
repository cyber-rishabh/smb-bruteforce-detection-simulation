# 🔐 SIEM-Based SOC Lab using Splunk

![SIEM](https://img.shields.io/badge/SIEM-Splunk-blue)
![Logs](https://img.shields.io/badge/Logs-Sysmon%20%2B%20NXLog-orange)
![Detection](https://img.shields.io/badge/Detection-SPL-green)
![Level](https://img.shields.io/badge/Level-Advanced-red)

---

## 📌 Overview

This project simulates a real-world Security Operations Center (SOC) pipeline where Windows logs are ingested, processed, and correlated in Splunk to detect multi-stage cyber attacks.

The lab integrates Windows Security logs and Sysmon telemetry, forwards them via NXLog, and applies detection engineering techniques using Splunk SPL.

---

## 🏗️ Architecture

The system follows a layered SIEM architecture:

* **Data Source Layer**
  Windows machine generating Security logs and Sysmon telemetry

* **Log Forwarding Layer**
  NXLog forwards logs via Syslog (UDP 514)

* **SIEM Layer**
  Ubuntu server running rsyslog and Splunk Enterprise

* **Detection Layer**
  SPL-based detection rules and correlation logic

* **SOC Layer**
  Dashboards, alerts, and threat hunting interface

📷 See: `/architecture/diagram.png`

---

## 🚀 Features

* Detects repeated failed login attempts (>3 within 5 minutes) using SPL aggregation
* Identifies successful login after brute-force attempts (account compromise detection)
* Correlates multi-stage attack chain (Fail → Success → Execution)
* Monitors process execution using Sysmon telemetry
* Visualizes attack patterns through SOC dashboards

---

## 🔎 Attack Scenario Walkthrough

1. An attacker performs multiple brute-force login attempts on a Windows system
2. After several failed attempts, one login attempt succeeds
3. The attacker executes a process (e.g., cmd.exe / PowerShell)
4. Logs are forwarded via NXLog to the Splunk SIEM
5. Splunk correlates failed logins, successful authentication, and process execution
6. A detection rule triggers an alert for a multi-stage attack

**Outcome:**
The system successfully detects and correlates a complete attack chain using SPL-based logic.

---

## 🧠 Detection Engineering

### 🔹 Brute Force Detection

Detects repeated failed login attempts within a short time window.

```spl
index=windows_logs "failed to log on"
| rex "Account Name:\#011(?<user>[^\s]+)"
| eval user=replace(user, "#011", "")
| bin _time span=5m
| stats count by user, host, _time
| where count > 3
```

---

### 🔹 Successful Login After Failure

Detects compromised accounts following brute-force attempts.

```spl
index=windows_logs ("failed to log on" OR "logged on")
| rex "Account Name:\#011(?<user>[^\s]+)"
| eval user=replace(user, "#011", "")
| eval action=if(searchmatch("failed to log on"), "fail", "success")
| bin _time span=5m
| stats count(eval(action="fail")) as fails,
        count(eval(action="success")) as success
        by user, host, _time
| where fails > 3 AND success > 0
```

---

### 🔹 Full Attack Chain Detection (Advanced)

```spl
index=windows_logs ("failed to log on" OR "logged on" OR "Process Create")
| rex "Account Name:\#011(?<user>[^\s]+)"
| eval user=replace(user, "#011", "")
| rex "Image:\#011(?<process>[^\s]+)"
| eval stage=case(
    searchmatch("failed to log on"), "bruteforce",
    searchmatch("logged on"), "success",
    searchmatch("Process Create"), "execution"
)
| bin _time span=15m
| stats values(stage) as stages, values(process) as processes by user, host, _time
| where mvcount(stages) >= 2
```

---

## 📂 Sample Logs

Example events used for detection:

* Failed login attempts
* Successful authentication
* Process execution events

See: `/logs/sample-events.json`

---

## 🧭 MITRE ATT&CK Mapping

* **T1110** – Brute Force
* **T1078** – Valid Accounts
* **T1059** – Command Execution
* **T1003** – Credential Access

---

## 📸 Screenshots

### Dashboard

![Dashboard](screenshots/dashboard.png)

### Brute Force Detection

![Bruteforce](screenshots/bruteforce_detection.png)

### Attack Chain Detection

![Attack Chain](screenshots/attack_chain_detection.png)

---

## 🛠️ Technologies Used

* Splunk Enterprise
* Sysmon
* NXLog
* Ubuntu Linux
* VMware

---

## 🔗 Related Project

SMB Attack Simulation:
👉 smb-bruteforce-detection-simulation

---

## 🎯 Impact

* Processed 1000+ Windows security events during simulation
* Detected brute-force and multi-stage attacks in near real-time
* Reduced detection time using correlation-based SPL queries
* Demonstrated practical SOC workflow: ingestion → detection → alerting → analysis

---

## 👤 Author

Rishabh Arora
