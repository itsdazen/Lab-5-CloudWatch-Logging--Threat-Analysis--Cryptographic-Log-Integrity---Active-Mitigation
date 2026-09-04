# 📊 IKB42603 Lab 5 – Monitoring, Logging & Incident Detection

---

## 📌 Project Overview

This repository contains the work completed for IKB42603 Cloud Computing Security Essentials – Lab 5: Monitoring, Logging & Incident Detection.

The laboratory demonstrates how monitoring, logging, and incident detection mechanisms can be implemented to detect and respond to security threats in cloud-based and containerized environments.

The lab focuses on centralized logging, log querying, tamper-proof (hash-chained) logs, threat detection through event correlation, and incident response procedures using Docker and LocalStack.

The practical activities demonstrate how logs are foundational to security monitoring, how tamper-proof logs maintain integrity, how correlation detects incidents that individual logs cannot reveal, and how incident response contains and documents security events.

---

## 🎯 Objectives

The main objectives of this laboratory are:

- 📝 Collect and centralize logs from multiple services
- 📊 Distinguish logs from events
- 🔍 Query logs for security-relevant activity
- 🔗 Build a tamper-evident (hash-chained) log
- 🚨 Detect an incident by correlating events
- ⚡ Execute incident-response steps: detect, contain, collect evidence, document timeline
- 📋 Write an incident report

---

## 🛠️ Tools & Technologies

| Tool / Technology | Purpose |
|---|---|
| 🐳 Docker | Container runtime and LocalStack |
| ☁️ LocalStack | Local AWS CloudWatch Logs emulation |
| 🔑 AWS CLI v2 | CloudWatch Logs interaction |
| 🔧 grep, awk, sed | Log analysis and manipulation |
| 🔐 sha256sum | Hash generation and verification |
| 🔥 iptables | Firewall rule modeling for containment |
| 🧊 Alpine Linux | Lightweight container environment |

---

## 🧪 Lab Environment

The laboratory consists of two main sessions:

### Session A – Authentication & Authorization

The first session focuses on controlling **WHO can access a service and WHAT they are allowed to do**.

```text
Session A
│
├── 📝 Task 1 – Generate Application Logs
│   └── Authentication Events (LOGIN_OK, LOGIN_FAIL, EXPORT_DATA)
│
├── 📝 Task 2 – Centralize Logs (Ship to CloudWatch)
│   └── Put Log Events and Read Back
│
└── 📝 Task 3 – Query for Security-Relevant Activity
    └── Failed Login Count Grouped by IP
```
```
Session B
│
├── 📝 Task 4 – Tamper-Proof (Hash-Chained) Logs
│   └── Chain Each Line to Previous Hash
│
├── 📝 Task 5 – Detect the Incident (Correlation)
│   └── Brute-Force → Compromise → Data Exfiltration
│
└── 📝 Task 6 – Incident Response
    └── Contain, Collect Evidence, Document
```
---

##🔐 Security Best Practices Checklist

☑ 📊 Logs are centralized, not left scattered on each host

☑ 🔍 Security-relevant activity (failed logins) can be queried

☑ 🔗 Logs are tamper-evident (hash chain) and forwarded to a separate store

☑ 🚨 An incident is detected by correlating multiple events

☑ ⚡ Incident response performed: contain, collect evidence, document

---

This repository was created for educational purposes as part of IKB42603 Cloud Computing Security Essentials course.


