# SOC Phishing Incident Response Playbook

## Project Overview

This project documents a structured Security Operations Center (SOC) approach to investigating and responding to phishing incidents.

It provides practical investigation procedures for identifying phishing emails, analyzing malicious URLs and attachments, assessing user interaction, collecting evidence, and coordinating incident response activities.

The playbook is designed around the responsibilities and investigation workflow of an L1 SOC Analyst, including escalation to L2 and Incident Response teams when required.

## Objectives

- Establish a structured phishing investigation workflow.
- Identify suspicious senders, domains, URLs and attachments.
- Understand email authentication mechanisms such as SPF, DKIM and DMARC.
- Assess user interaction and potential account compromise.
- Investigate phishing involving QR codes and malicious attachments.
- Document evidence and Indicators of Compromise (IOCs).
- Define containment, recovery, escalation and reporting procedures.

## Playbook Coverage

| Area | Description |
|---|---|
| Phishing investigation | Alert validation, sender investigation and user interaction |
| Email header analysis | Header fields, sender validation and routing |
| Email authentication | SPF, DKIM, DMARC and domain alignment |
| Threat intelligence | IP and domain reputation analysis |
| URL investigation | Malicious URLs, redirects and credential harvesting |
| QR code phishing | QR decoding and quishing investigation |
| Attachment analysis | File hashes, malware reputation and process investigation |
| Incident response | Containment, eradication, recovery and closure |
| Evidence management | Evidence collection, integrity and chain of custody |
| Escalation and reporting | Incident handover, severity and reporting |

## Tools and Technologies

| Tool | Investigation Use |
|---|---|
| Microsoft Defender for Office 365 | Email threat investigation |
| VirusTotal | URL, domain and file reputation |
| AbuseIPDB | IP reputation analysis |
| URLScan | Website and redirect analysis |
| ANY.RUN | Controlled sandbox analysis |
| CyberChef | QR decoding, hashing and data transformation |
| Hybrid Analysis | Malware behaviour analysis |
| Microsoft Defender for Endpoint | Endpoint investigation |

## Incident Response Workflow

1. Detection and identification
2. Investigation and analysis
3. Scope and impact assessment
4. Containment
5. Eradication
6. Recovery
7. Evidence documentation and incident closure
8. Post-incident review

## Repository Structure

```text
soc-incident-response-playbook/
│
├── Playbooks/
│   └── 01-Phishing/
│       └── phishing-response.md
│
└── README.md
```

## Key SOC Investigation Concepts

This project covers practical security investigation concepts, including:

- Phishing and brand impersonation
- Email spoofing and authentication
- Indicators of Compromise (IOCs)
- Threat intelligence correlation
- Credential theft and account compromise
- Malware analysis fundamentals
- Security log correlation
- Incident severity and escalation
- Evidence preservation and documentation

## Project Scope and Disclaimer

This repository is intended for learning, portfolio demonstration and reference purposes.

Investigation and response activities should be performed using authorized security tools and according to organizational policies. Actual containment actions depend on the organization's incident response procedures and access permissions.

## Project Status

The initial phishing incident response playbook contains 16 main sections covering investigation, response, evidence management and escalation.

Further playbooks and improvements may be added as the project develops.
