
# Phishing Incident Response Playbook

## 1. Incident Overview

Phishing is a social engineering attack in which an attacker impersonates a trusted individual or organization to trick users into revealing sensitive information, clicking malicious links, or downloading malicious attachments.

This playbook provides a structured approach for detecting, investigating, containing, eradicating, and recovering from phishing incidents.

## 2. Objective

- Identify and investigate suspected phishing emails.
- Analyze suspicious sender domains, URLs, and attachments.
- Determine the potential impact on users and the organization.
- Prevent credential theft and unauthorized access.
- Provide a standardized incident response procedure.

## 3. Scope

This playbook covers:

- User-reported phishing emails.
- Suspicious email attachments.
- Malicious URLs and QR codes.
- Sender domain impersonation and spoofing.
- Potentially compromised user accounts.
- Phishing emails delivered to multiple employees.

## 4. Incident Severity

Severity should be determined based on the potential impact and investigation findings.

| Severity | Example |
|---|---|
| Critical | Confirmed account compromise with significant unauthorized activity |
| High | Malicious phishing email with confirmed credential submission |
| Medium | Malicious email delivered but no confirmed interaction |
| Low | Spam or suspicious email with no identified malicious indicators |

## 5. Incident Response Lifecycle

1. Detection and Identification
2. Investigation and Analysis
3. Containment
4. Eradication
5. Recovery
6. Post-Incident Review

## 6. Tools and Technologies

| Tool | Purpose |
|---|---|
| Microsoft Defender for Office 365 | Email threat investigation |
| VirusTotal | URL, domain and file reputation |
| AbuseIPDB | IP address reputation |
| URLScan | URL and website analysis |
| ANY.RUN | Malware sandbox analysis |
| Email Header Analyzer | Email header investigation |

## 7. Investigation and Response

### 7.1 Alert Validation

- Identify whether the email was reported as phishing or spam.
- Collect the reported email and user details.
- Check whether other employees received the same email.
- Identify the email subject, sender and recipient.

### 7.2 Sender Investigation

- Examine the sender email address and domain.
- Identify potential spoofing and typosquatting.
- Check domain reputation using threat intelligence platforms.
- Review domain registration information where available.

### 7.3 Email Header Investigation

- Examine From, Reply-To and Return-Path fields.
- Identify the originating mail server and sending IP.
- Review SPF, DKIM and DMARC authentication results.
- Investigate suspicious email routing information.

### 7.4 URL Investigation

- Extract URLs from the reported email.
- Check URL reputation using VirusTotal and URLScan.
- Examine redirects and destination domains.
- Use approved isolated analysis environments when required.
- Never click suspicious URLs directly.

### 7.5 Attachment Investigation

- Identify attachment names, types and hashes.
- Check file reputation using threat intelligence platforms.
- Analyze suspicious files in an approved malware sandbox.
- Inspect embedded URLs, QR codes and suspicious content.
- Never download or execute suspicious attachments on a normal workstation.

### 7.6 User Validation

- Contact the user if additional business context is required.
- Verify whether the communication was expected.
- Determine whether the user clicked any links or opened attachments.
- Check whether credentials were submitted.

### 7.7 Incident Classification

Based on the investigation findings, classify the email as:

- Confirmed Phishing
- Spam
- Legitimate Email
- Suspicious / Inconclusive

Document the investigation findings and escalate according to organizational procedures.

## 8. Email Header Analysis

### 8.1 Objective

Analyze email headers to identify suspicious sender information, authentication results, routing details and potential email spoofing.

### 8.2 Important Email Header Fields

| Header Field | Investigation Purpose |
|---|---|
| From | Identifies the displayed sender address |
| Return-Path | Identifies the envelope sender |
| Reply-To | Identifies the reply destination |
| Received | Shows the email routing path |
| Authentication-Results | Contains SPF, DKIM and DMARC results |

### 8.3 Investigation Findings

**Scenario:** A suspicious email impersonating Microsoft Security Team.

**Observed sender domain:** micr0soft-security.com

**Authentication Results:**
- SPF: PASS
- DKIM: PASS
- DMARC: PASS

**Suspicious Indicator:**

The sender domain uses the number zero (0) instead of the letter o in Microsoft.

**Finding:** Potential typosquatting and brand impersonation.

### 8.4 Analyst Conclusion

Despite successful SPF, DKIM and DMARC authentication, the sender domain appears suspicious.

Authentication success does not guarantee sender legitimacy.

Further investigation of domain registration, reputation, URLs and email content is required before final classification.

## 9. Email Authentication Analysis – SPF, DKIM and DMARC

### 9.1 SPF (Sender Policy Framework)

SPF is an email authentication mechanism that verifies whether the sending mail server's IP address is authorized to send emails on behalf of a domain.

**How SPF works:**
1. The receiving mail server identifies the sender's IP address.
2. It retrieves the sender domain's SPF record from DNS.
3. It checks whether the sending IP is authorized.
4. It generates an SPF authentication result.

**Example SPF record:**

    v=spf1 ip4:192.0.2.10 -all

| Result | Meaning |
|---|---|
| Pass | Sending IP is authorized |
| Fail | Sending IP is not authorized |
| SoftFail | Sending IP is probably unauthorized |
| Neutral | No definitive statement |
| None | No SPF record found |
| Temperror | Temporary DNS error |
| Permerror | Permanent SPF configuration error |

### 9.2 DKIM (DomainKeys Identified Mail)

DKIM uses cryptographic signatures to verify the integrity of signed email content and identify the signing domain.

**How DKIM works:**
1. The sender signs selected email headers and the message body using a private key.
2. The receiving server retrieves the corresponding public key from DNS.
3. The receiving server verifies the digital signature.
4. It generates a DKIM authentication result.

| Result | Meaning |
|---|---|
| Pass | Signature successfully verified |
| Fail | Signature verification failed |
| None | No DKIM signature found |
| Neutral | No definitive result |
| Temperror | Temporary verification error |
| Permerror | Permanent verification error |

### 9.3 DMARC (Domain-based Message Authentication, Reporting and Conformance)

DMARC evaluates SPF and DKIM authentication results and checks domain alignment with the visible From address.

**How DMARC works:**
1. Identify the visible From domain.
2. Evaluate SPF and DKIM authentication.
3. Check SPF and DKIM domain alignment.
4. If at least one mechanism passes authentication and alignment, DMARC passes.
5. Otherwise, DMARC fails and the published policy is evaluated.

**Example DMARC DNS record:**

    v=DMARC1; p=reject; rua=mailto:dmarc@company.com

**DMARC policies:**

| Policy | Meaning |
|---|---|
| p=none | Monitor without requesting quarantine or rejection |
| p=quarantine | Request suspicious emails to be quarantined |
| p=reject | Request rejection of emails failing DMARC |

**DMARC reports:**
- RUA: Aggregate authentication reports.
- RUF: Forensic or failure reports, where supported.

### 9.4 SPF and DKIM Alignment

DMARC requires at least one of these conditions:

- SPF passes and the authenticated SPF domain aligns with the visible From domain.
- DKIM passes and the DKIM signing domain aligns with the visible From domain.

**Example:**

Visible From domain: company.com

| Mechanism | Authentication | Alignment |
|---|---|---|
| SPF | Pass | Fail |
| DKIM | Pass | Pass |

**DMARC Result: PASS**

Reason: DKIM authentication passed and the signing domain aligned with the visible From domain.

### 9.5 SOC Analyst Investigation Checklist

- Identify the visible sender domain.
- Extract the sending IP address from email headers.
- Review SPF authentication results.
- Verify DKIM signature results.
- Check DMARC authentication and alignment.
- Identify suspicious sender-domain mismatches.
- Investigate authentication failures.
- Correlate findings with domain, IP and URL reputation.
- Document evidence and determine appropriate escalation.

**Important:** Successful SPF, DKIM and DMARC authentication does not guarantee that an email is legitimate or safe. Further investigation is required.

## 10. Sender IP and Domain Reputation Analysis

### 10.1 IP Address Investigation

Investigate the sender IP address to identify potential malicious activity.

**Tools:**
- AbuseIPDB
- VirusTotal

**Information to collect:**
- Abuse confidence score
- Number of abuse reports
- Last reported date
- Reported abuse categories
- Threat intelligence detections

### 10.2 Domain Reputation Investigation

Investigate the sender domain to identify potential phishing, spoofing and malicious activity.

**Tools:**
- VirusTotal
- URLScan
- WHOIS Lookup
- MXToolbox

**Information to collect:**
- Domain reputation
- Domain creation date
- WHOIS registration information
- DNS records
- Historical malicious activity
- SSL certificate information

### 10.3 Investigation Findings

**Scenario:** Suspicious domain impersonating Microsoft.

**Observed indicators:**
- Recently registered domain.
- Malicious reputation detections.
- Lookalike domain name.
- Fake Microsoft 365 login page.

**Analyst Conclusion:**

The domain exhibits multiple indicators of phishing activity and should be classified as suspicious pending investigation.

### 10.4 Investigation Precautions

- Do not access suspicious websites directly from a normal workstation.
- Use approved threat intelligence platforms.
- Avoid submitting confidential organizational information to public platforms.
- Correlate reputation findings with email headers and SIEM alerts.
- Document evidence and escalate confirmed threats.
## 11. URL Investigation

### 11.1 Objective

Investigate suspicious URLs found in reported phishing emails to identify malicious websites, credential harvesting pages and suspicious redirects.

### 11.2 Tools

- VirusTotal – URL reputation analysis.
- URLScan – Website and redirect analysis.
- ANY.RUN – Controlled analysis of suspicious website behavior.

### 11.3 Investigation Procedure

1. Extract suspicious URLs from the reported email.
2. Check URL reputation using VirusTotal.
3. Review malicious and suspicious vendor detections.
4. Analyze the URL using URLScan.
5. Identify redirect chains and destination domains.
6. Examine website content for fake login pages.
7. Identify potential credential harvesting activity.
8. Record investigation findings and evidence.

### 11.4 Investigation Findings

**Scenario:** A suspicious URL impersonating Microsoft 365.

**Observed indicators:**
- Multiple security vendors flagged the URL.
- URLScan identified a suspicious redirect.
- The destination displayed a fake Microsoft 365 login page.
- The page requested employee credentials.

**Finding:** Potential credential harvesting attack.

### 11.5 Analyst Recommendations

- Identify employees who received the phishing email.
- Determine whether users clicked the malicious URL.
- Verify whether credentials were submitted.
- Review sign-in logs for suspicious authentication activity.
- Escalate confirmed account compromises.
- Block malicious URLs through approved security controls.
- Preserve investigation evidence.

### 11.6 Safety Precautions

- Never click suspicious URLs directly.
- Use approved threat intelligence platforms.
- Do not submit confidential company URLs to public analysis platforms without authorization.
- Use isolated environments for interactive analysis.
- Document all findings for incident escalation.

## 12. QR Code Phishing (Quishing) Investigation

### 12.1 Objective

Identify and investigate malicious QR codes embedded in phishing emails that redirect users to fraudulent websites or credential harvesting pages.

### 12.2 Tools

- CyberChef – QR code decoding.
- VirusTotal – URL reputation analysis.
- URLScan – Website and redirect investigation.
- ANY.RUN – Controlled website behaviour analysis.

### 12.3 Investigation Procedure

1. Collect the reported email.
2. Extract the QR code image.
3. Decode the QR code using an approved tool.
4. Extract the embedded URL.
5. Check URL reputation using VirusTotal.
6. Investigate redirects and destination websites using URLScan.
7. Identify fake login pages and credential harvesting attempts.
8. Determine whether users scanned the QR code or submitted credentials.
9. Document findings and escalate according to organizational procedures.

### 12.4 Investigation Findings

**Scenario:** A phishing email contains a QR code impersonating Microsoft 365.

**Observed indicators:**
- QR code redirects to a suspicious domain.
- Multiple security vendors flag the URL.
- Destination displays a fake Microsoft 365 login page.
- One employee submitted credentials.

**Finding:** QR-code-based credential harvesting attack.

### 12.5 Recommended Response

- Identify all affected employees.
- Investigate users who scanned the QR code.
- Determine whether credentials were submitted.
- Reset compromised passwords.
- Revoke active sessions and tokens where supported.
- Review sign-in logs and MFA activity.
- Quarantine phishing emails.
- Block malicious URLs through approved security controls.
- Monitor affected accounts for suspicious activity.

### 12.6 Safety Precautions

- Never scan suspicious QR codes using personal devices.
- Decode QR codes using approved analysis tools.
- Do not visit extracted URLs directly.
- Avoid uploading confidential email content to public platforms without authorization.
- Preserve evidence for incident investigation.

# Section 13 – Attachment and Malware Analysis

## 13.1 Introduction

Phishing emails may contain malicious attachments designed to infect systems, steal information or execute unauthorized commands.

Common suspicious attachments include:

- `.exe` – Executable files
- `.js` – JavaScript files
- `.vbs` – VBScript files
- `.bat` – Batch files
- `.ps1` – PowerShell scripts
- `.docm` – Macro-enabled Word documents
- `.xlsm` – Macro-enabled Excel documents
- `.iso` – Disk image files
- `.zip` – Compressed archives that may contain malicious files

**Example:** An employee receives an unexpected email containing `Invoice_2026.xlsm`.

A SOC Analyst should investigate the attachment safely before determining whether it is malicious.

## 13.2 Initial Attachment Investigation

When an employee reports a suspicious attachment:

1. Collect the attachment using approved procedures.
2. Record the file name, extension, size and source email.
3. Do not open the attachment on a normal workstation.
4. Do not enable macros or execute suspicious files.
5. Preserve the original attachment as evidence.
6. Follow the organization's evidence-handling procedures.

**Important:** Never execute suspicious attachments directly on your personal or corporate workstation.

## 13.3 File Hash Analysis

A file hash is a unique-looking digital fingerprint generated from the contents of a file.

Common hashing algorithms:

- MD5
- SHA-1
- SHA-256

SHA-256 is commonly used for malware identification and threat intelligence.

**Why do SOC Analysts calculate file hashes?**

- To identify known malicious files.
- To search for previously reported malware.
- To compare files across different security tools.
- To share Indicators of Compromise (IOCs) with security teams.

**Important points:**

- A hash lookup does not execute the file.
- If the file changes, its hash will generally change.
- An unknown hash does not automatically mean the file is safe.
- A hash reputation result should be considered alongside other evidence.

## 13.4 Malware Reputation Analysis

SOC Analysts can use the following tools to investigate suspicious files.

| Tool | Purpose |
|---|---|
| VirusTotal | Checks file hashes and files against multiple security engines |
| ANY.RUN | Interactive malware sandbox analysis |
| Hybrid Analysis | Automated malware analysis and behavioural reports |
| CyberChef | Performs hashing, decoding and data transformations |
| Microsoft Defender for Endpoint | Investigates endpoint alerts, processes and suspicious activity |

**VirusTotal:** Useful for checking whether a file hash has previously been identified as malicious.

**ANY.RUN:** Allows analysts to observe suspicious file behaviour in a controlled environment.

**Hybrid Analysis:** Provides information about file behaviour, processes and network activity.

**Caution:** Do not upload confidential company files to public analysis platforms unless organizational policy explicitly permits it.

## 13.5 Process Tree Investigation

A process tree shows the relationship between processes running on a system.

Example:

    EXCEL.EXE
        └── powershell.exe
                └── suspicious.exe

This process chain is suspicious because Excel launches PowerShell, which then executes an unknown file.

A SOC Analyst should investigate:

- Parent and child processes.
- Process command-line arguments.
- File paths.
- File hashes.
- Network connections.
- Execution timestamps.
- Related endpoint alerts.

**Important:** PowerShell is a legitimate Windows administration tool. However, attackers may abuse it to download malware, execute scripts, collect information or communicate with command-and-control infrastructure.

A suspicious process chain is an indicator for further investigation, not automatic proof of malware.

## 13.6 Malware Investigation Scenario

**Scenario:**

An employee receives an email containing `Invoice_2026.xlsm`.

During investigation:

- 12 antivirus engines identify the file as a Trojan.
- The file launches PowerShell.
- PowerShell executes `suspicious.exe` from the Downloads folder.

**SOC Analyst investigation:**

1. Collect and calculate the file's SHA-256 hash.
2. Check the hash reputation using VirusTotal.
3. Investigate the file in an approved sandbox.
4. Review the endpoint process tree.
5. Examine PowerShell command-line activity.
6. Check network connections and related security alerts.
7. Determine whether the file was executed and whether the endpoint was compromised.
8. Escalate the incident and initiate containment according to the organization's procedures.

## 13.7 Indicators of Compromise (IOCs)

During attachment investigation, collect relevant IOCs:

- File name.
- File hash (SHA-256).
- Malicious domain.
- IP address.
- Suspicious URL.
- Process name.
- File path.
- Command-line arguments.

These indicators can help identify other affected systems and support threat hunting.

## 13.8 Key Takeaways

- Never open suspicious attachments directly on a normal workstation.
- Calculate file hashes before investigating file reputation.
- Use approved sandbox environments for behavioural analysis.
- Investigate suspicious parent-child process relationships.
- PowerShell is legitimate but can be abused by attackers.
- An unknown hash does not mean a file is safe.
- Preserve evidence and follow organizational procedures.
- Correlate multiple indicators before declaring a file malicious.

## 13.9 Tools Used

- VirusTotal
- ANY.RUN
- Hybrid Analysis
- CyberChef
- Microsoft Defender for Endpoint

**Objective:** Safely investigate suspicious email attachments, identify potential malware, understand malicious execution behaviour and collect evidence for incident response.

## 14. Containment, Eradication, Recovery and Incident Closure

### 14.1 Containment

Containment aims to limit the impact of the phishing attack and prevent further unauthorized access.

**Actions:**
- Reset the compromised user's password.
- Revoke active sessions and refresh tokens where supported.
- Temporarily disable or restrict the compromised account if required.
- Investigate suspicious sign-in activity.
- Review MFA settings and identify unauthorized changes.

### 14.2 Eradication

The objective of eradication is to remove the phishing threat from the organization's environment.

**Actions:**
- Coordinate with the email security team to block confirmed malicious senders, domains and URLs.
- Search for and quarantine or purge phishing emails from affected mailboxes.
- Identify other employees who received or interacted with the phishing email.
- Investigate suspicious attachments and related indicators of compromise.
- Check for suspicious mailbox rules, forwarding configurations and unauthorized access.

### 14.3 Recovery

Before restoring the affected account, verify that it is secure.

**Actions:**
- Confirm that the password has been reset.
- Verify MFA configuration.
- Review sign-in logs and investigate suspicious authentication attempts.
- Remove unauthorized mailbox rules and forwarding configurations.
- Restore account access through the organization's approved recovery process.
- Monitor account activity for further suspicious behaviour.

### 14.4 Post-Incident Monitoring

Continue monitoring the affected account and related indicators for signs of further compromise.

**Monitoring activities:**
- Review sign-in logs for unfamiliar IP addresses, locations and devices.
- Monitor suspicious authentication attempts.
- Check for additional phishing emails from related senders or domains.
- Monitor unusual mailbox activity and outbound emails.
- Escalate any recurring suspicious activity.

### 14.5 Incident Closure and Documentation

Prepare an incident closure report containing:

- Incident summary and detection method.
- Incident timeline.
- Affected users and systems.
- Investigation findings and evidence.
- Indicators of compromise (IOCs), including malicious URLs, domains, IP addresses and file hashes where relevant.
- Containment, eradication and recovery actions.
- Root cause and business impact.
- Final incident status and recommendations.

### 14.6 Preventive Recommendations

To reduce the likelihood of similar phishing incidents:

- Conduct regular employee security awareness webinars.
- Run authorized phishing simulation campaigns.
- Encourage employees to report suspicious emails.
- Enforce MFA and phishing-resistant authentication where possible.
- Strengthen email security using SPF, DKIM and DMARC.
- Review email filtering and URL protection policies regularly.

