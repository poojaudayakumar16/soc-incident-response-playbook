
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
