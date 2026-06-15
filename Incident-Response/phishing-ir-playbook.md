# Incident Response Playbook — Phishing Attack

**Playbook ID:** IR-PB-001  
**Version:** 1.0  
**MITRE ATT&CK Coverage:** T1566 (Phishing), T1078 (Valid Accounts), T1110 (Brute Force), T1486 (Data Encrypted for Impact)  
**Severity Trigger:** Medium → Critical (escalates if credentials confirmed compromised)  
**Author:** [David Cox | SOC Analyst
**Last Updated:** 2025
## Playbook Flowchart

![Phishing IR Flowchart](https://raw.githubusercontent.com/siestakeydbc/SOC-Analyst-Portfolio/main/Incident-Response/phishing-ir-flowchart.png)


## Overview

This playbook defines the structured response procedure for suspected phishing incidents within the enterprise environment. It covers the full incident lifecycle from initial alert triage through post-incident review and rule tuning. The playbook is designed to be reproducible in environments using common SOC tooling (SIEM, EDR, email security gateway) and follows the NIST SP 800-61r2 incident handling framework.

**Assumptions:**
- SIEM is operational and ingesting O365/Exchange mail logs, endpoint telemetry, and DNS logs
- An EDR solution (e.g., CrowdStrike Falcon, Microsoft Defender for Endpoint) is deployed on all endpoints
- The analyst has appropriate permissions to access mail compliance search and disable user accounts
- A ticketing system (e.g., Jira, ServiceNow) is in use for tracking

---

## Phase 1 — Detection

### 1.1 Alert Sources

Phishing alerts typically originate from one or more of the following:

| Source | Example Trigger |
|---|---|
| Email security gateway | Suspicious attachment detonated in sandbox |
| SIEM correlation rule | Multiple failed MFA prompts following an email click |
| User report | User forwards suspicious email to `abuse@[domain]` |
| EDR telemetry | Macro-enabled document spawning `powershell.exe` |
| DNS/proxy logs | Outbound connection to newly registered domain post-click |

### 1.2 Initial Alert Review

When an alert is received, the first responder should:

1. Open the associated ticket and assign it to themselves
2. Record the UTC timestamp of initial review
3. Capture the raw alert data (screenshot or export) — this becomes the start of the evidence log
4. Note the originating system and rule name

**CLI — Pull raw alert from SIEM (Elastic/ELK example):**
```bash
# Query for phishing-related email events in the last 24 hours
curl -X GET "localhost:9200/logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          { "match": { "event.category": "email" }},
          { "range": { "@timestamp": { "gte": "now-24h" }}}
        ],
        "filter": [
          { "term": { "rule.name": "Phishing_Suspected" }}
        ]
      }
    }
  }'
```

**What this accomplishes:** Retrieves all email-category events tagged by your phishing detection rule within the last 24 hours, giving you the raw log context needed to begin triage. The output will include sender IP, recipient, subject line, and any associated file hashes.

---

## Phase 2 — Triage

### 2.1 Validate the Alert

The goal of triage is to determine whether the alert is a **true positive** before taking any containment action. Premature containment of a false positive wastes resources and can disrupt legitimate users.

**Checklist:**

- [ ] Inspect email headers for SPF/DKIM/DMARC failures
- [ ] Check sender domain age (newly registered domains are high-risk indicators)
- [ ] Detonate any URLs in an isolated sandbox (e.g., VirusTotal, Any.run, Browserling)
- [ ] Check file hashes against threat intel feeds (VirusTotal, MISP, internal IOC database)
- [ ] Identify all recipients of the email — was this targeted or bulk?
- [ ] Determine if any user clicked the link or opened the attachment

**CLI — Inspect email headers via O365 PowerShell:**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com

# Pull message trace for the suspected sender
Get-MessageTrace `
  -SenderAddress "attacker@suspiciousdomain.com" `
  -StartDate (Get-Date).AddDays(-1) `
  -EndDate (Get-Date) | 
  Select-Object Received, SenderAddress, RecipientAddress, Subject, Status
```

**What this accomplishes:** Returns a delivery record for every email from the suspected sender in the last 24 hours. The `Status` field tells you whether the email was delivered, quarantined, or blocked — and `RecipientAddress` gives you the full scope of who received it.

**CLI — Check URL reputation (VirusTotal API):**
```bash
# Replace YOUR_API_KEY and the URL hash accordingly
curl --request GET \
  --url "https://www.virustotal.com/api/v3/urls/<url-id>" \
  --header "x-apikey: YOUR_API_KEY"
```

### 2.2 Severity Classification

| Condition | Severity |
|---|---|
| Phishing email delivered, no clicks confirmed | Low |
| One or more users clicked the link | Medium |
| Credential entry confirmed on phishing page | High |
| Lateral movement or malware execution detected | Critical |

If **Critical**, escalate immediately to Tier 2 / IR lead and notify management per the escalation matrix.

---

## Phase 3 — Containment

### 3.1 Isolate the Affected Account

If a user is confirmed to have interacted with the phishing content, their account should be disabled immediately to prevent further exposure — particularly if credential theft is suspected.

**CLI — Disable Azure AD / Entra ID user account:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Disable the compromised user account
Update-MgUser -UserId "compromised.user@yourdomain.com" `
  -AccountEnabled:$false

# Revoke all active sessions
Revoke-MgUserSignInSession -UserId "compromised.user@yourdomain.com"
```

**What this accomplishes:** The `AccountEnabled:$false` flag immediately prevents new authentications. The `Revoke-MgUserSignInSession` call invalidates all existing OAuth tokens and session cookies — meaning any attacker who already has a valid session token will be kicked out within minutes as tokens expire.

### 3.2 Block IOCs at the Perimeter

Prevent other users from reaching known-malicious infrastructure identified during triage.

**CLI — Add URL to block list (Defender for Endpoint via PowerShell):**
```powershell
# Requires SecurityCenter.ReadWrite.All permission
$body = @{
  indicatorValue = "http://malicious-phishing-site.com"
  indicatorType  = "Url"
  action         = "Block"
  title          = "IR-PB-001: Phishing URL"
  severity       = "High"
  description    = "Confirmed phishing URL from incident IR-PB-001"
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "https://api.securitycenter.microsoft.com/api/indicators" `
  -Method POST `
  -Headers @{ Authorization = "Bearer $token" } `
  -Body $body `
  -ContentType "application/json"
```

**CLI — Block sender domain in Exchange Online:**
```powershell
# Add the sending domain to the tenant block list
New-TenantAllowBlockListItems `
  -ListType Sender `
  -Block `
  -Entries "suspiciousdomain.com" `
  -Notes "Phishing campaign — IR-PB-001"
```

**What this accomplishes:** The Defender indicator blocks the URL at the network layer across all enrolled endpoints. The Exchange block list prevents any future email from the sending domain from being delivered — protecting users who might receive follow-up waves of the campaign.

---

## Phase 4 — Eradication

### 4.1 Purge Phishing Emails from All Mailboxes

Even after blocking the sender, copies of the phishing email may still exist in recipient inboxes. These must be removed to prevent users from interacting with them.

**CLI — Compliance search and soft-delete (M365 Purview):**
```powershell
# Step 1: Create the compliance search
New-ComplianceSearch `
  -Name "IR-PB-001-Phishing-Purge" `
  -ExchangeLocation All `
  -ContentMatchQuery 'subject:"Urgent: Verify Your Account" AND from:suspiciousdomain.com'

# Step 2: Start the search
Start-ComplianceSearch -Identity "IR-PB-001-Phishing-Purge"

# Step 3: Review results before purging
Get-ComplianceSearch -Identity "IR-PB-001-Phishing-Purge" | 
  Select-Object Name, Status, Items, Size

# Step 4: Soft-delete matched emails (moves to Recoverable Items)
New-ComplianceSearchAction `
  -SearchName "IR-PB-001-Phishing-Purge" `
  -Purge `
  -PurgeType SoftDelete
```

> **Note:** `SoftDelete` moves emails to the Recoverable Items folder for 14 days. Use `HardDelete` only if policy requires permanent removal — this action is irreversible.

**What this accomplishes:** The compliance search queries every mailbox in the tenant for emails matching your subject and sender criteria. The purge action removes them silently from user inboxes without any notification, preventing further interaction. The `Status` check between steps 2 and 3 confirms the search completed and shows how many items were found before you commit to deletion.

### 4.2 Endpoint Scan for Payload / Persistence

If any user clicked an attachment or a link that triggered a download, scan the affected endpoints for indicators of persistence.

**CLI — Trigger live response scan (CrowdStrike RTR example):**
```bash
# Initiate a Real Time Response session to the affected host
# (Requires CrowdStrike API credentials pre-configured)

# List running processes — look for unusual parent-child relationships
runscript --CloudFile="list_processes.ps1" --CommandLine=""

# Check scheduled tasks for persistence mechanisms
runscript --CloudFile="audit_scheduled_tasks.ps1" --CommandLine=""

# Search for the known malicious file hash on disk
runscript --CloudFile="find_hash.ps1" \
  --CommandLine="-Hash 'a1b2c3d4e5f6...'"
```

**CLI — Defender for Endpoint: initiate antivirus scan via API:**
```powershell
$deviceId = "<target-device-id>"

Invoke-RestMethod `
  -Uri "https://api.securitycenter.microsoft.com/api/machines/$deviceId/runAntiVirusScan" `
  -Method POST `
  -Headers @{ Authorization = "Bearer $token" } `
  -Body '{"Comment": "IR-PB-001 eradication scan", "ScanType": "Full"}' `
  -ContentType "application/json"
```

**What this accomplishes:** The RTR session allows you to inspect the live state of the endpoint without requiring physical access or disrupting the user — you can pull process trees, scheduled tasks, registry run keys, and file presence checks in real time. The Defender scan initiates a full AV sweep and logs results back to the portal for evidence.

---

## Phase 5 — Recovery

### 5.1 Restore Account Access

Once the endpoint is confirmed clean and credentials have been reset, re-enable the user account and communicate clearly with the affected user.

**CLI — Re-enable account and force MFA re-registration:**
```powershell
# Re-enable the account
Update-MgUser -UserId "compromised.user@yourdomain.com" `
  -AccountEnabled:$true

# Force MFA re-registration at next sign-in
# (Requires the user's object ID)
$userId = (Get-MgUser -UserId "compromised.user@yourdomain.com").Id

Invoke-MgGraphRequest `
  -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods/passwordMethods/resetPassword" `
  -Body (@{ newPassword = "<temp-secure-password>" } | ConvertTo-Json)
```

**User notification template:**
```
Subject: Action Required — Your Account Has Been Secured

Hi [Name],

Your account was temporarily disabled as a precautionary measure following 
a security incident. We have completed our investigation and your account 
has been restored.

Please take the following steps when you next log in:
  1. You will be prompted to reset your password
  2. You will be asked to re-register your MFA method
  3. Review your email rules and forwarding settings for any changes

If you notice anything unusual, contact the SOC immediately at [contact].

Thank you,
Security Operations
```

### 5.2 Post-Incident Review

A post-incident review should occur within 5 business days of closure. This is one of the highest-value activities a SOC performs — it directly improves detection capability and reduces mean time to respond (MTTR) on future incidents.

**Review agenda:**

1. **Timeline reconstruction** — document every action taken with UTC timestamps
2. **Detection gap analysis** — was the email quarantined? If not, why not? Should a new rule be written?
3. **MITRE ATT&CK mapping** — which techniques were used? Update your coverage matrix
4. **IOC publication** — share confirmed IOCs with your threat intel platform (MISP, OpenCTI)
5. **Rule tuning** — did any detection rules fire too late, produce false positives, or miss the initial wave?
6. **Awareness trigger** — should this incident generate a targeted security awareness reminder to the affected team?

**Lessons learned log entry format:**
```
Incident ID:        IR-PB-001
Date Closed:        YYYY-MM-DD
Severity:           High
Time to Detect:     X minutes
Time to Contain:    X minutes
Time to Close:      X hours

What went well:
- [e.g., Email purge completed within 20 minutes of confirmation]

What could improve:
- [e.g., User MFA prompt was not enforced on initial link click]

Action items:
- [ ] Write Sigma rule for macro-spawned PowerShell from Office processes
- [ ] Enable conditional access policy requiring MFA from external IPs
- [ ] Add domain to MISP feed for sharing
```

---

## Appendix A — Evidence Log Template

| # | Timestamp (UTC) | Action Taken | Tool Used | Analyst | Notes |
|---|---|---|---|---|---|
| 1 | 2025-01-15 14:02 | Alert received and ticket opened | SIEM | J. Smith | Alert ID: 4821 |
| 2 | 2025-01-15 14:08 | Email headers pulled and reviewed | PowerShell | J. Smith | SPF fail confirmed |
| 3 | 2025-01-15 14:15 | User account disabled | Entra ID | J. Smith | Sessions revoked |
| 4 | 2025-01-15 14:22 | IOC URL blocked in Defender | MDE API | J. Smith | Hash also added |
| 5 | 2025-01-15 14:45 | Compliance purge initiated | M365 Purview | J. Smith | 47 mailboxes affected |

---

## Appendix B — MITRE ATT&CK Mapping

| Technique | ID | Phase | Detection Method |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | Email gateway sandbox |
| Valid Accounts | T1078 | Credential Access | MFA anomaly alert |
| OS Credential Dumping | T1003 | Credential Access | EDR process telemetry |
| Scheduled Task / Job | T1053 | Persistence | Scheduled task audit |
| Exfiltration Over C2 Channel | T1041 | Exfiltration | DNS/proxy egress logs |

---

## Appendix C — Tools Referenced

| Tool | Purpose | Documentation |
|---|---|---|
| Microsoft Purview Compliance | Mailbox search and purge | [docs.microsoft.com](https://docs.microsoft.com/en-us/purview/) |
| Microsoft Graph API | Account management, MFA | [graph.microsoft.com](https://graph.microsoft.com) |
| Microsoft Defender for Endpoint | IOC blocking, endpoint scan | [MDE API reference](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/) |
| CrowdStrike Falcon RTR | Live endpoint response | CrowdStrike API docs |
| Elastic / ELK | SIEM log queries | [elastic.co/docs](https://www.elastic.co/docs/) |
| VirusTotal API | URL / hash reputation | [virustotal.com/api](https://developers.virustotal.com/) |

---

*This playbook is part of the SOC Portfolio Project. See the [main README](../README.md) for repo structure and other playbooks.*
