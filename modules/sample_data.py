"""
modules/sample_data.py
Preloaded illustrative sample ransomware risk records.

IMPORTANT NOTICE:
  These records are FICTIONAL SAMPLE ASSESSMENTS created solely for
  educational demonstration purposes.  They do not represent findings
  from any real organisation.  Risk scores, likelihood ratings, and
  impact ratings are illustrative and should not be used for actual
  security decision-making without a proper site-specific assessment.
"""

from __future__ import annotations

SAMPLE_RISKS: list[dict] = [
    {
        "risk_id": "RAN-001",
        "title": "Phishing Emails Leading to Credential Theft",
        "description": (
            "Attackers send deceptive emails impersonating trusted entities to trick "
            "employees into revealing login credentials or executing malicious attachments. "
            "Stolen credentials are subsequently used to deploy ransomware payloads across "
            "the corporate network."
        ),
        "affected_asset": "Corporate Email System, Employee Workstations",
        "threat_source": "External Threat Actor (Cybercriminal Group)",
        "existing_controls": "Basic spam filter, periodic security reminders",
        "likelihood": 5,
        "impact": 5,
        "nist_function": "Protect",
        "nist_category": "Awareness and Training",
        "nist_category_id": "PR.AT",
        "nist_explanation": (
            "PR.AT addresses security awareness and training for personnel.  "
            "Reducing phishing susceptibility requires regular, targeted training "
            "so employees can recognise and report suspicious emails before "
            "credentials are compromised."
        ),
        "recommended_mitigation": (
            "Deploy advanced email filtering with sandboxed attachment analysis; "
            "conduct quarterly phishing simulation exercises; enforce phishing-resistant "
            "MFA (FIDO2/hardware keys); implement DMARC/DKIM/SPF email authentication; "
            "establish a one-click phishing-report button in the email client."
        ),
        "risk_owner": "Security Awareness Manager",
        "status": "In Progress",
        "target_date": "2025-09-30",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-002",
        "title": "Unpatched Operating Systems and Software",
        "description": (
            "Critical security patches are not applied within an acceptable timeframe, "
            "leaving known exploitable vulnerabilities in production systems.  Ransomware "
            "operators routinely exploit publicly disclosed vulnerabilities (e.g., EternalBlue, "
            "ProxyShell) to achieve initial access and lateral movement."
        ),
        "affected_asset": "All Servers, Workstations, Network Devices",
        "threat_source": "External Threat Actor, Automated Exploit Scanners",
        "existing_controls": "Manual patch approvals, monthly Patch Tuesday review",
        "likelihood": 4,
        "impact": 5,
        "nist_function": "Protect",
        "nist_category": "Platform Security",
        "nist_category_id": "PR.PS",
        "nist_explanation": (
            "PR.PS covers managing hardware and software platforms in line with risk "
            "strategy.  A robust patch-management programme is a core platform-security "
            "control that directly reduces the attack surface exploited by ransomware."
        ),
        "recommended_mitigation": (
            "Implement automated patch management (e.g., WSUS, SCCM, or cloud-based "
            "patch tools); enforce a 14-day SLA for critical patches and 30-day SLA "
            "for high-severity patches; perform monthly vulnerability scans; maintain "
            "an up-to-date software inventory; test patches in a staging environment "
            "before production rollout."
        ),
        "risk_owner": "IT Operations Manager",
        "status": "Open",
        "target_date": "2025-08-15",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-003",
        "title": "Weak or Reused Administrator Passwords",
        "description": (
            "Privileged accounts use simple, short, or previously breached passwords.  "
            "Credential-stuffing and password-spraying attacks allow threat actors to "
            "authenticate to administrative interfaces and deploy ransomware with "
            "domain-level privileges."
        ),
        "affected_asset": "Active Directory, Server Admin Accounts, Cloud Consoles",
        "threat_source": "External Threat Actor, Insider Threat",
        "existing_controls": "Basic password policy (8 chars, no history check)",
        "likelihood": 4,
        "impact": 5,
        "nist_function": "Protect",
        "nist_category": "Identity Management, Authentication, and Access Control",
        "nist_category_id": "PR.AA",
        "nist_explanation": (
            "PR.AA governs identity management, authentication, and access control.  "
            "Enforcing strong, unique credentials for privileged accounts and adding "
            "MFA directly reduces the likelihood of successful credential-based attacks."
        ),
        "recommended_mitigation": (
            "Deploy a Privileged Access Management (PAM) solution; enforce a minimum "
            "16-character passphrase policy with complexity and history requirements; "
            "mandate MFA on all administrative accounts; integrate a password manager "
            "for service accounts; rotate privileged credentials every 90 days; check "
            "credentials against known-breached-password databases (HaveIBeenPwned API)."
        ),
        "risk_owner": "Identity and Access Management Lead",
        "status": "In Progress",
        "target_date": "2025-07-31",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-004",
        "title": "Missing Multi-Factor Authentication (MFA)",
        "description": (
            "Critical systems, VPN, cloud portals, and email are accessible using "
            "single-factor (password-only) authentication.  Attackers who obtain "
            "credentials through phishing or data breaches can immediately access "
            "sensitive systems without any additional barrier."
        ),
        "affected_asset": "VPN Gateway, Microsoft 365, Cloud Portals, Admin Panels",
        "threat_source": "External Threat Actor",
        "existing_controls": "Password-only authentication",
        "likelihood": 5,
        "impact": 4,
        "nist_function": "Protect",
        "nist_category": "Identity Management, Authentication, and Access Control",
        "nist_category_id": "PR.AA",
        "nist_explanation": (
            "PR.AA mandates appropriate authentication mechanisms.  MFA is a proven "
            "control that significantly reduces account-takeover risk even when "
            "passwords have been compromised."
        ),
        "recommended_mitigation": (
            "Enforce MFA across all externally accessible systems and cloud services; "
            "prioritise phishing-resistant MFA (FIDO2, passkeys) for privileged accounts; "
            "use Conditional Access policies to block authentication anomalies; "
            "disable legacy authentication protocols (NTLM, Basic Auth)."
        ),
        "risk_owner": "Identity and Access Management Lead",
        "status": "Open",
        "target_date": "2025-07-15",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-005",
        "title": "Inadequate Backup and Recovery Procedures",
        "description": (
            "Backups are infrequent, stored online (reachable from the production network), "
            "and untested.  Ransomware can propagate to and encrypt backup repositories, "
            "leaving the organisation with no viable recovery path and forcing a ransom "
            "payment decision."
        ),
        "affected_asset": "Backup Servers, Tape Library, NAS Devices",
        "threat_source": "Ransomware Payload",
        "existing_controls": "Weekly full backup to a network share (online, same domain)",
        "likelihood": 3,
        "impact": 5,
        "nist_function": "Recover",
        "nist_category": "Incident Recovery Plan Execution",
        "nist_category_id": "RC.RP",
        "nist_explanation": (
            "RC.RP addresses restoration activities following a cybersecurity incident.  "
            "Resilient, tested backups are the primary technical recovery control against "
            "ransomware, enabling restoration without paying a ransom."
        ),
        "recommended_mitigation": (
            "Implement a 3-2-1-1-0 backup strategy (3 copies, 2 media types, 1 offsite, "
            "1 offline/air-gapped, 0 errors verified); use immutable object storage for "
            "cloud backups; perform quarterly full-restore drills; document and test the "
            "Recovery Time Objective (RTO) and Recovery Point Objective (RPO); segregate "
            "backup networks from production."
        ),
        "risk_owner": "IT Infrastructure Manager",
        "status": "Open",
        "target_date": "2025-10-31",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-006",
        "title": "Excessive User Privileges (Privilege Creep)",
        "description": (
            "Users accumulate permissions over time through role changes and project "
            "assignments without corresponding de-provisioning.  If a highly privileged "
            "account is compromised, ransomware can spread broadly across file shares, "
            "databases, and administrative systems."
        ),
        "affected_asset": "File Servers, Active Directory, Business Applications",
        "threat_source": "Insider Threat, Compromised Privileged Account",
        "existing_controls": "No regular access reviews; manual de-provisioning on request",
        "likelihood": 3,
        "impact": 4,
        "nist_function": "Protect",
        "nist_category": "Identity Management, Authentication, and Access Control",
        "nist_category_id": "PR.AA",
        "nist_explanation": (
            "PR.AA covers access control and the principle of least privilege.  "
            "Regular entitlement reviews ensure users only retain permissions needed "
            "for current responsibilities, limiting lateral movement blast radius."
        ),
        "recommended_mitigation": (
            "Enforce least-privilege access across all systems; implement quarterly "
            "user-access reviews (UAR) with manager sign-off; automate de-provisioning "
            "via HR system integration; separate administrative roles from standard "
            "user accounts; adopt Just-in-Time (JIT) privileged access for admin tasks."
        ),
        "risk_owner": "Identity and Access Management Lead",
        "status": "Open",
        "target_date": "2025-09-15",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-007",
        "title": "Lack of Endpoint Detection and Response (EDR)",
        "description": (
            "Workstations and servers rely on legacy signature-based antivirus products "
            "that are ineffective against modern fileless ransomware and living-off-the-land "
            "techniques.  Without behavioural detection, ransomware execution is not "
            "identified until encryption has already begun."
        ),
        "affected_asset": "All Endpoints, Servers",
        "threat_source": "Ransomware Payload, Fileless Malware",
        "existing_controls": "Signature-based antivirus (last updated 2 weeks ago)",
        "likelihood": 4,
        "impact": 5,
        "nist_function": "Detect",
        "nist_category": "Continuous Monitoring",
        "nist_category_id": "DE.CM",
        "nist_explanation": (
            "DE.CM requires continuous monitoring of assets for anomalies and indicators "
            "of compromise.  EDR solutions provide real-time behavioural analysis and "
            "automated response capabilities essential for early ransomware detection."
        ),
        "recommended_mitigation": (
            "Deploy an enterprise EDR solution with behavioural analytics and automated "
            "isolation; integrate EDR telemetry with the SIEM; enable application "
            "whitelisting on servers; disable unnecessary scripting engines (PowerShell "
            "Constrained Language Mode, WMIC restrictions); ensure 100% endpoint coverage "
            "and maintain EDR health dashboards."
        ),
        "risk_owner": "Security Operations Manager",
        "status": "Open",
        "target_date": "2025-11-30",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-008",
        "title": "Insufficient Network Segmentation",
        "description": (
            "The internal network is flat, allowing any device to communicate freely with "
            "any other.  Once ransomware gains an initial foothold, it can scan and infect "
            "all reachable hosts, including backup servers, OT systems, and critical "
            "business applications, leading to total network compromise."
        ),
        "affected_asset": "Core Network Infrastructure, VLAN Configuration",
        "threat_source": "Ransomware Lateral Movement",
        "existing_controls": "Perimeter firewall only; no internal micro-segmentation",
        "likelihood": 4,
        "impact": 5,
        "nist_function": "Protect",
        "nist_category": "Technology Infrastructure Resilience",
        "nist_category_id": "PR.IR",
        "nist_explanation": (
            "PR.IR covers infrastructure resilience including segmentation.  "
            "Network segmentation limits lateral movement, containing ransomware "
            "to the initially compromised segment and protecting critical assets."
        ),
        "recommended_mitigation": (
            "Implement network segmentation using VLANs and firewall ACLs; adopt a "
            "zero-trust network model for sensitive segments; deploy internal firewalls "
            "and east-west traffic inspection; isolate OT/ICS networks; restrict SMB "
            "traffic to necessary paths only; use micro-segmentation for crown-jewel "
            "systems."
        ),
        "risk_owner": "Network Security Architect",
        "status": "In Progress",
        "target_date": "2025-12-31",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-009",
        "title": "Poor Security Awareness Among Employees",
        "description": (
            "Employees lack foundational cybersecurity knowledge and are unable to "
            "recognise social engineering, unsafe browsing, removable media risks, or "
            "suspicious activities.  Human error remains the leading initial access "
            "vector in ransomware incidents."
        ),
        "affected_asset": "All Employees, Business Processes",
        "threat_source": "Social Engineering, Insider Error",
        "existing_controls": "Annual compliance training (tick-box exercise)",
        "likelihood": 5,
        "impact": 4,
        "nist_function": "Protect",
        "nist_category": "Awareness and Training",
        "nist_category_id": "PR.AT",
        "nist_explanation": (
            "PR.AT explicitly addresses cybersecurity awareness education and training "
            "for personnel.  A continuous, role-based security awareness programme "
            "reduces human-factor risks that underpin the majority of ransomware "
            "incidents."
        ),
        "recommended_mitigation": (
            "Replace annual tick-box training with monthly micro-learning modules; "
            "run role-based training for privileged users; conduct quarterly phishing "
            "simulations with immediate coaching for click-through employees; establish "
            "a security champion network; track and report awareness metrics to senior "
            "management."
        ),
        "risk_owner": "Security Awareness Manager",
        "status": "In Progress",
        "target_date": "2025-08-31",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-010",
        "title": "Inadequate Logging and Security Monitoring",
        "description": (
            "Critical systems do not forward logs to a centralised SIEM.  Log retention "
            "is insufficient for forensic investigation.  Without timely alerts on "
            "suspicious activity (mass file access, lateral movement, privilege escalation), "
            "ransomware operates undetected for extended dwell times before encryption."
        ),
        "affected_asset": "SIEM Platform, Active Directory, Servers, Network Devices",
        "threat_source": "Ransomware Dwell Time, Advanced Persistent Threat",
        "existing_controls": "Local Windows Event Logs, 7-day retention",
        "likelihood": 3,
        "impact": 4,
        "nist_function": "Detect",
        "nist_category": "Adverse Event Analysis",
        "nist_category_id": "DE.AE",
        "nist_explanation": (
            "DE.AE covers analysing anomalies and indicators of compromise to "
            "characterise events.  Centralised logging with correlation rules and "
            "alerting enables rapid detection of ransomware precursor activity such "
            "as credential harvesting and reconnaissance."
        ),
        "recommended_mitigation": (
            "Deploy a SIEM with pre-built ransomware detection use cases; forward "
            "logs from endpoints, Active Directory, DNS, firewalls, and cloud services; "
            "retain logs for a minimum of 12 months; create alerts for mass file "
            "rename/delete events; integrate threat intelligence feeds; establish a "
            "24/7 SOC or Managed Detection and Response (MDR) service."
        ),
        "risk_owner": "Security Operations Manager",
        "status": "Open",
        "target_date": "2025-10-15",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-011",
        "title": "Exposed Remote Access Services (RDP, SSH)",
        "description": (
            "Remote Desktop Protocol (RDP) and SSH services are exposed directly to "
            "the internet on default ports without IP allowlisting or rate-limiting.  "
            "Ransomware groups routinely scan for exposed RDP as a primary initial "
            "access vector, using brute-force or purchased credentials."
        ),
        "affected_asset": "Internet-Facing Servers, RDP/SSH Services",
        "threat_source": "External Threat Actor, Automated Scanners",
        "existing_controls": "Standard port in use; no IP restriction; no rate-limiting",
        "likelihood": 5,
        "impact": 5,
        "nist_function": "Protect",
        "nist_category": "Identity Management, Authentication, and Access Control",
        "nist_category_id": "PR.AA",
        "nist_explanation": (
            "PR.AA governs access control to logical assets.  Securing or removing "
            "direct internet-facing remote access services is a critical control to "
            "eliminate one of the most commonly exploited ransomware entry points."
        ),
        "recommended_mitigation": (
            "Remove direct internet exposure of RDP/SSH; route all remote access "
            "through a zero-trust network access (ZTNA) solution or MFA-protected VPN; "
            "enable account lockout after 5 failed attempts; restrict access by source "
            "IP allowlist; change default ports; deploy a honeypot for deception-based "
            "detection; regularly audit firewall rules for exposed services."
        ),
        "risk_owner": "Network Security Architect",
        "status": "In Progress",
        "target_date": "2025-06-30",
        "is_sample": 1,
    },
    {
        "risk_id": "RAN-012",
        "title": "Failure to Test Disaster Recovery Procedures",
        "description": (
            "The organisation has documented disaster recovery (DR) and incident "
            "response (IR) plans, but these have never been tested through tabletop "
            "exercises or live DR drills.  In a real ransomware incident, untested "
            "plans lead to confusion, prolonged downtime, and preventable data loss."
        ),
        "affected_asset": "Business Continuity Plans, DR Site, Recovery Runbooks",
        "threat_source": "Ransomware Incident, Business Disruption",
        "existing_controls": "Written DR plan (last reviewed 3 years ago); no test history",
        "likelihood": 3,
        "impact": 5,
        "nist_function": "Recover",
        "nist_category": "Incident Recovery Plan Execution",
        "nist_category_id": "RC.RP",
        "nist_explanation": (
            "RC.RP requires executing and validating restoration activities during and "
            "after an incident.  Regular DR testing identifies plan gaps before a real "
            "incident, reducing recovery time and improving organisational resilience."
        ),
        "recommended_mitigation": (
            "Conduct annual full DR exercises and semi-annual tabletop simulations; "
            "update IR and DR plans after each exercise; assign clear roles and "
            "responsibilities in the IR playbook; test communications with third-party "
            "vendors; document lessons learned and track corrective actions to closure; "
            "involve executive leadership in executive-level tabletop exercises."
        ),
        "risk_owner": "Business Continuity Manager",
        "status": "Open",
        "target_date": "2025-09-30",
        "is_sample": 1,
    },
]
