# Active Directory Attack and Defence Lab 

## Overview
A hands-on lab documenting Active Directory 
attack techniques, detection methods, and 
defensive controls — aligned with real-world 
SOC investigations and the MITRE ATT&CK framework.

Built to develop practical skills relevant to 
SOC analyst roles at Palo Alto Networks, 
CrowdStrike, and Cisco.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Domain Controller | Windows Server 2019 |
| Client Machine | Windows 10 |
| Attacker Machine | Kali Linux |
| Virtualisation | VirtualBox |
| Domain Name | lab.local |

---

## Attacks Simulated and Detected

### 1. Password Spraying
**MITRE ATT&CK:** T1110.003  
**Description:** Testing one password across 
many accounts to avoid lockouts

**Attack Method:**
- Used CrackMapExec to spray one password
  across all domain accounts
- Avoided lockout by staying below threshold

**Detection:**

Windows Event ID 4625 — Failed Logon
Pattern: Many different usernames
from same source IP
within short time window


**SPL Detection Query:**
```spl
index=windows EventCode=4625
| stats count dc(user) as unique_users 
  by src_ip
| where unique_users > 5
| sort -unique_users
```

---

### 2. Kerberoasting
**MITRE ATT&CK:** T1558.003  
**Description:** Requesting service tickets 
for offline password cracking

**Attack Method:**
- Enumerated accounts with SPNs
- Requested TGS service tickets
- Extracted tickets for offline cracking
- Used Hashcat to crack weak passwords

**Detection:**

Windows Event ID 4769 — Kerberos Service Ticket
Pattern: Multiple TGS requests
RC4 encryption type (0x17)
from single user in short time


**SPL Detection Query:**
```spl
index=windows EventCode=4769
| where Ticket_Encryption_Type="0x17"
| stats count by src_user, src_ip
| where count > 5
| sort -count
```

---

### 3. Pass-the-Hash
**MITRE ATT&CK:** T1550.002  
**Description:** Using NTLM hash to 
authenticate without plaintext password

**Attack Method:**
- Dumped NTLM hash using Mimikatz
- Used hash directly for authentication
- Accessed remote systems as admin

**Detection:**

Windows Event ID 4624 — Successful Logon
Logon Type 3 (Network)
Authentication Package: NTLM
From unexpected source workstation


**SPL Detection Query:**
```spl
index=windows EventCode=4624 
Logon_Type=3 
Authentication_Package=NTLM
| where src_ip!="expected_dc_ip"
| table _time, user, src_ip, 
  Logon_Type, Authentication_Package
```

---

### 4. Golden Ticket Attack
**MITRE ATT&CK:** T1558.001  
**Description:** Forging Kerberos TGTs using 
KRBTGT account hash for persistent domain access

**Attack Method:**
- Obtained KRBTGT hash via DCSync
- Forged TGT for any user
- Used ticket to access all domain resources

**Detection:**

Event ID 4769 — anomalous ticket lifetime
Event ID 4672 — special privileges on unknown account
Tickets with 10-year validity period
Non-existent account authenticating


**Why it is dangerous:**
- Persists even after password resets
- Works for any user including non-existent ones
- Requires KRBTGT password reset TWICE to fix

---

### 5. DCSync Attack
**MITRE ATT&CK:** T1003.006  
**Description:** Impersonating a Domain Controller 
to extract password hashes

**Attack Method:**
- Used Mimikatz lsadump::dcsync
- Extracted hashes for all domain accounts
- Obtained KRBTGT hash enabling Golden Ticket

**Detection:**

Event ID 4662 — AD object accessed
DS-Replication-Get-Changes permission used
Non-DC machine performing replication


**SPL Detection Query:**
```spl
index=windows EventCode=4662
| where Access_Mask="0x100" 
  OR Access_Mask="0x40"
| where src_user!="DOMAIN_CONTROLLER$"
| table _time, src_user, src_ip, 
  Object_Name, Access_Mask
```

---

### 6. BloodHound AD Enumeration
**MITRE ATT&CK:** T1087 — Account Discovery  
**Description:** Mapping attack paths through 
Active Directory

**Attack Method:**
- Ran SharpHound collector
- Imported data into BloodHound
- Identified shortest path to Domain Admin
- Found misconfigured ACLs and delegations

**Detection:**

Excessive LDAP queries to Domain Controller
Event ID 4662 in large quantities
SharpHound.exe in process logs
Large volume of AD object access in short time


---

## Key Defence Recommendations

| Attack | Primary Defence |
|--------|----------------|
| Password Spraying | Account lockout policy, MFA |
| Kerberoasting | Strong service account passwords, AES encryption |
| Pass-the-Hash | Credential Guard, disable NTLM |
| Golden Ticket | Protect KRBTGT, reset password regularly |
| DCSync | Restrict replication permissions |
| BloodHound | Least privilege, regular ACL audits |

---

## Key Learnings
- Understanding of Kerberos and NTLM authentication
- How attackers enumerate and exploit AD
- Detection strategies for common AD attacks
- Importance of least privilege in AD
- How to use BloodHound defensively
- Critical role of KRBTGT account security

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Detected |
|-------------|----------------|---------|
| T1110.003 | Password Spraying | ✅ |
| T1558.003 | Kerberoasting | ✅ |
| T1550.002 | Pass-the-Hash | ✅ |
| T1558.001 | Golden Ticket | ✅ |
| T1003.006 | DCSync | ✅ |
| T1087 | Account Discovery | ✅ |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| BloodHound | AD attack path mapping |
| Mimikatz | Credential extraction |
| CrackMapExec | Network authentication testing |
| Impacket | Windows protocol attacks |
| Hashcat | Offline password cracking |
| Splunk | Log analysis and detection |

---

## References
- MITRE ATT&CK: attack.mitre.org
- BloodHound: github.com/BloodHoundAD/BloodHound
- Microsoft Security Events: docs.microsoft.com
- CompTIA CySA+ CS0-003
