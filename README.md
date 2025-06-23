# 🛡️Internet-Facing VM Brute-Force Simulation

In this lab, we purposely exposed a virtual machine to the public internet to observe how quickly and how often attackers exploit misconfigurations in real-world environments.

_**Inception State:**_ the VM (`r3dant-ls-lab6`) is assumed to be private; no alerts or indicators of compromise exist and the security team has not detected any unusual login activity.

_**Completion State:**_ repeated brute-force attempts are identified from multiple external IPs. No logon succeeds, but the exposure is remediated: the public IP is removed, malicious addresses are blocked, MFA/NLA is enforced, Defender for Endpoint is deployed, Sentinel detection rules are created, and the activity is mapped to MITRE ATT&CK (`T1133`, `T1110.001`).

---

## Technology Utilized
- **Microsoft Defender for Endpoint** (device telemetry, attack-surface reduction, live response)
- **Azure Network Security Groups (NSGs)** (block malicious IPs, remove open RDP/SSH)
- **Azure Portal** (public-IP removal, network reconfiguration)
- **Kusto Query Language (KQL)** (log analysis and enrichment)
  
---

## 📑 Table of Contents

- [Internet-Facing VM Brute-Force Simulation](#️internet-facing-vm-brute-force-simulation)
- [Technology Utilized](#technology-utilized)
- [Initial Exposure Discovery](#-initial-exposure-discovery)
- [Failed Login Analysis](#-failed-login-analysis)
- [Successful Login Verification](#-successful-login-verification)
- [Account Integrity Check](#-account-integrity-check)
- [Final Assessment](#-final-assessment)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Recommended Mitigations](#-recommended-mitigations)
- [Summary Table](#-summary-table)



---
## 🔍 Initial Exposure Discovery

To begin this project, we used Microsoft Defender for Endpoint and a few simple KQL queries to kick off our threat hunt. Our first step was querying the DeviceInfo table, which revealed that our lab VM (r3dant-ls-lab6) had been unintentionally exposed to the internet for several days. This raised immediate concerns and led us to investigate login activity, failed access attempts, and signs of brute force attacks. Here's one of the queries that we started with.



![image](https://github.com/user-attachments/assets/a6dc1cf4-fc81-49db-b9fa-5e3a26522548)
##### 📝r3dant-ls-lab6 has been internet facing for several days: Last internet facing time: 2025-06-17T20:07:41.165522Z

📌 **Note:** This query checks whether the specified VM is exposed to the internet using the `DeviceInfo` table.


---
## 🚨 Failed Login Analysis

Next, we pivoted to login activity to determine whether the exposed VM had been targeted by attackers.

Using the DeviceLogonEvents table, we filtered for failed logon attempts originating from external IP addresses. The results confirmed our suspicion: several unauthorized login attempts had been made against our machine, with multiple bad actors attempting to access the system remotely via RDP and other network logon methods.

The KQL query below shows how we identified the top offending IPs by summarizing failed logon attempts:

![image](https://github.com/user-attachments/assets/9e4b2a0c-8140-4476-84de-183e0ecb7b21)


🧠 Insight: Brute force attacks often come in waves from a wide range of global IPs. Visualizing and counting failed login attempts helps identify targeted attack patterns early even if no login succeeds.

![image](https://github.com/user-attachments/assets/6a5af20e-bb1a-45b2-b988-759f1ab2b309)


---
## ✅ Successful Login Verification

With the failed login attempts identified, our next step was to determine whether any of those suspicious IP addresses had successfully logged into the VM.

Using the query below, we checked for successful logons from the top four offending IPs and confirmed that none of them were able to break in.
This validated that the brute force attempts were unsuccessful, likely due to strong credentials and lack of open access permissions.

![image](https://github.com/user-attachments/assets/31f6b13c-68f7-4804-9808-af4d18d449ff)

🔍 Query Result: No results found, meaning none of the brute force IPs successfully authenticated.



We then looked at which accounts did log in successfully over the past 30 days.
The only account observed making successful remote logons was labuser, our legitimate, preconfigured test account and all 16 logins came from expected, trusted sources.

![image](https://github.com/user-attachments/assets/b4b96893-e9cd-40de-a4b1-32e9b0b4cef4)


🧠 Insight: Because there were no failed logins for labuser, it's unlikely the account was guessed or brute-forced. This behavior is consistent with known, authorized access.

---
## 🧪 Account Integrity Check

Next, we validated the integrity of the legitimate account being used "labuser" to rule out any signs of compromise.

First, we checked whether this account had experienced any failed login attempts. The result showed zero failures, which suggests that:

1) A brute force attempt targeting labuser likely didn’t occur
2) A one-time password guess or credential stuffing attack is highly unlikely

✅ Result: 0 failed logons for labuser

![image](https://github.com/user-attachments/assets/d95fd2c8-7056-49ec-a3d0-0863578c1593)


🛰️ To complete our analysis, we inspected all successful logins made by labuser over the past 30 days and reviewed the originating IP addresses.
Our objective was to identify any anomalous logins, such as those from unexpected regions or infrastructure.

The results showed that all successful logons originated from known and trusted IP addresses, confirming no signs of unauthorized use.


![image](https://github.com/user-attachments/assets/4ee91a75-72c4-4d0f-b128-13ea6fd88d20)

![image](https://github.com/user-attachments/assets/32605d73-2f6e-482e-9468-e5d08b15ef65)

---

## 🧠 Final Assessment

Though the device was exposed to the internet and clear brute force attempts took place, there is no evidence of any successful compromise or unauthorized access from the legitimate account labuser.

This confirmed that our security configurations including strong credentials, limited user access, and network segmentation helped prevent an actual breach, even in the face of repeated login attempts.

---

## 🧩 MITRE ATT&CK Mapping
### A couple of the MITRE ATT&CK Tactics & Techniques Observed:
| Technique ID   | Name                             |
|----------------|----------------------------------|
| `T1133`        | External Remote Services         |
| `T1110.001`    | Brute Force: Password Guessing   |

---
## 🔧 Recommended Mitigations

### 1. **Remove Internet Exposure (Containment)**
- **Why:** Reduces external attack surface immediately.
- **How:**
  - Go to **Azure Portal > VM > Networking**.
  - Remove any **public IP addresses**.
  - Remove inbound **NSG rules** that allow RDP (3389) or SSH (22) from internet.
  - If remote access is required, restrict access to specific IPs or use a **Jump Box**.



### 2. **Block Malicious IPs (Containment)**
- **Why:** Prevents repeated brute force attempts.
- **How:**
  - Add the IPs to **NSG Deny rules** or Azure Firewall block lists:
    - `125.123.214.238`
    - `80.64.18.199`
    - `200.105.196.189`
    - `181.115.190.30`



### 3. **Enable Network-Level Authentication + MFA (Recovery)**
- **Why:** Adds a second layer of protection.
- **How:**
  - Enforce **MFA** via Entra ID (Azure AD).
  - Require **NLA (Network Level Authentication)** for all RDP connections.



### 4. **Audit All Logins & Accounts (Recovery + Detection)**
- **Why:** Ensure no persistence was established via other accounts.
- **How:**
  - Run a full review of `DeviceLogonEvents` for other accounts/logins.
  - Check for new accounts or modified users via:
    ```kql
    IdentityInfo
    | where TimeGenerated > ago(30d)
    | where AccountType == "User"
    ```



### 5. **Deploy Defender for Endpoint (Detection & Recovery)**
- **Why:** Adds real-time protection and visibility into malicious behavior.
- **How:**
  - Onboard the VM to **Microsoft Defender for Endpoint**.
  - Enable **attack surface reduction rules** and **automated investigation**.



### 6. **Turn on Brute Force Detection Alerts in Microsoft Sentinel**
- **Why:** Early warning system for future attempts.
- **How:**
  - In Sentinel: **Analytics > + Create > Scheduled Query Rule**
  - Use a query like:
    ```kql
    DeviceLogonEvents
    | where LogonType has_any ("Network", "Interactive", "RemoteInteractive")
    | where ActionType == "LogonFailed"
    | summarize Attempts = count() by AccountName, RemoteIP, bin(TimeGenerated, 5m)
    | where Attempts > 10
    ```

---

## 📊 Summary Table

| Action                          | Purpose                | Status    |
|--------------------------------|------------------------|-----------|
| Remove public IP/ports         | Containment            | ✅ Required |
| Block bad IPs                  | Containment            | ✅ Recommended |
| Enable MFA + NLA               | Recovery/Hardening     | ✅ Required |
| Audit all user accounts        | Recovery               | ✅ Recommended |
| Enable Defender for Endpoint   | Detection/Recovery     | ✅ Strongly Recommended |
| Setup brute force alerts       | Detection              | ✅ Essential |

---

## ⚙️ Tools to Use

- Azure Portal (Networking, NSGs)
- Microsoft Sentinel (Analytics Rules)
- Microsoft Defender for Endpoint
- Entra ID (MFA enforcement)

## 🧑‍💼 Author

Created by Jamal Mays  
💻 Cybersecurity Engineer | ✨ Portfolio Builder

---

## ⭐ Like This Project?

Give it a ⭐ on GitHub and connect with me on [LinkedIn](https://linkedin.com/in/jamal-mays/)!
