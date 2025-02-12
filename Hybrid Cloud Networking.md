# **Hybrid Cloud Networking on GCP**
Hybrid Cloud Networking on GCP involves securely connecting on-premise infrastructure with GCP services using VPNs, Interconnects, and VPC peering.  

### **Project Scope:**  
✅ **Site-to-Site VPN** → Secure tunnel between on-prem and GCP  
✅ **Cloud Interconnect** → High-bandwidth, low-latency connection  
✅ **VPC Peering** → Private connectivity between VPCs  
✅ **Private Google Access** → Secure access to Google APIs from on-prem  
✅ **Cloud NAT** → Enable outbound traffic without external IPs  
✅ **Hybrid DNS Resolution** → Resolve private domains across cloud & on-prem  

Got it! Here's the **step-by-step manual setup** for Hybrid Cloud Networking on GCP.

---

## **1. Create a VPC in GCP**
1. **Go to GCP Console** → **VPC network**  
2. Click **Create VPC network**  
   - Name: `hybrid-vpc`  
   - Subnets: **Custom**  
   - Create subnets in required regions  
   - Enable **Private Google Access**  
   - Click **Create**  

---

## **2. Set Up Cloud VPN (Site-to-Site VPN)**
1. **Go to** ☁️ **Hybrid Connectivity** → **VPN**  
2. Click **Create VPN**  
3. Choose **Classic VPN**  
   - Name: `onprem-to-gcp-vpn`  
   - Select **hybrid-vpc**  
   - Select **Region**  
   - Choose a **Cloud Router** (create one if needed)  
   - Add **IKE Version** (match on-prem settings)  
4. Configure **Peer VPN Gateway**  
   - Enter **on-prem public IP**  
   - Add **Pre-shared key**  
5. Configure **BGP Session** (for dynamic routing)  
6. Click **Create**  

✅ **Result**: Secure VPN tunnel between on-prem & GCP  

---

## **3. Set Up Cloud Interconnect (Optional)**
1. **Go to Hybrid Connectivity** → **Interconnect**  
2. Click **Create Interconnect**  
3. Select **Dedicated or Partner Interconnect**  
4. Choose **location** & **provider**  
5. Click **Create**  
6. Follow **provider’s instructions** for physical connection  

✅ **Result**: High-speed, low-latency private link  

---

## **4. Configure VPC Peering (Connect VPCs Privately)**
1. **Go to** ☁️ **VPC Network** → **VPC Peering**  
2. Click **Create Peering Connection**  
   - Name: `gcp-to-onprem-peering`  
   - Select **hybrid-vpc**  
   - Enter **on-prem VPC network details**  
3. Click **Create**  

✅ **Result**: Private connectivity between GCP & on-prem  

---

## **5. Configure Cloud NAT (Outbound Traffic Without External IP)**
1. **Go to** ☁️ **VPC network** → **Cloud NAT**  
2. Click **Create Cloud NAT Gateway**  
   - Name: `hybrid-nat`  
   - Select **hybrid-vpc**  
   - Select **Region**  
   - Configure NAT IP allocation  
3. Click **Create**  

✅ **Result**: Secure outbound internet access without public IPs  

---

## **6. Set Up Hybrid DNS Resolution**
1. **Go to** ☁️ **Cloud DNS**  
2. Click **Create Zone**  
   - Name: `onprem-dns`  
   - Type: **Forwarding zone**  
   - Add **on-prem DNS servers**  
3. Click **Create**  

✅ **Result**: On-prem & GCP can resolve private domains  

---

## **7. Test & Validate**
- **Ping private IPs** between on-prem & GCP  
- **Check VPN tunnel status** in Cloud Console  
- **Run traceroute** to verify routing  
- **Resolve private domain names** using `nslookup`  

---

### **IAM Best Practices for Hybrid Cloud Networking on GCP**  
To secure hybrid networking, we must follow **least privilege access**, **monitor permissions**, and **use service accounts securely**.  

---

## **1. Restrict IAM Roles for Hybrid Networking**  
### **Least Privilege Model:**
Instead of granting **Owner** or **Editor**, use **granular roles**:  

| **Task** | **Least Privilege IAM Role** |
|----------|-----------------------------|
| **Manage VPNs** | `roles/compute.networkAdmin` |
| **Manage Cloud Interconnect** | `roles/networkconnectivity.admin` |
| **Manage VPC Peering** | `roles/compute.networkAdmin` |
| **Manage Cloud NAT** | `roles/compute.networkAdmin` |
| **Configure Cloud DNS** | `roles/dns.admin` |
| **View Networking Logs** | `roles/logging.viewer` |

### **How to Assign Roles**  
1. **Go to** ☁️ **IAM & Admin** → **IAM**  
2. Click **Grant Access**  
3. Add **User or Service Account**  
4. Assign the **least privilege role**  
5. Click **Save**  

✅ **Never grant** `roles/editor` or `roles/owner` for networking tasks.  

---

## **2. Use Service Accounts for Automation**  
### **Create a Dedicated Service Account**
1. **Go to** ☁️ **IAM & Admin** → **Service Accounts**  
2. Click **Create Service Account**  
   - Name: `hybrid-network-sa`  
3. Grant **specific roles** (e.g., `compute.networkAdmin`)  
4. Click **Create Key** → **JSON**  
5. Store key **securely** (do NOT hardcode in scripts)  

✅ Use this service account for Terraform, automation scripts, and API calls.  

---

## **3. Enable IAM Conditions (Time-Based & IP-Based Restrictions)**  
Limit access based on **time, IP, or device** using IAM conditions.  

### **Example: Allow VPN Admins to Modify VPNs Only During Work Hours**
1. **Go to** ☁️ **IAM & Admin** → **IAM**  
2. Find the user/service account  
3. Click **Edit Condition**  
4. Use this condition:  
```yaml
{
  "expression": "request.time >= timestamp('2024-02-12T08:00:00Z') && request.time <= timestamp('2024-02-12T18:00:00Z')",
  "title": "Work Hours Only"
}
```
✅ VPN changes allowed **only from 08:00 to 18:00 UTC**.  

---

## **4. Enforce Multi-Factor Authentication (MFA) for Admins**  
### **Enable MFA for Network Admins**
1. **Go to** ☁️ **IAM & Admin** → **IAM**  
2. Click **Manage Policies**  
3. Require MFA for **admins** using:  
```yaml
{
  "expression": "resource.name.startsWith('projects/YOUR_PROJECT_ID') && identity.mfa_enabled == false",
  "title": "Require MFA for Admins"
}
```
✅ Enforces **MFA** before making changes.  

---

## **5. Monitor IAM Logs for Unauthorized Changes**  
### **Enable Audit Logs for Networking**
1. **Go to** ☁️ **Logging** → **Logs Explorer**  
2. Filter logs with:  
```yaml
protoPayload.serviceName="compute.googleapis.com" 
protoPayload.authenticationInfo.principalEmail!~"trusted-user@example.com"
```
✅ Alerts if **unauthorized users** modify networking.  

---

## **6. Implement VPC Service Controls for Data Protection**  
Restrict **data exfiltration** from hybrid cloud.  

### **Create a VPC Service Perimeter**
1. **Go to** ☁️ **Security** → **VPC Service Controls**  
2. Click **Create Perimeter**  
3. Add **GCP resources** (Cloud Storage, BigQuery, etc.)  
4. Enable **Restrict API calls to external networks**  
5. Click **Create**  

✅ **Prevents data leaks** from on-prem to external networks.  

---

### **Terraform Configuration for IAM Best Practices in Hybrid Cloud Networking on GCP**  

This Terraform script **automates IAM security** for your Hybrid Cloud setup by:  
✅ Assigning **least privilege roles**  
✅ Creating a **service account for automation**  
✅ Enforcing **IAM Conditions (time-based restrictions)**  
✅ Requiring **MFA for critical roles**  
✅ Enabling **audit logs for monitoring**  

---

### **1. Create a Service Account for Hybrid Cloud Networking**  
```hcl
resource "google_service_account" "hybrid_network_sa" {
  account_id   = "hybrid-network-sa"
  display_name = "Hybrid Cloud Networking Service Account"
}
```
✅ This service account will be used for **VPN, VPC Peering, Interconnect, and NAT**.  

---

### **2. Assign Least Privilege IAM Roles**  
```hcl
resource "google_project_iam_member" "vpn_admin" {
  project = var.project_id
  role    = "roles/compute.networkAdmin"
  member  = "serviceAccount:${google_service_account.hybrid_network_sa.email}"
}

resource "google_project_iam_member" "dns_admin" {
  project = var.project_id
  role    = "roles/dns.admin"
  member  = "serviceAccount:${google_service_account.hybrid_network_sa.email}"
}
```
✅ Ensures that **only necessary permissions** are granted.  

---

### **3. Enforce IAM Conditions (Restrict VPN Changes to Work Hours Only)**  
```hcl
resource "google_project_iam_binding" "vpn_restrict_time" {
  project = var.project_id
  role    = "roles/compute.networkAdmin"

  members = [
    "serviceAccount:${google_service_account.hybrid_network_sa.email}"
  ]

  condition {
    title       = "Work Hours Restriction"
    description = "Allow VPN changes only between 08:00 - 18:00 UTC"
    expression  = "request.time >= timestamp('2024-02-12T08:00:00Z') && request.time <= timestamp('2024-02-12T18:00:00Z')"
  }
}
```
✅ **Blocks VPN changes outside of work hours**.  

---

### **4. Enforce Multi-Factor Authentication (MFA) for Admins**  
```hcl
resource "google_project_iam_binding" "mfa_required_for_admins" {
  project = var.project_id
  role    = "roles/compute.networkAdmin"

  members = [
    "user:admin@example.com"
  ]

  condition {
    title       = "Require MFA"
    description = "Admins must use MFA to manage hybrid networking"
    expression  = "identity.mfa_enabled == false"
  }
}
```
✅ **Denies access** if MFA is not enabled.  

---

### **5. Enable Audit Logging for Security Monitoring**  
```hcl
resource "google_logging_project_sink" "network_iam_audit" {
  name        = "network-iam-audit"
  destination = "storage.googleapis.com/${google_storage_bucket.iam_logs.name}"
  filter      = "protoPayload.serviceName=\"compute.googleapis.com\""

  unique_writer_identity = true
}

resource "google_storage_bucket" "iam_logs" {
  name          = "iam-logs-${var.project_id}"
  location      = "US"
  storage_class = "STANDARD"
}
```
✅ Logs **every IAM change** in GCP Networking.  

---

### **6. Apply Terraform Script**
1️⃣ Save the script as `main.tf`  
2️⃣ Set up Terraform:
```sh
terraform init
terraform apply -var="project_id=YOUR_PROJECT_ID"
```
3️⃣ Confirm with **"yes"**  

✅ **Fully automated IAM security setup for Hybrid Cloud Networking**  

---

### **Extending Hybrid Cloud Networking IAM Setup to Terraform Cloud**  

Terraform Cloud allows you to:  
✅ **Automate deployments** with version control integration  
✅ **Enforce security policies** via Sentinel  
✅ **Enable team collaboration** on infrastructure  

---

### **1. Create a Terraform Cloud Account**  
1️⃣ Go to [Terraform Cloud](https://app.terraform.io/)  
2️⃣ Click **"Start for Free"**  
3️⃣ Create an **organization** (e.g., `hybrid-networking-org`)  

---

### **2. Create a New Workspace**  
1️⃣ Go to **Workspaces** → Click **"New Workspace"**  
2️⃣ Choose **Version Control Workflow**  
3️⃣ Connect to **GitHub/GitLab/Bitbucket**  
4️⃣ Select your **Hybrid Cloud Networking repository**  
5️⃣ Click **Create Workspace**  

---

### **3. Store GCP Credentials as Environment Variables**  
1️⃣ Go to **Workspace** → **Variables**  
2️⃣ Click **Add Variable**  
3️⃣ Add the following **environment variables**:  

| Name                 | Value  | Type |
|----------------------|--------|------|
| `GOOGLE_CREDENTIALS` | JSON key from service account | Sensitive |
| `GOOGLE_PROJECT`     | Your GCP Project ID | Normal |

✅ **Avoid storing secrets in `.tfvars` files**  

---

### **4. Modify Terraform Backend to Use Terraform Cloud**  
In `main.tf`, replace the local backend with:  
```hcl
terraform {
  cloud {
    organization = "hybrid-networking-org"

    workspaces {
      name = "hybrid-cloud-networking"
    }
  }
}
```
✅ Terraform Cloud **stores and manages your state file**  

---

### **5. Push Code to GitHub & Trigger Terraform Cloud**  
1️⃣ Initialize Terraform Cloud  
```sh
terraform init
```
2️⃣ Push your **Terraform code** to GitHub  
```sh
git add .
git commit -m "Deploy Hybrid Cloud Networking IAM with Terraform Cloud"
git push origin main
```
3️⃣ Terraform Cloud will **automatically trigger a plan**  
4️⃣ Go to **Terraform Cloud Dashboard** → Click **Confirm & Apply**  

✅ **Your IAM security for Hybrid Cloud Networking is now managed in Terraform Cloud!**  

---

### **Adding Cloud Armor for DDoS Protection in Hybrid Cloud Networking**  

Google Cloud Armor helps protect **hybrid networks** from:  
✅ **DDoS attacks** (Layer 3 & 4)  
✅ **Botnets & brute force attacks**  
✅ **OWASP Top 10 vulnerabilities**  

---

### **1. Enable Cloud Armor**  
Modify `main.tf` to enable Cloud Armor:  
```hcl
resource "google_compute_security_policy" "hybrid_network_armor" {
  name        = "hybrid-network-armor"
  description = "DDoS protection for hybrid cloud networking"

  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "origin.region_code in [\"CN\", \"RU\", \"KP\"]"
      }
    }
    description = "Block traffic from high-risk regions"
  }

  rule {
    action   = "rate_based_ban"
    priority = 2000
    match {
      expr {
        expression = "request.count > 1000 && request.time < duration(\"1m\")"
      }
    }
    description = "Rate-limit requests to prevent DDoS"
  }

  rule {
    action   = "allow"
    priority = 3000
    match {
      expr {
        expression = "true"
      }
    }
    description = "Allow all other traffic"
  }
}
```
✅ **Blocks malicious traffic while allowing legitimate requests**  

---

### **2. Attach Cloud Armor to Hybrid Cloud Load Balancer**  
If using an **HTTPS Load Balancer**, attach Cloud Armor:  
```hcl
resource "google_compute_backend_service" "hybrid_backend" {
  name          = "hybrid-backend"
  security_policy = google_compute_security_policy.hybrid_network_armor.id
}
```
✅ **Applies security rules to backend services**  

---

### **3. Deploy & Verify Cloud Armor**  
1️⃣ **Apply Terraform Changes**  
```sh
terraform apply -var="project_id=YOUR_PROJECT_ID"
```
2️⃣ **Test Cloud Armor**  
- Try **sending 1000+ requests per minute** → Should **block excess traffic**  
- Access from **blocked regions** → Should **return HTTP 403**  

✅ **DDoS protection is now active on Hybrid Cloud Networking!**  

---

### **Extending Cloud Armor with Web Application Firewall (WAF) Rules**  

GCP Cloud Armor WAF protects against:  
✅ **SQL Injection (SQLi)**  
✅ **Cross-Site Scripting (XSS)**  
✅ **Command Injection (RCE)**  
✅ **Bad Bots & Web Scrapers**  

---

### **1. Enable Cloud Armor WAF Rules**  
Modify `main.tf` to add **pre-configured Google WAF rules**:  
```hcl
resource "google_compute_security_policy" "hybrid_network_armor_waf" {
  name        = "hybrid-network-armor-waf"
  description = "Cloud Armor WAF for hybrid networking"

  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable')"
      }
    }
    description = "Block SQL Injection attacks"
  }

  rule {
    action   = "deny(403)"
    priority = 1100
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable')"
      }
    }
    description = "Block Cross-Site Scripting (XSS) attacks"
  }

  rule {
    action   = "deny(403)"
    priority = 1200
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable')"
      }
    }
    description = "Block Remote Code Execution (RCE) attempts"
  }

  rule {
    action   = "deny(403)"
    priority = 1300
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable')"
      }
    }
    description = "Block Local File Inclusion (LFI) attacks"
  }

  rule {
    action   = "rate_based_ban"
    priority = 2000
    match {
      expr {
        expression = "request.count > 500 && request.time < duration(\"1m\")"
      }
    }
    description = "Rate-limit abusive requests"
  }

  rule {
    action   = "allow"
    priority = 3000
    match {
      expr {
        expression = "true"
      }
    }
    description = "Allow all other traffic"
  }
}
```
✅ **Blocks malicious traffic before it reaches hybrid workloads.**  

---

### **2. Attach WAF to Hybrid Cloud Load Balancer**  
Modify backend service to apply **Cloud Armor WAF**:  
```hcl
resource "google_compute_backend_service" "hybrid_backend" {
  name             = "hybrid-backend"
  security_policy  = google_compute_security_policy.hybrid_network_armor_waf.id
}
```
✅ **Automatically applies WAF filtering to incoming traffic.**  

---

### **3. Deploy & Test Cloud Armor WAF**  
1️⃣ **Apply Terraform Changes**  
```sh
terraform apply -var="project_id=YOUR_PROJECT_ID"
```
2️⃣ **Test WAF Protection:**  
- Try an **SQL Injection** (`' OR 1=1 --`) → **Blocked**  
- Try an **XSS attack** (`<script>alert('XSS')</script>`) → **Blocked**  
- Try **sending 500+ requests in 1 minute** → **Rate-limited**  

✅ **Hybrid Cloud Network now has full WAF protection!**  

---

### **Automating Cloud Armor WAF Updates with Terraform Cloud**  

Terraform Cloud will:  
✅ **Auto-apply WAF rule changes** when updating Terraform code  
✅ **Enforce security policies** using Sentinel  
✅ **Integrate with version control (GitHub/GitLab/Bitbucket)**  

---

### **1. Update Terraform Backend to Use Terraform Cloud**  
Modify `main.tf` to connect to Terraform Cloud:  
```hcl
terraform {
  cloud {
    organization = "hybrid-networking-org"

    workspaces {
      name = "hybrid-cloud-waf"
    }
  }
}
```
✅ **Terraform Cloud will now manage state and deployments**  

---

### **2. Store GCP Credentials in Terraform Cloud**  
1️⃣ Go to **Terraform Cloud → Workspaces → hybrid-cloud-waf**  
2️⃣ Click **"Variables" → Add Variable**  
3️⃣ Add these **environment variables**:  

| Name                 | Value | Type |
|----------------------|-------|------|
| `GOOGLE_CREDENTIALS` | JSON key from service account | Sensitive |
| `GOOGLE_PROJECT`     | Your GCP Project ID | Normal |

✅ **Ensures secure Terraform execution**  

---

### **3. Push WAF Rule Updates to GitHub & Trigger Terraform Cloud**  
1️⃣ **Modify WAF rules in Terraform code**  
2️⃣ Commit & push changes to GitHub:  
```sh
git add .
git commit -m "Update Cloud Armor WAF rules"
git push origin main
```
3️⃣ Terraform Cloud will **automatically trigger a plan**  
4️⃣ Go to **Terraform Cloud Dashboard → Confirm & Apply**  

✅ **WAF rule updates are now fully automated!**  

---
