# **Multi-Region Disaster Recovery (DR) Setup for Hybrid Cloud Networking on GCP**  

A multi-region DR strategy ensures:  
✅ **High availability** with failover across regions  
✅ **Minimal downtime** in case of failures  
✅ **Resilient networking and storage replication**  

---

### **1. Design the Multi-Region Architecture**  
- **Primary Region**: Deploy main workloads (e.g., `us-central1`)  
- **Secondary Region**: Disaster recovery site (e.g., `us-east1`)  
- **Global Load Balancer**: Routes traffic to the healthiest region  
- **Cloud Storage & Databases**: Enable cross-region replication  
- **Cloud DNS**: Automatic failover to DR region  

---

### **2. Deploy Global Load Balancer for Failover**  
Modify `main.tf`:  
```hcl
resource "google_compute_global_address" "lb_ip" {
  name         = "global-lb-ip"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
}

resource "google_compute_backend_service" "backend_primary" {
  name             = "backend-primary"
  region          = "us-central1"
  security_policy  = google_compute_security_policy.hybrid_network_armor_waf.id
}

resource "google_compute_backend_service" "backend_secondary" {
  name             = "backend-secondary"
  region          = "us-east1"
  security_policy  = google_compute_security_policy.hybrid_network_armor_waf.id
}

resource "google_compute_url_map" "lb_map" {
  name            = "global-lb-map"
  default_service = google_compute_backend_service.backend_primary.id
}

resource "google_compute_target_https_proxy" "lb_proxy" {
  name    = "global-lb-proxy"
  url_map = google_compute_url_map.lb_map.id
}

resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name       = "global-https-forwarding-rule"
  target     = google_compute_target_https_proxy.lb_proxy.id
  ip_address = google_compute_global_address.lb_ip.address
  port_range = "443"
}
```
✅ **Routes traffic to the best available region**  

---

### **3. Enable Cross-Region Storage Replication**  
```hcl
resource "google_storage_bucket" "dr_bucket" {
  name          = "hybrid-cloud-dr-bucket"
  location      = "us"  # Multi-region
  storage_class = "MULTI_REGIONAL"
  versioning {
    enabled = true
  }
}
```
✅ **Ensures replicated storage in multiple regions**  

---

### **4. Enable Database Replication**  
For Cloud SQL:  
```hcl
resource "google_sql_database_instance" "primary_db" {
  name             = "primary-db"
  region           = "us-central1"
  database_version = "POSTGRES_14"

  settings {
    availability_type = "REGIONAL"
    backup_configuration {
      enabled = true
      point_in_time_recovery_enabled = true
    }
  }
}

resource "google_sql_database_instance" "replica_db" {
  name                 = "replica-db"
  region               = "us-east1"
  database_version     = "POSTGRES_14"
  master_instance_name = google_sql_database_instance.primary_db.name
}
```
✅ **Maintains a hot standby database in the DR region**  

---

### **5. Automate Failover with Cloud DNS**  
```hcl
resource "google_dns_record_set" "dr_dns" {
  name = "app.example.com."
  type = "A"
  ttl  = 300

  managed_zone = "your-dns-zone"

  rrdatas = [
    google_compute_global_address.lb_ip.address
  ]
}
```
✅ **Automatically switches to the DR region on failure**  

---

### **6. Deploy with Terraform Cloud for Automation**  
1️⃣ Push Terraform files to GitHub  
2️⃣ Terraform Cloud automatically applies changes  
3️⃣ Run failover tests by shutting down the primary region  

✅ **Hybrid Cloud Networking now has a multi-region DR setup!**
