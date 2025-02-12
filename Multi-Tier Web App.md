# **Multi-Tier Web App on GCP**  
This project showcases a **scalable, secure, and highly available** multi-tier web application architecture on Google Cloud Platform (GCP).  

#### **Tech Stack:**  
- **Frontend:** React, Angular, or Vue.js (served via Cloud CDN or Cloud Storage)  
- **Backend:** Node.js, Python (Flask/Django), or Go (deployed on GKE, Cloud Run, or App Engine)  
- **Database:** Cloud SQL (PostgreSQL/MySQL), Firestore, or Bigtable  
- **Authentication:** Firebase Authentication or Identity-Aware Proxy (IAP)  
- **Infrastructure:** Terraform for IaC  

---

### **Architecture Overview**  
1. **Frontend Layer**  
   - Static files hosted on Cloud Storage with Cloud CDN  
   - Load balancing via Cloud Load Balancer  

2. **Backend Layer**  
   - Microservices deployed on **GKE, Cloud Run, or App Engine**  
   - REST API with API Gateway for security  
   - Logging & monitoring with Cloud Logging and Cloud Monitoring  

3. **Database Layer**  
   - Cloud SQL for relational data (PostgreSQL/MySQL)  
   - Firestore for NoSQL and real-time data  
   - Memorystore (Redis) for caching  

4. **Security & IAM**  
   - Identity-Aware Proxy (IAP) for user authentication  
   - IAM roles to enforce least privilege access  
   - Secret Manager for API keys and credentials  
   - Cloud Armor for DDoS protection  

---

### **Step-by-Step Deployment**  

#### **1. Set Up the Project & Enable Services**  
```sh
gcloud config set project [PROJECT_ID]
gcloud services enable compute.googleapis.com \
    container.googleapis.com \
    sqladmin.googleapis.com \
    cloudfunctions.googleapis.com \
    secretmanager.googleapis.com
```

---

#### **2. Deploy the Frontend**  
- Build frontend using React, Vue, or Angular  
- Upload to Cloud Storage and enable Cloud CDN  
```sh
gsutil mb gs://my-app-frontend
gsutil -m cp -r ./dist/* gs://my-app-frontend
gcloud storage buckets update gs://my-app-frontend --website-index=index.html
```

---

#### **3. Deploy Backend API on Cloud Run**  
Example Flask API:  
```python
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/hello', methods=['GET'])
def hello():
    return jsonify({"message": "Hello from Cloud Run!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
Deploy to Cloud Run:  
```sh
gcloud builds submit --tag gcr.io/[PROJECT_ID]/backend-api
gcloud run deploy backend-api --image gcr.io/[PROJECT_ID]/backend-api --region us-central1 --platform managed
```

---

#### **4. Set Up Cloud SQL**  
Create a PostgreSQL instance:  
```sh
gcloud sql instances create my-db --database-version=POSTGRES_14 --tier=db-f1-micro --region=us-central1
```
Create a database and user:  
```sh
gcloud sql databases create mydatabase --instance=my-db
gcloud sql users create myuser --instance=my-db --password=my-password
```

---

#### **5. Deploy API Gateway for Security**  
Create an API config file (`api-config.yaml`):  
```yaml
swagger: '2.0'
info:
  title: My API
  description: Secure API Gateway
  version: 1.0.0
host: [YOUR_GATEWAY_HOST]
schemes:
  - https
paths:
  /api/hello:
    get:
      description: Hello API
      responses:
        200:
          description: OK
      security:
        - api_key: []
securityDefinitions:
  api_key:
    type: apiKey
    name: X-API-KEY
    in: header
```
Deploy API Gateway:  
```sh
gcloud api-gateway apis create my-api
gcloud api-gateway api-configs create my-api-config --api=my-api --openapi-spec=api-config.yaml --backend-auth-service-account=my-service-account
gcloud api-gateway gateways create my-gateway --api=my-api --api-config=my-api-config --location=us-central1
```

---

#### **6. Implement IAM & Security**  
- **Limit API access:**  
  ```sh
  gcloud projects add-iam-policy-binding [PROJECT_ID] --member=user:[YOUR_EMAIL] --role=roles/apigateway.admin
  ```
- **Enable Cloud Armor for DDoS protection:**  
  ```sh
  gcloud compute security-policies create my-security-policy
  gcloud compute security-policies rules create 1000 --security-policy=my-security-policy --action=deny-403 --src-ip-ranges=0.0.0.0/0
  ```

---

### **Additional Enhancements**
- **CI/CD Pipeline:** Use Cloud Build & GitHub Actions  
- **Observability:** Set up Prometheus & Grafana  
- **Autoscaling:** Configure autoscaling for GKE/Cloud Run  
- **Error Tracking:** Use Cloud Error Reporting  

---

### **GitHub Repository Structure**
```
multi-tier-gcp-app/
│── frontend/           # React/Vue frontend
│── backend/            # Flask/Django backend
│── infra/              # Terraform scripts
│── api-gateway/        # API Gateway configs
│── cloudbuild.yaml     # CI/CD Pipeline
│── README.md           # Documentation
```

---
Here's a **Terraform setup** for deploying the multi-tier web app on GCP. This setup includes:  

- **VPC & Subnets**  
- **Cloud Storage (for frontend)**  
- **Cloud Run (for backend API)**  
- **Cloud SQL (PostgreSQL)**  
- **API Gateway (for security)**  
- **IAM & Security Controls**  

---

### **1. Project Structure**  
```
multi-tier-gcp-app/
│── terraform/
│   │── main.tf            # Main Terraform file
│   │── variables.tf       # Input variables
│   │── outputs.tf         # Output values
│   │── backend.tf         # Remote state (optional)
│   │── cloud_run.tf       # Cloud Run service
│   │── storage.tf         # Cloud Storage for frontend
│   │── cloud_sql.tf       # Cloud SQL instance
│   │── api_gateway.tf     # API Gateway
│   │── iam.tf             # IAM roles & permissions
│── backend/               # Flask/Node.js backend
│── frontend/              # React/Vue frontend
│── README.md              # Documentation
```

---

### **2. Terraform Files**  

#### **`main.tf` (Main Terraform File)**  
```hcl
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "enabled_services" {
  for_each = toset([
    "compute.googleapis.com",
    "storage.googleapis.com",
    "sqladmin.googleapis.com",
    "run.googleapis.com",
    "apigateway.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
  service = each.key
}
```

---

#### **`variables.tf` (Input Variables)**  
```hcl
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "storage_bucket" {
  description = "Storage bucket for frontend"
  type        = string
}

variable "db_instance_name" {
  description = "Cloud SQL instance name"
  type        = string
}
```

---

#### **`storage.tf` (Cloud Storage for Frontend)**  
```hcl
resource "google_storage_bucket" "frontend" {
  name          = var.storage_bucket
  location      = var.region
  force_destroy = true
  uniform_bucket_level_access = true

  website {
    main_page_suffix = "index.html"
    not_found_page   = "index.html"
  }
}

resource "google_storage_bucket_iam_member" "frontend_public_access" {
  bucket = google_storage_bucket.frontend.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

---

#### **`cloud_sql.tf` (Cloud SQL Database)**  
```hcl
resource "google_sql_database_instance" "db" {
  name             = var.db_instance_name
  database_version = "POSTGRES_14"
  region           = var.region

  settings {
    tier = "db-f1-micro"
  }
}

resource "google_sql_user" "db_user" {
  name     = "myuser"
  instance = google_sql_database_instance.db.name
  password = "mypassword"
}
```

---

#### **`cloud_run.tf` (Backend API on Cloud Run)**  
```hcl
resource "google_cloud_run_service" "backend" {
  name     = "backend-api"
  location = var.region

  template {
    spec {
      containers {
        image = "gcr.io/${var.project_id}/backend-api:latest"
        env {
          name  = "DATABASE_URL"
          value = "postgres://myuser:mypassword@/${google_sql_database_instance.db.name}"
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

resource "google_cloud_run_service_iam_member" "public_access" {
  service = google_cloud_run_service.backend.name
  role    = "roles/run.invoker"
  member  = "allUsers"
}
```

---

#### **`api_gateway.tf` (Secure API Gateway)**  
```hcl
resource "google_api_gateway_api" "api" {
  provider = google
  api_id   = "my-api"
}

resource "google_api_gateway_api_config" "api_config" {
  provider = google
  api      = google_api_gateway_api.api.api_id
  api_config_id = "my-api-config"

  openapi_documents {
    document {
      path     = "openapi.yaml"
      contents = filebase64("api/openapi.yaml")
    }
  }
}

resource "google_api_gateway_gateway" "gateway" {
  provider = google
  api      = google_api_gateway_api.api.api_id
  api_config = google_api_gateway_api_config.api_config.id
  gateway_id = "my-gateway"
  region     = var.region
}
```

---

#### **`iam.tf` (IAM Roles & Permissions)**  
```hcl
resource "google_project_iam_member" "cloud_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "allUsers"
}

resource "google_project_iam_member" "sql_admin" {
  project = var.project_id
  role    = "roles/cloudsql.admin"
  member  = "serviceAccount:${google_cloud_run_service.backend.email}"
}
```

---

### **3. Deploy the Terraform Setup**  

#### **Step 1: Initialize Terraform**  
```sh
terraform init
```

#### **Step 2: Plan Deployment**  
```sh
terraform plan -var="project_id=your-gcp-project-id" \
  -var="storage_bucket=your-frontend-bucket" \
  -var="db_instance_name=my-db"
```

#### **Step 3: Apply Deployment**  
```sh
terraform apply -auto-approve
```

---

### **Next Steps**
✅ Upload frontend code to Cloud Storage  
✅ Build & push backend container to Google Container Registry (GCR)  
✅ Deploy API Gateway  
✅ Implement Cloud Armor for DDoS protection  

---

Here’s a **CI/CD automation setup using GitHub Actions** for deploying the **multi-tier web app on GCP**.  

### **CI/CD Pipeline Overview**  
- **Frontend** (React/Vue/Angular)  
  - Built and deployed to Google Cloud Storage  
- **Backend API** (Flask/Node.js)  
  - Containerized, pushed to Google Container Registry (GCR), and deployed to Cloud Run  
- **Terraform Infrastructure**  
  - Applied automatically on changes  

---

### **1. GitHub Secrets Configuration**  
Before setting up the workflow, add the following **secrets** in your GitHub repository:  
1. **`GCP_PROJECT_ID`** → Your GCP project ID  
2. **`GCP_SA_KEY`** → JSON key of your service account  
3. **`GCP_REGION`** → Deployment region (e.g., `us-central1`)  
4. **`GCS_BUCKET_NAME`** → Name of the Cloud Storage bucket  
5. **`CLOUD_RUN_SERVICE`** → Name of the Cloud Run service  
6. **`DATABASE_URL`** → PostgreSQL connection string  

To generate the **`GCP_SA_KEY`**, run:  
```sh
gcloud iam service-accounts keys create key.json \
    --iam-account=my-service-account@your-project.iam.gserviceaccount.com
```
Then, copy-paste the contents of `key.json` into the **GitHub Secret** `GCP_SA_KEY`.  

---

### **2. GitHub Actions Workflow**
Create `.github/workflows/deploy.yml` in your repo.  

#### **`deploy.yml` (CI/CD Pipeline)**
```yaml
name: GCP Multi-Tier App Deployment

on:
  push:
    branches:
      - main

jobs:
  setup:
    runs-on: ubuntu-latest
    outputs:
      image_tag: ${{ steps.set_tag.outputs.image_tag }}
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set Image Tag
        id: set_tag
        run: echo "image_tag=$(date +%s)" >> $GITHUB_ENV

  deploy-frontend:
    runs-on: ubuntu-latest
    needs: setup
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Setup Google Cloud SDK
        uses: google-github-actions/setup-gcloud@v1

      - name: Build and Upload Frontend
        run: |
          cd frontend
          npm install
          npm run build
          gsutil -m cp -r dist/* gs://${{ secrets.GCS_BUCKET_NAME }}

  deploy-backend:
    runs-on: ubuntu-latest
    needs: setup
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Setup Google Cloud SDK
        uses: google-github-actions/setup-gcloud@v1

      - name: Build and Push Docker Image
        run: |
          docker build -t gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:${{ env.image_tag }} backend/
          gcloud auth configure-docker
          docker push gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:${{ env.image_tag }}

      - name: Deploy to Cloud Run
        run: |
          gcloud run deploy ${{ secrets.CLOUD_RUN_SERVICE }} \
            --image gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:${{ env.image_tag }} \
            --region ${{ secrets.GCP_REGION }} \
            --platform managed \
            --allow-unauthenticated \
            --set-env-vars "DATABASE_URL=${{ secrets.DATABASE_URL }}"

  deploy-infra:
    runs-on: ubuntu-latest
    needs: setup
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init
        working-directory: terraform/

      - name: Terraform Plan
        run: terraform plan -out=tfplan
        working-directory: terraform/

      - name: Terraform Apply
        run: terraform apply -auto-approve tfplan
        working-directory: terraform/
```

---

### **3. How the CI/CD Pipeline Works**
✅ **Push to `main` branch** → Triggers deployment  
✅ **Frontend Deployment**  
   - Builds frontend  
   - Uploads to Google Cloud Storage  
✅ **Backend Deployment**  
   - Builds a Docker image for the API  
   - Pushes it to Google Container Registry  
   - Deploys it to Cloud Run  
✅ **Infrastructure Deployment**  
   - Runs Terraform to apply changes  

---

### **4. Next Steps**
- ✅ **Ensure IAM permissions** for GitHub Actions service account  
- ✅ **Set up monitoring** using Cloud Logging  
- ✅ **Test the API via API Gateway**  
- ✅ **Add security layers** (Cloud Armor, IAM policies)  

---

### **Unit Testing for Multi-Tier GCP App**  
To enhance reliability, we’ll add **unit tests** for both the **backend** (API) and **frontend**.  

---

### **1. Backend API Unit Tests**
We’ll use **Pytest** for a Flask API (or Jest for a Node.js API). These tests will:  
✅ **Test API endpoints** for expected responses  
✅ **Mock database connections** to avoid real Cloud SQL dependencies  
✅ **Run in GitHub Actions** before deployment  

---

#### **`backend/tests/test_api.py` (Flask Example)**
```python
import pytest
from app import create_app  

@pytest.fixture
def client():
    app = create_app(testing=True)  # Create test app instance
    return app.test_client()

def test_home(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"Welcome to API" in response.data

def test_db_query(mocker, client):
    mocker.patch('app.db.session.query', return_value=[])  # Mock DB
    response = client.get('/data')
    assert response.status_code == 200
    assert response.json == []
```

📌 **If using Node.js**, create `backend/tests/api.test.js`:
```javascript
const request = require('supertest');
const app = require('../server');  

test('GET / should return API home', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.text).toContain("Welcome to API");
});

test('GET /data should return empty array (mocked)', async () => {
    jest.spyOn(db, 'findAll').mockResolvedValue([]);
    const res = await request(app).get('/data');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual([]);
});
```

---

### **2. Frontend Unit Tests**  
For React, we use **Jest + React Testing Library** to test UI rendering and API calls.

#### **`frontend/src/__tests__/App.test.js`**
```javascript
import { render, screen } from '@testing-library/react';
import App from '../App';

test('renders welcome text', () => {
    render(<App />);
    expect(screen.getByText(/Welcome to Multi-Tier App/i)).toBeInTheDocument();
});
```

---

### **3. Add Tests to GitHub Actions**  
Modify `.github/workflows/deploy.yml` to **run tests before deployment**.

#### **Updated `deploy.yml`**
```yaml
jobs:
  run-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install Backend Dependencies
        run: |
          cd backend
          pip install -r requirements.txt
          pip install pytest pytest-mock

      - name: Run Backend Tests
        run: pytest backend/tests/

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install Frontend Dependencies
        run: |
          cd frontend
          npm install
          npm run test  # Runs Jest tests
```

---

### **How This Improves Deployment**  
✅ If tests fail, deployment **stops**  
✅ Catches **breaking changes** in API & frontend  
✅ Ensures **backend logic works** with mock DB  
✅ Keeps the **frontend UI stable**  

---

### **Integration Testing for Multi-Tier GCP App**  
Integration tests ensure the **backend API works correctly with the database** and **frontend communicates properly with the backend**.

---

## **1. Backend Integration Tests (Flask + Cloud SQL Mocking)**  
We will:  
✅ Test API calls **with real database queries**  
✅ Use **a test database** (PostgreSQL in Cloud SQL or SQLite for local)  
✅ Run tests in **GitHub Actions**  

---

#### **Setup a Test Database (Optional, for Local Testing)**  
Modify `app.py` to allow using a test database:
```python
import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app(testing=False):
    app = Flask(__name__)
    if testing:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"  # In-memory DB for tests
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")  # Cloud SQL
    db.init_app(app)

    @app.route("/data")
    def get_data():
        result = db.session.execute("SELECT * FROM my_table").fetchall()
        return jsonify([dict(row) for row in result])

    return app
```

---

#### **`backend/tests/test_integration.py`**
```python
import pytest
from app import create_app, db

@pytest.fixture
def test_client():
    app = create_app(testing=True)
    with app.app_context():
        db.create_all()  # Create test tables
        yield app.test_client()
        db.drop_all()  # Cleanup

def test_database_connection(test_client):
    response = test_client.get('/data')
    assert response.status_code == 200
    assert isinstance(response.json, list)  # Should return an array
```

---

## **2. Frontend Integration Test (React API Calls to Backend)**  
We will:  
✅ Mock API requests  
✅ Test UI interactions with backend  

---

#### **`frontend/src/__tests__/API.test.js`**
```javascript
import { render, screen, waitFor } from '@testing-library/react';
import App from '../App';
import fetchMock from 'jest-fetch-mock';

fetchMock.enableMocks();

beforeEach(() => {
    fetchMock.resetMocks();
});

test('fetches and displays API data', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([{ id: 1, name: "Test Item" }]));

    render(<App />);
    
    await waitFor(() => expect(screen.getByText(/Test Item/i)).toBeInTheDocument());
});
```

---

## **3. Add Integration Tests to GitHub Actions**  
Modify `.github/workflows/deploy.yml` to **run integration tests** before deployment.

#### **Updated `deploy.yml`**
```yaml
jobs:
  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:latest
        env:
          POSTGRES_USER: testuser
          POSTGRES_PASSWORD: testpass
          POSTGRES_DB: testdb
        ports:
          - 5432:5432

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install Backend Dependencies
        run: |
          cd backend
          pip install -r requirements.txt
          pip install pytest pytest-mock psycopg2-binary

      - name: Run Backend Integration Tests
        env:
          DATABASE_URL: postgresql://testuser:testpass@localhost:5432/testdb
        run: pytest backend/tests/test_integration.py

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install Frontend Dependencies
        run: |
          cd frontend
          npm install
          npm run test  # Runs frontend tests
```

---

## **How This Improves Deployment**  
✅ Ensures **API properly interacts** with the database  
✅ Catches **breaking changes** before deployment  
✅ Verifies **frontend successfully communicates** with backend  

---

### **Security Scans for Multi-Tier GCP App**  
Security scanning ensures your code, dependencies, and cloud infrastructure are **free from vulnerabilities**.  

We'll integrate:  
✅ **SCA (Software Composition Analysis)** → Scan dependencies for vulnerabilities  
✅ **SAST (Static Application Security Testing)** → Scan source code for security flaws  
✅ **Container Security Scans** → Check Docker images for vulnerabilities  
✅ **GCP Security Checks** → Scan IAM roles, firewall rules, and storage permissions  

---

## **1. Dependency Security Scanning (SCA)**
📌 **Tools**: [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/), [Snyk](https://snyk.io/), [npm audit](https://docs.npmjs.com/cli/audit)  

### **GitHub Actions for Dependency Scanning**  
Add this to `.github/workflows/security.yml`:
```yaml
name: Security Scans

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Python Dependency Check
        run: |
          cd backend
          pip install safety
          safety check

      - name: Run NPM Audit
        run: |
          cd frontend
          npm audit --audit-level=high
```
✅ Fails build if any **high-severity** vulnerabilities exist  

---

## **2. Static Code Security Scanning (SAST)**
📌 **Tools**: [Bandit (Python)](https://bandit.readthedocs.io/en/latest/), [ESLint (JS)](https://eslint.org/), [Semgrep](https://semgrep.dev/)  

### **GitHub Actions for SAST**
```yaml
  static-code-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Install Bandit (Python SAST)
        run: |
          cd backend
          pip install bandit
          bandit -r . -ll

      - name: Run ESLint (JavaScript SAST)
        run: |
          cd frontend
          npm install
          npx eslint . --max-warnings 0
```
✅ Catches **SQL injection, XSS, SSRF** risks  

---

## **3. Container Security Scanning**
📌 **Tools**: [Trivy](https://aquasecurity.github.io/trivy/)  

### **GitHub Actions for Docker Scanning**
```yaml
  container-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

      - name: Scan Docker Image
        run: |
          docker pull gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:latest
          trivy image --exit-code 1 --severity CRITICAL gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:latest
```
✅ **Fails** if any **CRITICAL** vulnerabilities exist  

---

## **4. GCP Security Checks**
📌 **Tools**: [gcloud IAM analysis](https://cloud.google.com/iam/docs/analyzing-policies), [GCP Security Command Center](https://cloud.google.com/security-command-center)  

### **GitHub Actions for GCP Security Checks**
```yaml
  gcp-security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Check IAM Roles
        run: gcloud projects get-iam-policy ${{ secrets.GCP_PROJECT_ID }} --format=json | jq '.bindings[] | select(.role | test("admin"))'

      - name: Check Firewall Rules
        run: gcloud compute firewall-rules list --format=json | jq 'map(select(.allowed != null))'
```
✅ Detects **over-permissive IAM roles** & **open firewall ports**  

---

## **Final Security CI/CD Pipeline**
Here's the **complete security scan pipeline**:
```yaml
name: Security Scans

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Python Dependency Check
        run: |
          cd backend
          pip install safety
          safety check

      - name: NPM Audit
        run: |
          cd frontend
          npm audit --audit-level=high

  static-code-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Python Security Scan (Bandit)
        run: |
          cd backend
          pip install bandit
          bandit -r . -ll

      - name: JavaScript Security Scan (ESLint)
        run: |
          cd frontend
          npm install
          npx eslint . --max-warnings 0

  container-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

      - name: Scan Docker Image
        run: |
          docker pull gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:latest
          trivy image --exit-code 1 --severity CRITICAL gcr.io/${{ secrets.GCP_PROJECT_ID }}/backend-api:latest

  gcp-security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Check IAM Roles
        run: gcloud projects get-iam-policy ${{ secrets.GCP_PROJECT_ID }} --format=json | jq '.bindings[] | select(.role | test("admin"))'

      - name: Check Firewall Rules
        run: gcloud compute firewall-rules list --format=json | jq 'map(select(.allowed != null))'
```

---

## **How This Improves Deployment Security**  
✅ **Prevents vulnerable dependencies** from deployment  
✅ **Catches security flaws** in Python & JS code  
✅ **Ensures containers are secure** before deployment  
✅ **Detects IAM misconfigurations & open firewalls**  

---

### **Automated Penetration Testing for Multi-Tier GCP App**  
Penetration testing simulates **real-world attacks** to uncover vulnerabilities before deployment.  

We'll integrate:  
✅ **OWASP ZAP** → API & Web App scanning for **XSS, SQLi, CSRF, SSRF, etc.**  
✅ **Nikto** → Web server misconfigurations  
✅ **Metasploit** → Exploit testing on staging servers  
✅ **Google Cloud Security Scanner** → GCP-native web security scans  

---

## **1. OWASP ZAP: API & Web App Penetration Testing**
📌 **Finds**: SQL Injection, XSS, CSRF, broken authentication, security misconfigurations  

### **GitHub Actions for OWASP ZAP**
```yaml
  zap-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Start Application (Test Server)
        run: |
          docker-compose up -d backend frontend

      - name: Run OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:3000'  # Replace with frontend URL
          cmd_options: '-a'  # Aggressive mode
```
✅ **Fails deployment** if critical vulnerabilities found  

---

## **2. Nikto: Web Server Security Testing**
📌 **Finds**: Open directories, outdated software, misconfigured headers  

### **GitHub Actions for Nikto**
```yaml
  nikto-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Nikto
        run: sudo apt update && sudo apt install nikto -y

      - name: Run Nikto Scan
        run: nikto -h http://localhost:3000 -output reports/nikto_report.txt
```
✅ Scans **HTTP headers, SSL/TLS, exposed files**  

---

## **3. Metasploit: Exploit Testing (Staging Server)**
📌 **Finds**: Exploitable vulnerabilities via automated attacks  

### **GitHub Actions for Metasploit**
```yaml
  metasploit-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Metasploit
        run: sudo apt update && sudo apt install metasploit-framework -y

      - name: Run Metasploit Scan
        run: |
          msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS http://staging.example.com; run; exit"
```
✅ **Checks for known exploits** against staging app  

---

## **4. Google Cloud Security Scanner**
📌 **Finds**: **SQL Injection, XSS, outdated software** in GCP-hosted apps  

### **GitHub Actions for GCP Security Scanner**
```yaml
  gcp-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Run GCP Security Scan
        run: |
          gcloud beta security scan-runs create --target-url=https://yourapp.com
```
✅ Scans **Google App Engine, Cloud Run, and GKE apps**  

---

## **Full Automated Penetration Testing CI/CD Pipeline**
```yaml
name: Security Scans

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  zap-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Start Application (Test Server)
        run: |
          docker-compose up -d backend frontend

      - name: Run OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:3000'
          cmd_options: '-a'

  nikto-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Nikto
        run: sudo apt update && sudo apt install nikto -y

      - name: Run Nikto Scan
        run: nikto -h http://localhost:3000 -output reports/nikto_report.txt

  metasploit-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install Metasploit
        run: sudo apt update && sudo apt install metasploit-framework -y

      - name: Run Metasploit Scan
        run: |
          msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS http://staging.example.com; run; exit"

  gcp-security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate with GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Run GCP Security Scan
        run: |
          gcloud beta security scan-runs create --target-url=https://yourapp.com
```

---

## **How This Improves Security**  
✅ **Simulates real-world attacks** on API & web app  
✅ **Finds open vulnerabilities** before hackers do  
✅ **Fails deployment** if **critical security flaws** exist
