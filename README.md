# OmniScan AI — Intent-Aware Security Intelligence & Vulnerability Analyzer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![React](https://img.shields.io/badge/Frontend-React_18-61DAFB?logo=react&logoColor=black)
![Node.js](https://img.shields.io/badge/Backend-Node.js_Express-339933?logo=node.js&logoColor=white)
![AI Engine](https://img.shields.io/badge/AI_Engine-Google_Gemini_%2F_Ollama_Phi--3-FF6F00?logo=google&logoColor=white)
![Vector DB](https://img.shields.io/badge/Vector_DB-FAISS_%2B_MiniLM--L6--v2-00599C)
![Security](https://img.shields.io/badge/Security-OWASP_Top--10_CWE_Hardened-red)

**OmniScan AI** is an enterprise-grade, full-stack automated security scanning and attack intelligence platform. It merges deterministic static code analysis, live blackbox surface crawlers, API probes, and modern Generative AI (Google Gemini & Local Phi-3 RAG) to simulate real-world attacker techniques, construct exploit chains, estimate CVSS risk scores, and generate remediation code.

---

## 📑 Table of Contents

- [Key Capabilities](#-key-capabilities)
- [System Architecture](#-system-architecture)
- [Scan Modalities](#-scan-modalities)
- [AI Engine (Dual-Mode Operation)](#-ai-engine-dual-mode-operation)
- [Security Hardening & Safeguards](#-security-hardening--safeguards)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Installation](#local-installation)
  - [Environment Variables](#environment-variables)
- [Interactive CLI Demo](#-interactive-cli-demo)
- [Deployment Guide](#-deployment-guide)
  - [Option A: 100% Cloud (Vercel + Render / Cloud VPS)](#option-a-100-cloud-vercel--render--cloud-vps)
  - [Option B: Hybrid / Local Deployment](#option-b-hybrid--local-deployment)
- [API Reference](#-api-reference)
- [License](#-license)

---

## ⚡ Key Capabilities

- **🔍 Multi-Surface Security Analysis**:
  - **Source Code SAST**: Analyzes code across 6+ languages (JS, Python, PHP, Java, Ruby, Go) across 17+ CWE categories.
  - **Live Web Crawling & DAST**: Crawls web endpoints, inspects response headers, checks for plaintext secrets, and probes forms for reflected XSS and SQL injection patterns.
  - **API Endpoint Probing**: Tests authentication boundaries, wildcard CORS configurations, rate-limiting headers, sensitive data exposure, and error stack trace leakage.
- **🧠 Intent-Aware AI Intelligence**:
  - **Attacker Persona Simulation**: Simulates attacks from *Script Kiddie* (noisy, public tools), *Insider Threat* (privilege abuse, stealth), and *APT / Nation-State* (custom chaining, defense evasion).
  - **Vulnerability Chaining**: Detects how low/medium severity vulnerabilities combine to form critical kill chains (e.g., SSRF + Cloud Misconfiguration = Credential Theft).
  - **Adaptive Explanations**: Tailors reporting for *Beginners* (plain language), *Developers* (code patches & unit tests), or *Security Experts* (CVSS metrics & attack vectors).
- **🛡️ Remediation & Strategic Defense**:
  - Auto-generates syntactically correct code patches.
  - Categorizes defenses into **Immediate Actions**, **Security Controls**, and **Monitoring & Alerts**.

---

## 🏗️ System Architecture

```
                       ┌─────────────────────────────────────────┐
                       │           React 18 Dashboard            │
                       │   (Risk Gauge, Tabs, Defense Panel)     │
                       └────────────────────┬────────────────────┘
                                            │ HTTP / JSON
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │          Node.js Express Server         │
                       │    (Helmet, Rate Limiter, SSRF Guard)   │
                       └──────┬───────────────────────────┬──────┘
                              │                           │
            ┌─────────────────┴───────────────┐           │
            ▼                                 ▼           ▼
┌───────────────────────┐         ┌──────────────────────────────┐
│  Deterministic Engine │         │       Dual-Mode AI Engine    │
│  - SAST Scanner       │         ├──────────────────────────────┤
│  - Active Crawler     │         │ Mode 1: Google Gemini Flash  │
│  - API Prober         │         │         (Cloud Zero-Config)  │
└───────────────────────┘         │             - OR -           │
                                  │ Mode 2: Local Python RAG     │
                                  │         (FAISS + Ollama Phi3)│
                                  └──────────────────────────────┘
```

---

## 🎯 Scan Modalities

### 1. Web URL Scan (`/api/scan-url`)
- **Header Analysis**: Validates `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, and detects server version disclosure (`Server`, `X-Powered-By`).
- **Crawler & Secret Scanner**: Extracts HTML forms, evaluates directory listing vulnerabilities, and scans source code against high-entropy regex patterns (AWS tokens, Google API keys, JWTs, etc.).
- **Active Probe Payloads**: Submits non-destructive probes for reflected XSS (with multi-encoding detection) and SQL error leakage.

### 2. Static Source Code Scan (`/api/scan-code`)
- **17+ Rule CWE Ruleset**:
  - `CWE-89`: SQL Injection via string interpolation & raw query execution.
  - `CWE-78`: OS Command Injection (`exec`, `system`, `subprocess.run`).
  - `CWE-94/95`: Dangerous evaluation (`eval`).
  - `CWE-798`: Hardcoded credentials, private keys, and API tokens.
  - `CWE-327`: Deprecated cryptographic algorithms (MD5, SHA-1).
  - `CWE-79`: DOM-based XSS (`innerHTML`, `document.write`).
  - `CWE-918`: Server-Side Request Forgery.
  - `CWE-22`: Directory Traversal.
  - `CWE-502`: Insecure Deserialization (`pickle.loads`, `yaml.load`).
- **Manifest Audit**: Flags vulnerable legacy dependencies in `package.json` and `requirements.txt`.

### 3. API Endpoint Analyzer (`/api/analyze-api`)
- Probes live REST endpoints with configurable HTTP verbs.
- Validates missing authorization mechanisms, open CORS policies (`*`), and missing rate-limiting headers (`RateLimit-Limit`, `Retry-After`).
- Scans response bodies for high-risk data leakage (passwords, credit cards, SSNs, API tokens).

---

## 🤖 AI Engine (Dual-Mode Operation)

The platform supports two swappable AI backends managed by `aiEngine.js`:

| Feature | ☁️ Mode 1: Google Gemini (Cloud) | 💻 Mode 2: Local RAG (Offline) |
|---|---|---|
| **Best For** | Production, Vercel/Render, fast demo | Zero cost, strict air-gapped environments |
| **Model** | `gemini-3.8-flash` (auto-fallback to flash-lite/pro) | `phi-3` (via Ollama) |
| **Hardware Reqs** | Zero (runs on Google Cloud) | 4GB–8GB RAM, CPU/GPU |
| **Setup** | Add `GEMINI_API_KEY` to `.env` | Run `ollama serve` + `rag_service.py` |
| **Embeddings** | Cloud generation | Local `all-MiniLM-L6-v2` + FAISS L2 |

---

## 🔒 Security Hardening & Safeguards

This application has undergone strict defensive hardening:

- **🛡️ Comprehensive SSRF Protection (`middleware/validateUrl.js`)**:
  - Prohibits requests to loopback (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and Cloud metadata endpoints (`169.254.169.254`).
  - Pre-resolves DNS records to prevent DNS Rebinding attacks.
  - Restricts schemes strictly to `http:` and `https:`.
- **🚫 Prompt Injection Mitigation**:
  - User-provided parameters (`goal`, `persona`, `explainMode`) are strictly sanitized, stripped of control characters, and bound to allowlists.
- **🧱 Request & Resource Limits**:
  - Body payload capped at `100KB` (mitigates memory exhaustion DoS).
  - Rate limiting via `express-rate-limit` (30 requests / 15 minutes per IP).
  - Static code input capped at `50,000` characters.
  - Bounded vector search `k` parameters (`1 <= k <= 20`).
- **🔐 Safe Logging & Error Handling**:
  - Filenames and logged data are stripped of ANSI sequences and directory traversal characters.
  - Stack traces are completely removed from production client responses.

---

## 📁 Project Structure

```
AI_security_analyzer/
├── backend/
│   ├── middleware/
│   │   ├── errorHandler.js       # Production-safe error middleware
│   │   └── validateUrl.js        # SSRF filter, IP/DNS validator & header sanitizer
│   ├── routes/
│   │   ├── analyzeApi.js         # API probing route
│   │   ├── scanCode.js           # Static code analysis route
│   │   └── scanUrl.js            # URL & active scanner route
│   ├── services/
│   │   ├── aiEngine.js           # Dual-mode AI orchestrator (Gemini & Ollama RAG)
│   │   ├── codeScanner.js        # Deterministic 17+ CWE rules engine
│   │   └── urlScanner.js         # Web crawler, secret regex & active probe engine
│   ├── rag_service/
│   │   ├── knowledge_base/       # OWASP Top-10 curated knowledge base
│   │   ├── rag_service.py        # Python Flask RAG service (MiniLM + FAISS + Ollama)
│   │   └── requirements.txt      # Python dependencies
│   ├── demo.js                   # Interactive CLI terminal scanner
│   ├── server.js                 # Express server with Helmet, CORS & Rate limiting
│   ├── .env.example              # Backend environment template
│   └── package.json
├── frontend/
│   ├── public/
│   │   ├── index.html
│   │   └── manifest.json
│   ├── src/
│   │   ├── App.jsx               # Main React dashboard & analytics UI
│   │   ├── index.css
│   │   └── index.js
│   ├── .env.example              # Frontend environment template
│   └── package.json
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: `v18.0.0` or higher
- **npm**: `v9.0.0` or higher
- *(Optional - for Local RAG Mode)*: Python `3.10+` and [Ollama](https://ollama.com/)

---

### Local Installation

#### 1. Clone the repository
```bash
git clone https://github.com/your-username/AI_security_analyzer.git
cd AI_security_analyzer
```

#### 2. Configure Backend
```bash
cd backend
npm install
cp .env.example .env
```
Edit `backend/.env` with your settings:
```env
PORT=3001
NODE_ENV=development
FRONTEND_URL=http://localhost:3000

# Recommended: Add your free Google Gemini API key
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
```

Start the backend:
```bash
npm start
```

#### 3. Configure Frontend
Open a new terminal:
```bash
cd frontend
npm install
cp .env.example .env
npm start
```
The dashboard will open automatically at **`http://localhost:3000`**.

---

## 💻 Interactive CLI Demo

OmniScan includes an interactive terminal scanner interface:

```bash
cd backend
node demo.js
```

Features:
- Interactive prompts for Target, Mode, Attacker Persona, and Attacker Goal.
- Live CLI progress spinner.
- ANSI-color formatted terminal risk scorecards and attack chains.

---

## ☁️ Deployment Guide

### Option A: 100% Cloud (Vercel + Render / Cloud VPS)

Since the platform supports Google Gemini, you can deploy the entire stack to the cloud for free with zero background Ollama dependencies.

#### 1. Deploy Frontend to Vercel
1. Import your GitHub repository into [Vercel](https://vercel.com).
2. Set **Root Directory** to `frontend`.
3. Set **Framework Preset** to `Create React App`.
4. Add Environment Variable:
   - `REACT_APP_API_URL` = `https://your-backend-url.onrender.com` (no trailing slash).
5. Click **Deploy**.

#### 2. Deploy Backend to Render / Railway
1. Create a new **Web Service** pointing to your repository.
2. Set **Root Directory** to `backend`.
3. Set **Build Command** to `npm install --omit=dev`.
4. Set **Start Command** to `node server.js`.
5. Add Environment Variables:
   - `NODE_ENV` = `production`
   - `PORT` = `3001`
   - `FRONTEND_URL` = `https://your-app.vercel.app`
   - `GEMINI_API_KEY` = `your_google_gemini_api_key`
   - `TRUST_PROXY` = `true`

---

### Option B: Hybrid / Local Deployment (Ollama + Phi-3)

If you prefer to run air-gapped without external cloud APIs:

1. **Start Ollama**:
   ```bash
   ollama serve
   ollama pull phi3
   ```
2. **Start Local Python RAG**:
   ```bash
   cd backend/rag_service
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   python rag_service.py server
   ```
3. Leave `GEMINI_API_KEY` empty in `backend/.env`. The backend will automatically route queries through `http://127.0.0.1:5001`.

---

## 📡 API Reference

All requests accept `Content-Type: application/json`.

### `POST /api/scan-url`
Scans a public website for missing headers, reflected XSS, SQLi, and exposed credentials.
```json
{
  "url": "https://example.com",
  "goal": "extract customer credentials",
  "persona": "advanced",
  "explainMode": "developer"
}
```

### `POST /api/scan-code`
Runs static pattern analysis and dependency audits on submitted code snippets.
```json
{
  "code": "app.get('/user', (req, res) => db.query('SELECT * FROM users WHERE id=' + req.query.id));",
  "filename": "server.js",
  "goal": "bypass authentication",
  "persona": "advanced",
  "explainMode": "developer"
}
```

### `POST /api/analyze-api`
Probes live REST APIs for access control flaws, CORS wildcards, and unauthenticated endpoints.
```json
{
  "endpoint": "https://api.example.com/v1/users",
  "method": "GET",
  "headers": {},
  "goal": "unauthorized data access",
  "persona": "advanced",
  "explainMode": "developer"
}
```

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
