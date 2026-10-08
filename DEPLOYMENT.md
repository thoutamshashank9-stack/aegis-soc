# AEGIS SOC Threat Intelligence Platform — Production Deployment Guide (Render)

This guide provides step-by-step instructions to deploy the **AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform** publicly on [Render](https://render.com) for college project reviews and external demonstrations.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │            User Web Browser            │
                      └──────────────────┬─────────────────────┘
                                         │
                   HTTPS API Calls       │  HTTPS Static Assets
         (VITE_API_BASE_URL)             │
                                         ▼
┌────────────────────────────────────────┐     ┌────────────────────────────────────────┐
│     Render Backend Web Service         │     │      Render Frontend Static Site       │
│     (Python 3.11 / FastAPI / Uvicorn)  │     │      (React / Vite / Tailwind CSS)     │
│     https://aegis-backend.onrender.com │     │      https://aegis-soc.onrender.com    │
└──────────────────┬─────────────────────┘     └────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│   Database (SQLite / PostgreSQL)       │
│   In-Memory ML Inference (TF-IDF + LR) │
│   Forensic MIME / RFC 5322 Engine      │
└────────────────────────────────────────┘
```

---

## Prerequisites

1. A [GitHub](https://github.com) account.
2. A free [Render](https://render.com) account.
3. Your local repository committed to GitHub.

---

## Step 1: Push Repository to GitHub

Ensure sensitive files (`.env`, `node_modules/`, `__pycache__/`) are excluded via `.gitignore`.

From the project root:

```bash
git init
git add .
git commit -m "feat: prepare AEGIS SOC platform for production deployment"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

---

## Step 2: Deploy the Backend Web Service on Render

1. Log into your **Render Dashboard** (`https://dashboard.render.com`).
2. Click **New +** > **Web Service**.
3. Select your connected GitHub repository.
4. Configure the Web Service settings:

| Setting | Value | Notes |
| :--- | :--- | :--- |
| **Name** | `aegis-soc-backend` | Or any unique service name |
| **Region** | `Frankfurt` / `Oregon` / `Ohio` | Choose closest to you |
| **Branch** | `main` | Production branch |
| **Root Directory** | `backend` | Runs builds inside the `backend/` folder |
| **Runtime** | `Python 3` | Render detects `.python-version` (3.11.9) |
| **Build Command** | `pip install -r requirements.txt` | Installs FastAPI, scikit-learn, etc. |
| **Start Command** | `uvicorn main:app --host 0.0.0.0 --port $PORT` | Listens dynamically on Render's assigned port |
| **Instance Type** | `Free` | Free tier supported |

5. Under **Advanced** > **Health Check Path**:
   - Set to: `/api/health`
6. Under **Environment Variables**, add:

| Key | Value | Purpose |
| :--- | :--- | :--- |
| `PYTHON_VERSION` | `3.11.9` | Ensures compatible Python runtime |
| `FRONTEND_ORIGIN` | `*` | Or your deployed frontend URL in Step 3 |
| `DATABASE_URL` | `sqlite:///./email_threat_intelligence.db` | Default SQLite persistence (or Render Postgres) |

7. Click **Create Web Service**.
8. Wait for the build to finish. Once live, copy your backend URL (e.g., `https://aegis-soc-backend.onrender.com`).
9. Test the health endpoint in your browser:
   `https://aegis-soc-backend.onrender.com/api/health` → should return `{"status": "healthy"}`.

---

## Step 3: Deploy the Frontend Static Site on Render

1. Return to the **Render Dashboard**.
2. Click **New +** > **Static Site**.
3. Select the same GitHub repository.
4. Configure the Static Site settings:

| Setting | Value | Notes |
| :--- | :--- | :--- |
| **Name** | `aegis-soc-frontend` | Or any unique name |
| **Branch** | `main` | Production branch |
| **Root Directory** | `frontend` | Vite project root |
| **Build Command** | `npm install && npm run build` | Compiles optimized Vite distribution |
| **Publish Directory** | `dist` | Built production bundle |

5. Under **Environment Variables**, add:

| Key | Value |
| :--- | :--- |
| `VITE_API_BASE_URL` | `https://aegis-soc-backend.onrender.com` |

*(Replace with your actual backend URL from Step 2, without a trailing slash).*

6. Under **Redirects/Rewrites**:
   - Add a rewrite rule for React Router:
     - **Type**: `Rewrite`
     - **Source**: `/*`
     - **Destination**: `/index.html`
7. Click **Create Static Site**.
8. Once deployment completes, open your frontend URL (e.g., `https://aegis-soc-frontend.onrender.com`).

---

## Step 4: Verification & Smoke Testing

1. **Dashboard Loading**: Verify the SOC Operations dashboard displays dynamic telemetry counters without console errors.
2. **Email Upload & Analysis**:
   - Open **Threat Sandbox**.
   - Test with an uploaded `.eml` file or click any synthetic scenario (e.g. `phishing_demo.eml`, `test_d_public_ip_demo.eml`, `test_e_multi_hop_demo.eml`).
   - Confirm threat score, SPF/DKIM/DMARC verdicts, ML confidence, and extracted IOCs are populated.
3. **IP Geolocation**:
   - Open **IP Geolocation & Routing Intelligence**.
   - Verify 3-way distinction (Network PoP vs Relay Role vs Sender Physical Location: Unverified).
   - Verify non-routable IPs (RFC 1918 / RFC 5737) are flagged as `Not geolocatable` with zero fabricated coordinates.
   - Verify public IPs render an interactive OpenStreetMap view.
4. **Reports**:
   - Open **Forensic Reports**, select the case, and download or print the report.

---

## Troubleshooting Common Issues

### 1. Free Tier Cold Starts
On Render's Free tier, services spin down after 15 minutes of inactivity. The first request after idle may take 30–50 seconds while the instance wakes up. The frontend includes production error handling and timeouts to accommodate this cleanly.

### 2. CORS Preflight Failures
If API requests are blocked by CORS:
- Go to Render Dashboard > `aegis-soc-backend` > **Environment Variables**.
- Set `FRONTEND_ORIGIN=*` or explicitly provide `https://<YOUR_FRONTEND_URL>.onrender.com`.
- Trigger a manual deploy.

### 3. React Router 404 on Page Refresh
If refreshing `/analysis` or `/reports` gives a 404 on Render:
- Ensure the Static Site **Redirects/Rewrites** rule is configured (`/*` → `/index.html`, Action: `Rewrite`).
