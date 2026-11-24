# ReconMind — Installation and Deployment Guide

## Prerequisites

- **Python**: Version 3.11 or 3.13
- **Node.js**: Version 18.x or newer (npm 10+)
- **Operating System**: Windows 10/11, Ubuntu 22.04+, or macOS Sonoma+
- **MongoDB** *(Optional)*: Recommended for production deployments. If absent, ReconMind automatically engages its high-speed local file JSON fallback engine.

---

## 1. Backend Setup

Open a terminal (e.g. PowerShell on Windows) and run:

```powershell
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### Launching the Backend API
From the project root directory:

```powershell
$env:PYTHONPATH=".\backend;."
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI documentation is accessible at: `http://127.0.0.1:8000/docs`

---

## 2. Frontend Dashboard Setup

In a separate terminal:

```powershell
# Navigate to frontend directory
cd frontend

# Install node dependencies
npm install

# Start Vite development server
npm run dev
```

The interactive security dashboard opens at: `http://127.0.0.1:5173`

---

## 3. Python SDK Installation

To use the ReconMind guardrail inside your own external Python applications:

```powershell
pip install -e sdk/python/
```
