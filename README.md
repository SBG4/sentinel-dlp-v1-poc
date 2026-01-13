<div align="center">

# 🛡️ SentinelDLP v1 POC

**Proof of Concept - Document Sensitivity Detection System**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Claude AI](https://img.shields.io/badge/Claude-AI%20Powered-6B4FBB)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*AI-powered document classification for enterprise security teams - Proof of Concept Edition*

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [API](#api-reference)

</div>

---

## 📋 Overview

SentinelDLP v1 POC is a lightweight proof-of-concept demonstrating AI-powered document sensitivity detection. This version is ideal for:

- **Evaluating the concept** before enterprise deployment
- **Small teams** (< 50 users) for internal document scanning
- **Development and testing** of DLP workflows
- **Learning** how Claude AI can be used for security classification

### ⚠️ POC Limitations

This is a **Proof of Concept** and has limitations:

| Feature | v1 POC | Production Needed |
|---------|--------|-------------------|
| Authentication | ❌ None | JWT/AD/LDAP |
| File Formats | Text only | PDF, DOCX, Images |
| Scalability | Single instance | Horizontal scaling |
| Storage | JSON files | Database |
| Deployment | Manual | Docker/K8s |

## ✨ Features

- **7-Dimension Sensitivity Scoring** - PII, Financial, Strategic, IP, Legal, OpSec, HR
- **Claude AI Integration** - Configurable via Web UI
- **Department Routing** - Automatic classification for 9 departments
- **Regulatory Detection** - GDPR, HIPAA, PCI-DSS, SOX compliance flags
- **Incident Dashboard** - Real-time analytics and logging
- **RESTful API** - Full programmatic access

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Anthropic API Key ([Get one here](https://console.anthropic.com/))

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sentinel-dlp-v1-poc.git
cd sentinel-dlp-v1-poc

# Install dependencies
pip install -r src/backend/requirements.txt

# Start the application
./start.sh
```

### Access

| Service | URL |
|---------|-----|
| 🌐 **Web UI** | http://localhost:3000 |
| 📡 **API** | http://localhost:8000 |
| 📚 **API Docs** | http://localhost:8000/docs |

### First-Time Setup

1. Open http://localhost:3000
2. Go to **Settings**
3. Enter your Anthropic API key
4. Click **Test Connection**
5. Start scanning documents!

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Browser                               │
│              React SPA (localhost:3000)                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Backend                             │
│               (localhost:8000)                               │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Analyze   │  │  Incidents  │  │     Settings        │  │
│  │   Engine    │  │   Manager   │  │     Manager         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Claude API                                │
│               Anthropic AI Backend                           │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
sentinel-dlp-v1-poc/
├── src/
│   ├── backend/
│   │   ├── main.py           # FastAPI application
│   │   └── requirements.txt  # Python dependencies
│   └── frontend/
│       └── index.html        # React SPA
├── docs/
│   └── EXPLAINER.xml         # Claude explainer file
├── data/                     # Runtime data (gitignored)
├── start.sh                  # Startup script
├── .gitignore
├── LICENSE
└── README.md
```

## 📡 API Reference

### Analyze Text

```bash
curl -X POST http://localhost:8000/api/analyze/text \
  -H "Content-Type: application/json" \
  -d '{
    "document_text": "John Doe SSN: 123-45-6789",
    "filename": "test.txt"
  }'
```

### Upload File

```bash
curl -X POST http://localhost:8000/api/analyze/file \
  -F "file=@document.txt"
```

### Response Schema

```json
{
  "id": "uuid",
  "overall_sensitivity_score": 85,
  "sensitivity_level": "HIGH",
  "confidence": 0.92,
  "dimension_scores": {
    "pii": 90,
    "financial": 45,
    "strategic_business": 40,
    "intellectual_property": 30,
    "legal_compliance": 50,
    "operational_security": 70,
    "hr_employee": 20
  },
  "department_relevance": {
    "HR": "HIGH",
    "IT_Security": "CRITICAL"
  },
  "findings": [...],
  "regulatory_concerns": ["GDPR"],
  "recommended_actions": [...]
}
```

## 📊 Sensitivity Dimensions

| Dimension | Description | Examples |
|-----------|-------------|----------|
| **PII** | Personal Identifiable Information | SSN, passport, addresses |
| **Financial** | Financial data | Revenue, salaries, banking |
| **Strategic** | Business strategy | M&A, roadmaps, partnerships |
| **IP** | Intellectual property | Patents, source code, R&D |
| **Legal** | Legal compliance | Contracts, attorney-client |
| **OpSec** | Operational security | Credentials, network diagrams |
| **HR** | Human resources | Reviews, disciplinary actions |

## 🔄 Upgrade Path

When ready for production, consider:

| Version | Best For | Key Additions |
|---------|----------|---------------|
| **v1 Docker** | Small-medium teams | Docker, OCR, PDF support |
| **v2 Production** | Enterprise (300+ endpoints) | Auth, Elasticsearch, scaling |

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**[⬆ Back to Top](#-sentineldlp-v1-poc)**

*Proof of Concept - For evaluation and small team use*

</div>
