"""
Sensitive Information Detection System - Backend API
FastAPI service with Claude API integration for document analysis
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List
import asyncio

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import anthropic

# Initialize FastAPI app
app = FastAPI(
    title="Sensitive Information Detection API",
    description="Enterprise document sensitivity analysis powered by Claude AI",
    version="1.0.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data storage paths
DATA_DIR = Path(__file__).parent.parent / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
UPLOADS_DIR = DATA_DIR / "uploads"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

# ============== Models ==============

class Settings(BaseModel):
    api_key: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    auto_delete_uploads: bool = True
    retention_days: int = 30

class SettingsUpdate(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = None
    max_tokens: Optional[int] = None
    auto_delete_uploads: Optional[bool] = None
    retention_days: Optional[int] = None

class AnalysisRequest(BaseModel):
    document_text: str
    filename: str = "unknown"
    filetype: str = "unknown"
    filesize: str = "unknown"

class DimensionScores(BaseModel):
    pii: int = 0
    financial: int = 0
    strategic_business: int = 0
    intellectual_property: int = 0
    legal_compliance: int = 0
    operational_security: int = 0
    hr_employee: int = 0

class DepartmentRelevance(BaseModel):
    HR: str = "NONE"
    Finance: str = "NONE"
    Legal: str = "NONE"
    IT_Security: str = "NONE"
    Executive: str = "NONE"
    RnD: str = "NONE"
    Sales: str = "NONE"
    Operations: str = "NONE"
    Marketing: str = "NONE"

class Finding(BaseModel):
    category: str
    severity: str
    description: str
    count: int = 1
    examples: List[str] = []

class AnalysisResult(BaseModel):
    id: str
    timestamp: str
    filename: str
    filetype: str
    filesize: str
    overall_sensitivity_score: int
    sensitivity_level: str
    confidence: float
    dimension_scores: DimensionScores
    department_relevance: DepartmentRelevance
    findings: List[Finding]
    regulatory_concerns: List[str]
    recommended_actions: List[str]
    reasoning: str
    status: str = "completed"
    error: Optional[str] = None

class Incident(BaseModel):
    id: str
    timestamp: str
    filename: str
    filetype: str
    filesize: str
    sensitivity_level: str
    overall_score: int
    top_categories: List[str]
    departments_affected: List[str]
    status: str
    hash: str

# ============== Storage Functions ==============

def load_settings() -> Settings:
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, 'r') as f:
            data = json.load(f)
            return Settings(**data)
    return Settings()

def save_settings(settings: Settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings.model_dump(), f, indent=2)

def load_incidents() -> List[dict]:
    if INCIDENTS_FILE.exists():
        with open(INCIDENTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_incidents(incidents: List[dict]):
    with open(INCIDENTS_FILE, 'w') as f:
        json.dump(incidents, f, indent=2, default=str)

def add_incident(result: AnalysisResult, doc_hash: str):
    incidents = load_incidents()
    
    # Get top categories (score > 50)
    dim_scores = result.dimension_scores.model_dump()
    top_cats = [k for k, v in dim_scores.items() if v > 50]
    
    # Get affected departments (HIGH or CRITICAL)
    dept_rel = result.department_relevance.model_dump()
    affected_depts = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]
    
    incident = Incident(
        id=result.id,
        timestamp=result.timestamp,
        filename=result.filename,
        filetype=result.filetype,
        filesize=result.filesize,
        sensitivity_level=result.sensitivity_level,
        overall_score=result.overall_sensitivity_score,
        top_categories=top_cats,
        departments_affected=affected_depts,
        status=result.status,
        hash=doc_hash
    )
    
    incidents.insert(0, incident.model_dump())
    
    # Keep last 1000 incidents
    incidents = incidents[:1000]
    save_incidents(incidents)

# ============== Analysis System Prompt ==============

ANALYSIS_PROMPT = """You are a sensitive information detection system deployed in an enterprise environment. Your task is to analyze documents and assign accurate sensitivity ratings to prevent data leakage, ensure compliance, and protect organizational information.

Analyze the provided document and generate a comprehensive sensitivity assessment. Output ONLY valid JSON matching this exact schema:

{
  "overall_sensitivity_score": <0-100>,
  "sensitivity_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "confidence": <0.0-1.0>,
  
  "dimension_scores": {
    "pii": <0-100>,
    "financial": <0-100>,
    "strategic_business": <0-100>,
    "intellectual_property": <0-100>,
    "legal_compliance": <0-100>,
    "operational_security": <0-100>,
    "hr_employee": <0-100>
  },
  
  "department_relevance": {
    "HR": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Finance": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Legal": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "IT_Security": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Executive": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "RnD": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Sales": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Operations": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Marketing": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>"
  },
  
  "findings": [
    {
      "category": "<dimension name>",
      "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "description": "<what was found, with values redacted>",
      "count": <number of instances>,
      "examples": ["<redacted sample 1>", "<redacted sample 2>"]
    }
  ],
  
  "regulatory_concerns": ["<GDPR|HIPAA|PCI-DSS|SOX|NONE>"],
  
  "recommended_actions": ["<specific action recommendation>"],
  
  "reasoning": "<brief explanation of scoring rationale>"
}

Sensitivity Dimensions to analyze:
1. PII: Names, IDs, SSN, financial accounts, medical records, biometrics
2. Financial: Revenue, budgets, salaries, banking, forecasts
3. Strategic Business: M&A, partnerships, roadmaps, competitive analysis
4. Intellectual Property: Patents, source code, R&D, trade secrets
5. Legal & Compliance: Attorney-client privilege, regulatory filings, audits
6. Operational Security: Credentials, network diagrams, vulnerabilities
7. HR & Employee: Performance reviews, disciplinary actions, terminations

Scoring Guide:
- Low (0-30): Public information, marketing materials
- Medium (31-60): Internal use, non-sensitive business data  
- High (61-85): Confidential, limited distribution
- Critical (86-100): Highly restricted, severe impact if leaked

CRITICAL: Output ONLY the JSON object, no markdown, no explanation outside JSON."""

# ============== API Endpoints ==============

@app.get("/")
async def root():
    return {"status": "online", "service": "Sensitive Information Detection API", "version": "1.0.0"}

@app.get("/api/health")
async def health_check():
    settings = load_settings()
    return {
        "status": "healthy",
        "api_configured": bool(settings.api_key),
        "model": settings.model
    }

# Settings endpoints
@app.get("/api/settings")
async def get_settings():
    settings = load_settings()
    # Mask API key for security
    masked = settings.model_dump()
    if masked["api_key"]:
        masked["api_key"] = masked["api_key"][:8] + "..." + masked["api_key"][-4:] if len(masked["api_key"]) > 12 else "***configured***"
    masked["api_key_set"] = bool(settings.api_key)
    return masked

@app.put("/api/settings")
async def update_settings(update: SettingsUpdate):
    settings = load_settings()
    update_data = update.model_dump(exclude_unset=True)
    
    for key, value in update_data.items():
        if value is not None:
            setattr(settings, key, value)
    
    save_settings(settings)
    return {"status": "updated", "message": "Settings saved successfully"}

@app.post("/api/settings/test")
async def test_api_connection():
    settings = load_settings()
    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured")
    
    try:
        client = anthropic.Anthropic(api_key=settings.api_key)
        response = client.messages.create(
            model=settings.model,
            max_tokens=50,
            messages=[{"role": "user", "content": "Say 'API connection successful' in exactly those words."}]
        )
        return {"status": "success", "message": "API connection verified", "model": settings.model}
    except anthropic.AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid API key")
    except anthropic.APIError as e:
        raise HTTPException(status_code=500, detail=f"API error: {str(e)}")

# Analysis endpoints
@app.post("/api/analyze/text")
async def analyze_text(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze document text directly"""
    settings = load_settings()
    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured. Please configure in Settings.")
    
    # Generate analysis ID and hash
    analysis_id = str(uuid.uuid4())
    doc_hash = hashlib.sha256(request.document_text.encode()).hexdigest()[:16]
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    try:
        client = anthropic.Anthropic(api_key=settings.api_key)
        
        # Build the analysis request
        user_message = f"""Analyze this document:

<document>
{request.document_text}
</document>

<metadata>
File name: {request.filename}
File type: {request.filetype}
File size: {request.filesize}
Upload timestamp: {timestamp}
</metadata>"""

        response = client.messages.create(
            model=settings.model,
            max_tokens=settings.max_tokens,
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )
        
        # Parse response
        response_text = response.content[0].text
        
        # Clean potential markdown wrapping
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        
        analysis_data = json.loads(response_text)
        
        # Build result object
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=request.filename,
            filetype=request.filetype,
            filesize=request.filesize,
            overall_sensitivity_score=analysis_data.get("overall_sensitivity_score", 0),
            sensitivity_level=analysis_data.get("sensitivity_level", "LOW"),
            confidence=analysis_data.get("confidence", 0.5),
            dimension_scores=DimensionScores(**analysis_data.get("dimension_scores", {})),
            department_relevance=DepartmentRelevance(**analysis_data.get("department_relevance", {})),
            findings=[Finding(**f) for f in analysis_data.get("findings", [])],
            regulatory_concerns=analysis_data.get("regulatory_concerns", []),
            recommended_actions=analysis_data.get("recommended_actions", []),
            reasoning=analysis_data.get("reasoning", ""),
            status="completed"
        )
        
        # Log incident
        add_incident(result, doc_hash)
        
        return result.model_dump()
        
    except json.JSONDecodeError as e:
        # Return partial result with error
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=request.filename,
            filetype=request.filetype,
            filesize=request.filesize,
            overall_sensitivity_score=0,
            sensitivity_level="UNKNOWN",
            confidence=0,
            dimension_scores=DimensionScores(),
            department_relevance=DepartmentRelevance(),
            findings=[],
            regulatory_concerns=[],
            recommended_actions=[],
            reasoning="",
            status="error",
            error=f"Failed to parse AI response: {str(e)}"
        )
        add_incident(result, doc_hash)
        return result.model_dump()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze uploaded file"""
    settings = load_settings()
    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured. Please configure in Settings.")
    
    # Read file content
    content = await file.read()
    filesize = f"{len(content)} bytes"
    
    # Determine file type and extract text
    filename = file.filename or "unknown"
    filetype = filename.split(".")[-1].lower() if "." in filename else "unknown"
    
    # For now, handle text-based files
    supported_types = ["txt", "csv", "json", "xml", "html", "md", "log", "py", "js", "ts", "yaml", "yml", "ini", "conf", "cfg"]
    
    if filetype in supported_types:
        try:
            document_text = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                document_text = content.decode("latin-1")
            except:
                raise HTTPException(status_code=400, detail="Unable to decode file content")
    else:
        # For binary files, we'd need additional processing (PDF, DOCX, etc.)
        raise HTTPException(
            status_code=400, 
            detail=f"File type '{filetype}' not directly supported. Supported types: {', '.join(supported_types)}. For PDF/DOCX, extract text first."
        )
    
    # Create analysis request
    request = AnalysisRequest(
        document_text=document_text,
        filename=filename,
        filetype=filetype,
        filesize=filesize
    )
    
    # Reuse text analysis
    return await analyze_text(request, BackgroundTasks())

# Incidents/Dashboard endpoints
@app.get("/api/incidents")
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    department: Optional[str] = None
):
    """Get incident log with optional filtering"""
    incidents = load_incidents()
    
    # Apply filters
    if severity:
        incidents = [i for i in incidents if i.get("sensitivity_level") == severity.upper()]
    
    if department:
        incidents = [i for i in incidents if department in i.get("departments_affected", [])]
    
    total = len(incidents)
    incidents = incidents[offset:offset + limit]
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "incidents": incidents
    }

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get specific incident details"""
    incidents = load_incidents()
    for incident in incidents:
        if incident.get("id") == incident_id:
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")

@app.delete("/api/incidents/{incident_id}")
async def delete_incident(incident_id: str):
    """Delete an incident"""
    incidents = load_incidents()
    incidents = [i for i in incidents if i.get("id") != incident_id]
    save_incidents(incidents)
    return {"status": "deleted", "id": incident_id}

@app.delete("/api/incidents")
async def clear_incidents():
    """Clear all incidents"""
    save_incidents([])
    return {"status": "cleared", "message": "All incidents deleted"}

# Statistics endpoint
@app.get("/api/stats")
async def get_statistics():
    """Get dashboard statistics"""
    incidents = load_incidents()
    
    if not incidents:
        return {
            "total_scans": 0,
            "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "by_department": {},
            "by_category": {},
            "avg_score": 0,
            "recent_critical": []
        }
    
    # Count by severity
    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    for i in incidents:
        level = i.get("sensitivity_level", "UNKNOWN")
        by_severity[level] = by_severity.get(level, 0) + 1
    
    # Count by department
    by_department = {}
    for i in incidents:
        for dept in i.get("departments_affected", []):
            by_department[dept] = by_department.get(dept, 0) + 1
    
    # Count by category
    by_category = {}
    for i in incidents:
        for cat in i.get("top_categories", []):
            by_category[cat] = by_category.get(cat, 0) + 1
    
    # Average score
    scores = [i.get("overall_score", 0) for i in incidents]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Recent critical
    recent_critical = [i for i in incidents if i.get("sensitivity_level") == "CRITICAL"][:5]
    
    return {
        "total_scans": len(incidents),
        "by_severity": by_severity,
        "by_department": by_department,
        "by_category": by_category,
        "avg_score": round(avg_score, 1),
        "recent_critical": recent_critical
    }

# Available models endpoint
@app.get("/api/models")
async def get_available_models():
    """Get list of available Claude models"""
    return {
        "models": [
            {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "description": "Fast and capable"},
            {"id": "claude-opus-4-20250514", "name": "Claude Opus 4", "description": "Most capable"},
            {"id": "claude-haiku-4-20250514", "name": "Claude Haiku 4", "description": "Fastest, most economical"}
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
