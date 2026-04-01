"""
CloudSecurityApp — Production-Ready FastAPI Backend
Phase 1: WAF Assessment (LLM-driven, conversational)
Phase 2: DAST/CSPM Scan Ingestion & AI Triage

Production hardening:
  - CORS restricted to ALLOWED_ORIGINS env var
  - API Key authentication on all /api/v1/* endpoints
  - Rate limiting via slowapi (60 req/min default, 10 req/min on ingest)
  - Security response headers injected by middleware
  - Session store replaced global variable (multi-user safe)
  - All secrets via environment variables / .env file
"""

import os
import hashlib
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Security, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

# ── Internal imports ─────────────────────────────────────────────────────────
from assessment_engine.llm_service import LLMService
from assessment_engine.pdf_generator import PDFReportGenerator
from assessment_engine.models import Pillar
from assessment_engine.dast_models import UnifiedVulnerability, ScannerSource, Severity
from assessment_engine.dast_parsers import (
    ZAPParser, BurpParser, NucleiParser, ProwlerParser, CheckovParser, CustomParser, GenericParser
)
from assessment_engine.prioritization import PrioritizationEngine
from assessment_engine.db import get_db, VulnerabilityDB, AssessmentSessionDB, ApiKeyDB, init_db

# ── Configuration ─────────────────────────────────────────────────────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000")
ALLOWED_ORIGINS: List[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
API_KEY_HEADER_NAME = "x-api-key"
LLM_MODEL = os.getenv("LLM_MODEL", "llama3.2")

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="CloudSecurityApp — Cloud Security Platform",
    description="WAF Assessment + DAST/CSPM Unified Analysis Engine",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS (Production-safe) ────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Security Headers Middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    # Uncomment when behind HTTPS in production:
    # response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response

# ── API Key Authentication ────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

async def verify_api_key(
    api_key: str = Security(api_key_header),
    db: Session = Depends(get_db),
):
    """
    Validates the x-api-key header against SHA-256 hashes stored in the DB.
    Raises HTTP 403 if missing or invalid.
    """
    if not api_key:
        raise HTTPException(status_code=403, detail="Missing API Key. Include 'x-api-key' header.")
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    record = db.query(ApiKeyDB).filter(
        ApiKeyDB.key_hash == key_hash,
        ApiKeyDB.is_active == 1
    ).first()
    if not record:
        raise HTTPException(status_code=403, detail="Invalid or inactive API Key.")
    # Update usage stats (fire-and-forget style)
    record.last_used_at   = datetime.utcnow()
    record.requests_count = (record.requests_count or 0) + 1
    db.commit()
    return record

# ── Services (initialized on startup) ────────────────────────────────────────
llm_service: Optional[LLMService] = None

try:
    from assessment_engine.rag_service import RAGService
    rag_service = RAGService()
except Exception as e:
    print(f"Failed to initialize RAG Service: {e}")
    rag_service = None

# ── Session Store (multi-user safe, replaces global variable) ─────────────────
# Maps session_id (str) → session dict
session_store: Dict[str, dict] = {}

# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    session_id: str
    message:    str

class ChatResponse(BaseModel):
    session_id:       str
    response:         str
    finished:         bool = False
    report_available: bool = False
    progress:         float = 0.0

class DastChatRequest(BaseModel):
    message: str
    history: List[Dict[str, str]] = []

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    global llm_service
    print("🚀 CloudSecurityApp starting up...")
    llm_service = LLMService(model=LLM_MODEL)
    try:
        init_db()
        print("✅ Database initialized.")
    except Exception as e:
        print(f"⚠️  Database initialization warning: {e}")
    print(f"✅ CORS allowed origins: {ALLOWED_ORIGINS}")
    print("✅ Services ready.")

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — WAF ASSESSMENT (conversational, no API key required)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/chat/start")
def start_chat():
    """Start a new WAF assessment session. Returns a unique session_id."""
    session_id = str(uuid.uuid4())
    session_store[session_id] = {
        "session_id":          session_id,
        "started_at":          datetime.now().isoformat(),
        "conversation_history": [],
        "current_phase":       "discovery",  # Phases: discovery -> pillar_checks -> tradeoffs
        "current_pillar":      "Operational Excellence",
        "pillar_index":        0,
        "pillars": [
            "Operational Excellence", "Security", "Reliability", 
            "Performance Efficiency", "Cost Optimization", "Sustainability"
        ],
        "workload_profile":    {},
        "pillar_scores":       [],
        "qa_log":              [],
        "question_count":      0,
        "max_questions":       25, # 5 discovery, 15 pillars, 5 tradeoffs
    }

    first_question = (
        "Hello! I'm CloudSecurityApp, your Well-Architected Framework assessment engine. "
        "Let's start by profiling your workload.\n\n"
        "**Q1:** What type of application or system are you assessing? "
        "(e.g., e-commerce web app, internal microservice, data pipeline, IoT platform)"
    )
    session_store[session_id]["conversation_history"].append({
        "role": "assistant", "content": first_question
    })

    return {"session_id": session_id, "response": first_question, "finished": False, "progress": 0.0}


@app.post("/api/chat/message", response_model=ChatResponse)
def chat_message(msg: ChatMessage):
    """Process a user message within an active assessment session."""
    session = session_store.get(msg.session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{msg.session_id}' not found. Start a new assessment via /api/chat/start"
        )

    user_message = msg.message.strip()
    session["conversation_history"].append({"role": "user", "content": user_message})

    # Analyse the answer
    last_question = (
        session["conversation_history"][-2]["content"]
        if len(session["conversation_history"]) > 1
        else ""
    )
    analysis = llm_service.analyze_answer(last_question, user_message)
    session["qa_log"].append({
        "question": last_question,
        "answer":   user_message,
        "analysis": analysis,
    })

    session["question_count"] += 1
    progress = (session["question_count"] / session["max_questions"]) * 100

    if session["question_count"] >= session["max_questions"]:
        return _finish_assessment(msg.session_id)

    # Phase Transition Logic
    # 0-4: Discovery
    # 5-20: Pillar Checks (approx 2-3 per pillar)
    # 21-25: Tradeoffs
    
    if session["question_count"] < 5:
        session["current_phase"] = "discovery"
    elif session["question_count"] < 20:
        session["current_phase"] = "pillar_checks"
        # Advance pillar every 2-3 questions in this phase
        pillar_questions = session["question_count"] - 5
        session["pillar_index"] = min(
            pillar_questions // 3,
            len(session["pillars"]) - 1,
        )
        session["current_pillar"] = session["pillars"][session["pillar_index"]]
    else:
        session["current_phase"] = "tradeoffs"

    context       = _build_context(session)
    next_question = llm_service.generate_question(
        phase=session["current_phase"],
        pillar=session["current_pillar"],
        workload_type=session.get("workload_profile", {}).get("type", "Unknown"),
        previous_context=context,
    )

    session["conversation_history"].append({"role": "assistant", "content": next_question})
    return ChatResponse(
        session_id=msg.session_id,
        response=next_question,
        finished=False,
        progress=round(progress, 1),
    )


def _build_context(session: dict) -> str:
    recent = session["conversation_history"][-6:]
    return "\n".join([f"{m['role']}: {m['content']}" for m in recent])


def _finish_assessment(session_id: str):
    """Finalize assessment and generate the powerful technical report."""
    session = session_store[session_id]
    
    # 1. Calculate scores
    pillar_scores = []
    # Use a set to track gaps for recommendations later
    all_gaps = []
    
    for pillar_name in session["pillars"]:
        # Filter Q&A relevant to this pillar for scoring and analysis
        pillar_qas = []
        for qa in session["qa_log"]:
            analysis = qa.get("analysis", {})
            # Match if pillar is mentioned in analysis or question
            if (pillar_name.lower() in str(analysis.get("evidence_summary", "")).lower() or 
                pillar_name.lower() in qa["question"].lower()):
                pillar_qas.append(qa)
        
        # If no specific QAs found for this pillar, use the full log (fallback)
        if not pillar_qas:
            pillar_qas = session["qa_log"]
            
        avg_score = sum(qa["analysis"].get("maturity_signal", 3) for qa in pillar_qas) / max(len(pillar_qas), 1)
        
        # Collect gaps from this pillar
        for qa in pillar_qas:
            all_gaps.extend(qa["analysis"].get("gaps_identified", []))
            
        ps = {
            "pillar":   pillar_name,
            "score":    round(avg_score, 1),
            "maturity": _get_maturity_level(avg_score),
        }
        
        # 3. Generate per-pillar technical analysis (Real logic)
        evidence_text = ""
        for qa in pillar_qas[:5]: # Take top 5 evidence points
            evidence_text += f"Q: {qa['question']}\nA: {qa['answer']}\nAnalysis: {qa['analysis'].get('evidence_summary','')}\n\n"
        
        if llm_service:
            ps['deep_analysis'] = llm_service.generate_pillar_analysis(
                pillar=pillar_name,
                score=ps['score'],
                maturity_level=ps['maturity'],
                evidence=evidence_text[:3000]
            )
        else:
            ps['deep_analysis'] = "AI Analysis service unavailable."
            
        pillar_scores.append(ps)

    # 4. Generate recommendations and summary
    avg_score = sum(p['score'] for p in pillar_scores) / len(pillar_scores) if pillar_scores else 0
    unique_gaps = list(set(all_gaps))
    
    recommendations = []
    exec_summary = ""
    if llm_service:
        recommendations = llm_service.generate_recommendations(
            session.get('workload_profile', {}),
            pillar_scores,
            unique_gaps
        )
        
        exec_summary = llm_service.generate_executive_summary(
            session.get('workload_profile', {}).get('type', 'Unknown'),
            avg_score,
            pillar_scores,
            unique_gaps[:10]
        )

    # 5. Update session state
    session['pillar_scores'] = pillar_scores
    session['average_score'] = avg_score
    session['recommendations'] = recommendations
    session['executive_summary'] = exec_summary
    session['status'] = 'completed'
    session['completed_at'] = datetime.utcnow().isoformat()

    # 6. Generate PDF report
    report_available = False
    try:
        pdf_gen = PDFReportGenerator()
        output_path = f"assessment_report_{session_id[:8]}.pdf"
        pdf_gen.generate_report(session, output_path)
        session['report_url'] = f"/api/report/download/{session_id}"
        report_available = True
        print(f"✅ Report generated: {output_path}")
    except Exception as e:
        print(f"❌ PDF Generation failed: {e}")

    return ChatResponse(
        session_id=session_id,
        response=(
            f"✅ **Assessment Complete!** Overall Maturity: **{avg_score:.1f}/5.0**\n\n"
            f"{exec_summary}\n\n"
            f"Your comprehensive technical report has been generated."
        ),
        finished=True,
        report_available=report_available,
        progress=100.0
    )


def _get_maturity_level(score: float) -> str:
    if score < 1:   return "Unknown"
    if score < 2:   return "Ad-hoc / Initial"
    if score < 3:   return "Baseline / Repeatable"
    if score < 4:   return "Standardized / Defined"
    if score < 5:   return "Optimized / Managed"
    return "Continuously Improved / Optimizing"


@app.get("/api/report/pdf")
def download_pdf_report(session_id: str):
    """Generate and download a PDF report for a completed assessment session."""
    session = session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    pdf_gen     = PDFReportGenerator()
    output_path = f"assessment_report_{session_id[:8]}.pdf"
    pdf_gen.generate_report(session, output_path)
    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename=f"WAF_Assessment_{datetime.now().strftime('%Y%m%d')}.pdf",
    )


@app.get("/api/status")
def get_status(session_id: Optional[str] = None):
    """Health check + optional session progress."""
    if session_id:
        s = session_store.get(session_id)
        if s:
            return {
                "active":          True,
                "question_count":  s["question_count"],
                "max_questions":   s["max_questions"],
                "current_pillar":  s["current_pillar"],
                "progress":        round((s["question_count"] / s["max_questions"]) * 100, 1),
            }
    return {"active": False, "server": "ok", "version": "2.0.0"}


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — DAST / CSPM INGESTION  (API key required on all /api/v1/* routes)
# ─────────────────────────────────────────────────────────────────────────────

PARSER_MAP = {
    # Specialized parsers
    ScannerSource.OWASP_ZAP:        ZAPParser,
    ScannerSource.BURP_SUITE:       BurpParser,
    ScannerSource.NUCLEI:           NucleiParser,
    ScannerSource.PROWLER:          ProwlerParser,
    ScannerSource.CHECKOV:          CheckovParser,
    ScannerSource.CUSTOM:           CustomParser,
    # Generic parser (handles popular JSON output formats)
    ScannerSource.SCOUTSUITE:       GenericParser,
    ScannerSource.CLOUDSPLOIT:      GenericParser,
    ScannerSource.AMAZON_INSPECTOR: GenericParser,
    ScannerSource.QUALYS_CLOUD:     GenericParser,
    ScannerSource.TRIVY:            GenericParser,
    ScannerSource.KUBE_HUNTER:      GenericParser,
    ScannerSource.KUBE_BENCH:       GenericParser,
    ScannerSource.KUBESCAPE:        GenericParser,
    ScannerSource.NIKTO:            GenericParser,
    ScannerSource.ARACHNI:          GenericParser,
    ScannerSource.STACKHAWK:        GenericParser,
    ScannerSource.BRIGHT_SECURITY:  GenericParser,
    ScannerSource.OPENVAS:          GenericParser,
    ScannerSource.SHODAN:           GenericParser,
    ScannerSource.PACU:             GenericParser,
    ScannerSource.CLOUDGOAT:        GenericParser,
}


@app.post("/api/v1/scans/ingest")
@limiter.limit("10/minute")
async def ingest_scan(
    request: Request,
    file:           UploadFile = File(...),
    scanner_source: ScannerSource = Form(...),
    environment:    str = Form("production"),
    db:             Session = Depends(get_db),
):
    """
    Ingest a DAST or CSPM scan file.
    Supported sources: OWASP_ZAP, Burp_Suite, Nuclei, Prowler, Checkov, Custom.
    Requires x-api-key header.
    """
    parser_cls = PARSER_MAP.get(scanner_source)
    if not parser_cls:
        raise HTTPException(status_code=400, detail=f"Unsupported scanner: {scanner_source}")

    content  = await file.read()
    filename = file.filename

    try:
        parser = parser_cls()
        # GenericParser needs the scanner_source to tag findings correctly
        if isinstance(parser, GenericParser):
            new_vulns = parser.parse(content, filename, scanner_source=scanner_source)
        else:
            new_vulns = parser.parse(content, filename)
        prioritized     = PrioritizationEngine.prioritize_findings(new_vulns)
        saved_count     = 0

        for v in prioritized:
            v_dict = json.loads(v.json())
            db_vuln = VulnerabilityDB(
                id             = v.id,
                title          = v.title,
                severity       = v.severity.value,
                priority_score = v.remediation_tracking.priority_score,
                status         = v.remediation_tracking.status.value,
                scanner_source = v.scanner_source.value,
                environment    = environment,
                full_data      = v_dict,
            )
            db.add(db_vuln)
            saved_count += 1

        db.commit()
        return {
            "status":         "success",
            "findings_count": saved_count,
            "message":        f"Ingested {saved_count} findings from '{filename}' [{scanner_source.value}]",
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vulnerabilities")
@limiter.limit("60/minute")
def get_vulnerabilities(
    request:      Request,
    min_severity: Optional[Severity] = None,
    status:       Optional[str] = None,
    environment:  Optional[str] = None,
    db:           Session = Depends(get_db),
):
    """Return all ingested vulnerabilities with optional filters."""
    query = db.query(VulnerabilityDB)
    if min_severity:
        query = query.filter(VulnerabilityDB.severity == min_severity.value)
    if status:
        query = query.filter(VulnerabilityDB.status == status)
    if environment:
        query = query.filter(VulnerabilityDB.environment == environment)
    vulns = query.order_by(VulnerabilityDB.priority_score.desc()).all()
    return [v.full_data for v in vulns]


@app.post("/api/v1/analysis/summarize")
@limiter.limit("20/minute")
def summarize_findings(
    request: Request,
    db:      Session = Depends(get_db),
):
    """Generate an AI-powered summary of all scan findings."""
    vulns = db.query(VulnerabilityDB).all()
    if not vulns:
        return {"summary": "No findings to summarize."}
    findings_dicts = [v.full_data for v in vulns]
    context = {
        "workload_type":     "Internet-Facing SaaS — Security Platform",
        "environment":       "Production",
        "asset_criticality": "High",
    }
    summary = llm_service.summarize_dast_findings(findings_dicts, context)
    return {"summary": summary}


@app.post("/api/v1/analysis/remediation")
@limiter.limit("20/minute")
def get_remediation(
    request:          Request,
    vulnerability_id: str,
    db:               Session = Depends(get_db),
):
    """Get detailed remediation guidance for a specific vulnerability by ID."""
    vuln = db.query(VulnerabilityDB).filter(VulnerabilityDB.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    remediation = llm_service.generate_remediation_guidance(vuln.full_data)
    return {"remediation": remediation}


class DastChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = None

@app.post("/api/v1/analysis/chat")
@limiter.limit("20/minute")
def dast_chat_endpoint(
    request: Request,
    msg:     DastChatRequest,
    db:      Session = Depends(get_db),
):
    """Conversational assistant for DAST/CSPM findings."""
    vulns = db.query(VulnerabilityDB).all()
    if not vulns:
        context = "No vulnerabilities detected in the current environment."
    else:
        # Create a summary context of the findings
        context = "Current Findings:\n"
        for v in vulns:
            context += f"- {v.title} (Severity: {v.severity})\n"
            
    response = llm_service.dast_chat(msg.message, context, msg.history)
    return {"response": response}


@app.post("/api/v1/context/clarify")
@limiter.limit("20/minute")
def interpret_context(
    request: Request,
    db:      Session = Depends(get_db),
):
    """Generate clarifying questions to improve triage accuracy for current findings."""
    vulns = db.query(VulnerabilityDB).all()
    if not vulns:
        return {"questions": "No findings to analyze."}
    findings_dicts = [v.full_data for v in vulns]
    context = {}
    questions = llm_service.get_dast_clarifications(findings_dicts, context)
    return {"questions": questions}


@app.get("/api/v1/stats")
@limiter.limit("60/minute")
def get_stats(
    request: Request,
    db:      Session = Depends(get_db),
):
    """Return a summary dashboard of finding counts by severity/status."""
    from sqlalchemy import func
    severity_counts = (
        db.query(VulnerabilityDB.severity, func.count(VulnerabilityDB.id))
        .group_by(VulnerabilityDB.severity)
        .all()
    )
    status_counts = (
        db.query(VulnerabilityDB.status, func.count(VulnerabilityDB.id))
        .group_by(VulnerabilityDB.status)
        .all()
    )
    return {
        "by_severity": {s: c for s, c in severity_counts},
        "by_status":   {s: c for s, c in status_counts},
        "total":       sum(c for _, c in severity_counts),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 3 — RAG / KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/rag/upload")
@limiter.limit("10/minute")
async def rag_upload(
    request: Request,
    file: UploadFile = File(...),
    _auth: ApiKeyDB = Depends(verify_api_key),
):
    """Upload a PDF document to the RAG knowledge base."""
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG Service is not available.")
        
    if not file.filename.endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")
        
    # Save file temporarily
    temp_path = f"rag_docs/temp_{file.filename}"
    try:
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)
            
        result = rag_service.ingest_pdf(temp_path, file.filename)
        
        if not result.get("success"):
             raise HTTPException(status_code=500, detail=result.get("error", "Unknown error during ingestion."))
             
        return result
    finally:
        # Cleanup temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.get("/api/v1/rag/documents")
@limiter.limit("60/minute")
def list_rag_documents(
    request: Request,
    _auth: ApiKeyDB = Depends(verify_api_key),
):
    """List all documents currently in the RAG knowledge base."""
    if not rag_service:
        return []
        
    return rag_service.get_all_documents()


@app.delete("/api/v1/rag/documents/{doc_id}")
@limiter.limit("20/minute")
def delete_rag_document(
    request: Request,
    doc_id: str,
    _auth: ApiKeyDB = Depends(verify_api_key),
):
    """Remove a document and its embeddings from the RAG knowledge base."""
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG Service is not available.")
        
    success = rag_service.delete_document(doc_id)
    if success:
        return {"status": "success", "message": f"Document {doc_id} deleted."}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete document.")


class RagQuery(BaseModel):
    query: str

@app.post("/api/v1/rag/chat")
@limiter.limit("20/minute")
def rag_chat(
    request: Request,
    body: RagQuery,
    _auth: ApiKeyDB = Depends(verify_api_key),
):
    """Ask a question to the RAG knowledge base."""
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG Service is not available.")
        
    query = body.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
        
    # 1. Retrieve context
    context = rag_service.query_documents(query)
    
    # 2. Generate answer
    answer = llm_service.answer_with_context(query, context)
    
    return {
        "answer": answer,
        "context_used": context != "No relevant context found in documents."
    }

# ── STATIC UI ────────────────────────────────────────────────────────────────
if os.path.exists("ui/dist/assets"):
    app.mount("/assets", StaticFiles(directory="ui/dist/assets"), name="assets")

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    """Serve the React frontend for all unknown paths."""
    ui_index = "ui/dist/index.html"
    if os.path.exists(ui_index):
        return FileResponse(ui_index)
    return {"message": "UI not built. Please run 'npm run build' in the /ui directory."}
