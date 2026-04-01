# Technical Architecture & System Documentation

This document describes the architectural flow, component relationships, and directory structure of the CloudSecurityApp.

## Architectural Flow
CloudSecurityApp is divided into three primary assessment phases powered by a FastAPI backend and a React (Vite) frontend.

1. **Phase 1: Conversational WAF Assessment**
   - **User Flow**: The user interacts with the system via the `/api/chat/*` endpoints. 
   - **Logic**: The LLM acts as an architect, traversing AWS Well-Architected Framework pillars, scoring responses, and finally generating a PDF technical report.
   - **Persistence**: Sessions are currently built dynamically into PDF formats and cached in backend states.

2. **Phase 2: DAST / CSPM Ingestion & Triage**
   - **User Flow**: Users upload XML/JSON outputs from popular vulnerability scanners (ZAP, Burp, Trivy).
   - **Logic**: The `assessment_engine/dast_parsers` interpret the proprietary outputs, mapping them to a generic `UnifiedVulnerability` model. The prioritization engine scores these based on severity and risk context. 
   - **AI Context**: Users can chat specifically about their findings ("Summarize this report," "How do I fix this cross-site scripting issue?").

3. **Phase 3: RAG Knowledge Base**
   - **User Flow**: Admins upload PDF architectural reference models.
   - **Logic**: PDFs are immediately fragmented and embedded using `sentence-transformers` and stored in `ChromaDB` inside the `rag_db` directory. 
   - **AI Context**: Queries to the LLM are enriched by vector-matching content from these technical documents, generating highly relevant advice.

## Directory Structure
- `/` - Root workspace including `README.md`, `DOCS.md`, `start.ps1`, `docker-compose.yml`, and `api.py`.
- `/assessment_engine` - The core backend logic module.
  - `llm_service.py`: Orchestrates queries to Groq using distinct WAF and Pentesting prompts.
  - `dast_parsers.py`: Adapter pattern implementations for multiple vulnerability scanner schemas.
  - `db.py`: SQLAlchemy schemas mapping API keys, sessions, and findings back to MySQL/SQLite.
  - `prioritization.py`: Scoring algorithm to rank critical DAST findings based on environment scope.
  - `pdf_generator.py`: Formatting logic utilizing `reportlab`.
- `/ui` - The React Vite Frontend. Provides real-time views utilizing components like `DastAnalyzer.jsx` and `AdminDashboard.jsx`.
- `/raft` - Experimental sub-system supporting retrieval-augmented fine tuning.

## Security Context
- All API bindings meant for internal admin or RAG upload require authentication via the `x-api-key` header, which is hashed (`API_KEY_SALT`).
- Web service interactions are bound to Cross-Origin constraints initialized in `ALLOWED_ORIGINS` to mitigate Cross-Site Request Forgery architectures.
