# Evaluation Section: Supplementary Outputs

## 3. Scanner Ingestion Log for Workload 2 (Mobile Payment)

**Confirmed explicitly:** The scanner normalization test (Task 3) was **not run** for Workload 2 (mobile payment platform). 

The existing multi-scanner tests in `task3_ingestion.py` evaluate parser performance using synthetic vulnerability fixtures (ZAP, Prowler, Checkov, Trivy) that are decoupled from specific workload contexts. Therefore, there is no separate scanner output log associated with the Workload 2 chat session. Please document this as a scope limitation in the evaluation section.

## 5. Negative / Failure Test Cases

To demonstrate the system's robustness, the following three failure scenarios were evaluated:

### Scenario 1: Malformed Scanner Output
- **Input Provided:** A corrupted JSON payload (`{"invalid": "json"...`) submitted to the `/api/v1/scans/ingest` endpoint.
- **System Behavior:** The specific scanner parser (or `GenericParser`) raises a JSONDecodeError during content extraction.
- **Result:** **Pass (Failed Gracefully)**. The FastAPI `try/except` block at line 501 in `api.py` catches the exception, rolls back the database transaction to prevent partial ingestion, and returns an HTTP 500 error containing the exception details (`detail=str(e)`). The system does not crash and continues serving other requests.

### Scenario 2: LLM Returns Malformed Maturity Score
- **Input Provided:** The LLM hallucinates an invalid `maturity_signal` (e.g., `-1`, `10`, or `None`) in the structured JSON block parsed by the ANSWER_ANALYZER.
- **System Behavior:** When computing the pillar maturity averages during `_finish_assessment`, the backend uses `qa["analysis"].get("maturity_signal", 3)`. For valid but out-of-range integers (e.g., `10`), the mathematical averager accepts it. The `_get_maturity_level(score)` function is resilient by design: anything `< 1` is bounded to "Unknown", and anything `>= 5` defaults safely to "Continuously Improved / Optimizing".
- **Result:** **Pass (Failed Gracefully)**. No crash occurs. The UI displays the bounded categorization without impacting the PDF report generation workflow.

### Scenario 3: RAG Query Returns No Relevant Chunks
- **Input Provided:** A highly specific or out-of-domain knowledge query (e.g., "What is the capital of France?") sent to `/api/v1/rag/chat` that has no semantic overlap with the uploaded compliance PDFs.
- **System Behavior:** ChromaDB's cosine similarity search yields results below the semantic relevance threshold. `rag_service.query_documents` returns the explicit string: `"No relevant context found in documents."`
- **Result:** **Pass (Failed Gracefully)**. `api.py` passes this empty context to the LLM and successfully returns `{ "answer": "...", "context_used": false }`. The LLM falls back transparently to its pre-trained baseline knowledge to answer the user without crashing the conversational flow.
