"""
SCAAE — Task 2 + Task 4: Live Assessment Capture & Performance Timing
  Task 2: Hit the running FastAPI backend for two workloads and log everything.
  Task 4: Repeated timing runs for 5 metrics.
Requires the backend to be running on http://127.0.0.1:8000
"""
import sys, os, json, time, requests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:8000"

WORKLOADS = {
    "workload1_ecommerce": (
        "A basic e-commerce web application hosted on AWS. Single-region deployment. "
        "EC2 instances behind an Application Load Balancer. RDS MySQL database backend. "
        "S3 for static assets. No stated compliance requirements. No formal disaster "
        "recovery plan. Backups run nightly to the same region."
    ),
    "workload2_fintech": (
        "A fintech API platform running on EKS (Kubernetes) across two AWS regions. "
        "Handles payment card data (PCI scope) and personal customer PII. No WAF deployed. "
        "Application logs are written to local pod storage only — not shipped to a central "
        "log aggregator. Autoscaling is configured but no maximum node limit is defined. "
        "No rate limiting on public API endpoints. Uses a third-party payment processor "
        "via outbound HTTPS only."
    ),
}

SIMULATED_ANSWERS = [
    "Yes, we use automated CI/CD with GitHub Actions for all deployments.",
    "We have CloudWatch for monitoring but no centralized log aggregation.",
    "We use AWS RDS with Multi-AZ for the database, backups daily.",
    "Security is handled at the ALB level with SSL termination.",
    "We have an IAM policy but it hasn't been audited recently.",
    "Our RTO is 4 hours but no formal DR plan exists.",
    "We use auto-scaling groups on EC2 but haven't load-tested recently.",
    "We do monthly patching, coordinated with the operations team.",
    "Cost tagging is partially implemented, missing on older resources.",
    "No Kubernetes workloads, all EC2 or serverless (Lambda).",
    "We have Terraform for infrastructure but not all resources are tracked.",
    "PCI scope applies to the payment endpoints only.",
    "We rely on AWS Trusted Advisor for rightsizing recommendations.",
    "Sustainability isn't formally tracked but we use spot instances.",
    "No formal energy efficiency targets defined.",
    "We use Checkov in CI for IaC scanning.",
    "Read replicas are not deployed yet.",
    "We have basic alerting via CloudWatch alarms.",
    "Our API is REST, horizontally scaled, no circuit breaker.",
    "We're aware of the rate-limit gap and it's on the backlog.",
    "Data classification is informal — PII is not formally catalogued.",
    "Encryption at rest is enabled on RDS and S3.",
    "No formal threat modelling has been done.",
    "We use SQS for async workloads, no DLQ configured.",
    "Monthly security reviews but no penetration testing scheduled.",
]


def run_session(name: str, workload_desc: str, output_dir="."):
    print(f"\n{'='*60}")
    print(f"Task 2 — Starting session: {name}")
    print(f"{'='*60}")

    # Start session
    r = requests.post(f"{BASE}/api/chat/start", timeout=10)
    r.raise_for_status()
    data = r.json()
    session_id = data["session_id"]
    first_q = data["response"]
    print(f"  Session ID : {session_id}")
    print(f"  First Q    : {first_q[:80]}...")

    log = {
        "session_id": session_id,
        "workload_name": name,
        "workload_description": workload_desc,
        "qa_pairs": [],
        "pillar_scores": None,
    }

    # Send workload description as first answer
    answers_remaining = list(SIMULATED_ANSWERS)
    current_question = first_q
    turn = 0

    while True:
        if turn == 0:
            user_msg = workload_desc
        elif answers_remaining:
            user_msg = answers_remaining.pop(0)
        else:
            user_msg = "We follow AWS best practices where documented."

        t0 = time.perf_counter()
        resp = requests.post(f"{BASE}/api/chat/message", json={
            "session_id": session_id,
            "message": user_msg
        }, timeout=30)
        latency_ms = (time.perf_counter() - t0) * 1000

        resp.raise_for_status()
        rdata = resp.json()

        log["qa_pairs"].append({
            "turn": turn,
            "question": current_question,
            "answer": user_msg,
            "llm_response": rdata["response"],
            "progress": rdata.get("progress", 0),
            "latency_ms": round(latency_ms, 1),
        })

        current_question = rdata["response"]
        print(f"  Turn {turn:02d} [{rdata.get('progress',0):.0f}%] → {rdata['response'][:60]}...")
        turn += 1

        if rdata.get("finished"):
            log["completed"] = True
            log["final_response"] = rdata["response"]
            print(f"\n  ✅  Session complete after {turn} turns.")
            break

        if turn > 30:
            print("  ⚠️  Safety break at 30 turns.")
            break

    # Save log
    log_path = os.path.join(output_dir, f"task2_{name}_log.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
    print(f"  📄  Log saved → {log_path}")

    # Download PDF
    pdf_url = f"{BASE}/api/report/pdf?session_id={session_id}"
    pdf_path = os.path.join(output_dir, f"task2_{name}.pdf")
    try:
        pr = requests.get(pdf_url, timeout=30)
        if pr.status_code == 200 and pr.headers.get("content-type","").startswith("application/pdf"):
            with open(pdf_path, "wb") as f:
                f.write(pr.content)
            print(f"  📄  PDF saved  → {pdf_path}")
        else:
            print(f"  ⚠️  PDF not available (status {pr.status_code})")
    except Exception as e:
        print(f"  ⚠️  PDF download failed: {e}")

    return log


def task4_timing():
    print(f"\n{'='*60}")
    print("Task 4 — Performance Timing Verification")
    print(f"{'='*60}")

    results = {}

    # ── Metric 1: LLM TTFT (5 runs) ──────────────────────────────────────────
    print("\n[1/5] LLM TTFT — 5 runs via /api/chat/message")
    ttft_times = []
    sess = requests.post(f"{BASE}/api/chat/start", timeout=10).json()
    sid = sess["session_id"]
    # Seed with workload first
    requests.post(f"{BASE}/api/chat/message", json={"session_id": sid, "message": "Microservices e-commerce app on AWS EKS."}, timeout=30)

    for i in range(5):
        t0 = time.perf_counter()
        r = requests.post(f"{BASE}/api/chat/message", json={
            "session_id": sid,
            "message": f"We use standard AWS security controls. Run {i+1}."
        }, timeout=30)
        ms = (time.perf_counter() - t0) * 1000
        ttft_times.append(round(ms, 0))
        print(f"  Run {i+1}: {ms:.0f} ms")
        if r.json().get("finished"):
            break
    results["LLM TTFT"] = ttft_times

    # ── Metric 2: DAST Ingestion 100 findings (5 runs) ───────────────────────
    import assessment_engine.task3_ingestion as t3
    batch_zap     = t3.zap_fixture(25)
    batch_prowler = t3.prowler_fixture(30)
    batch_checkov = t3.checkov_fixture(25)
    batch_trivy   = t3.trivy_fixture(20)

    from assessment_engine.dast_parsers import ZAPParser, ProwlerParser, CheckovParser, GenericParser
    from assessment_engine.dast_models import ScannerSource
    from assessment_engine.prioritization import PrioritizationEngine

    print("\n[2/5] DAST Ingestion 100 findings — 5 runs")
    dast_times = []
    for i in range(5):
        t0 = time.perf_counter()
        combined = []
        combined.extend(ZAPParser().parse(batch_zap, "zap.json"))
        combined.extend(ProwlerParser().parse(batch_prowler, "prowler.json"))
        combined.extend(CheckovParser().parse(batch_checkov, "checkov.json"))
        combined.extend(GenericParser().parse(batch_trivy, "trivy.json", scanner_source=ScannerSource.TRIVY))
        PrioritizationEngine.prioritize_findings(combined)
        ms = (time.perf_counter() - t0) * 1000
        dast_times.append(round(ms, 0))
        print(f"  Run {i+1}: {ms:.0f} ms  ({len(combined)} findings)")
    results["DAST ingestion 100"] = dast_times

    # ── Metric 3: RAG Query (5 runs) ──────────────────────────────────────────
    print("\n[3/5] RAG Query — 5 runs (skipped if no API key / no RAG docs)")
    rag_times = []
    for i in range(5):
        t0 = time.perf_counter()
        try:
            r = requests.post(f"{BASE}/api/v1/rag/chat",
                              headers={"x-api-key": "dev-key-not-configured"},
                              json={"query": "What is the best practice for S3 bucket security?"},
                              timeout=20)
            ms = (time.perf_counter() - t0) * 1000
        except Exception:
            ms = -1
        rag_times.append(round(ms, 0))
        print(f"  Run {i+1}: {ms:.0f} ms")
    results["RAG query"] = rag_times

    # ── Metric 4: PDF Report Generation (5 runs) ─────────────────────────────
    print("\n[4/5] PDF Report Generation — 5 runs")
    pdf_times = []
    # Use any completed session: run a quick dummy session
    for i in range(5):
        s = requests.post(f"{BASE}/api/chat/start", timeout=10).json()
        sid2 = s["session_id"]
        # Complete quickly
        for msg in ["Quick e-commerce app, AWS, no compliance."] + ["Fine, standard controls."] * 25:
            r2 = requests.post(f"{BASE}/api/chat/message", json={"session_id": sid2, "message": msg}, timeout=30)
            if r2.json().get("finished"):
                break
        t0 = time.perf_counter()
        try:
            pr = requests.get(f"{BASE}/api/report/pdf?session_id={sid2}", timeout=30)
            ms = (time.perf_counter() - t0) * 1000
        except Exception:
            ms = -1
        pdf_times.append(round(ms, 0))
        print(f"  Run {i+1}: {ms:.0f} ms")
    results["PDF generation"] = pdf_times

    # ── Metric 5: Full Pipeline E2E (3 runs) ─────────────────────────────────
    print("\n[5/5] Full Pipeline E2E — 3 runs")
    e2e_times = []
    for i in range(3):
        t0 = time.perf_counter()
        s = requests.post(f"{BASE}/api/chat/start", timeout=10).json()
        sid3 = s["session_id"]
        for msg in ["SaaS microservices app, AWS, PCI scope."] + ["Yes, we follow best practices."] * 25:
            r3 = requests.post(f"{BASE}/api/chat/message", json={"session_id": sid3, "message": msg}, timeout=30)
            if r3.json().get("finished"):
                break
        # Also run a quick DAST ingest
        combined2 = []
        combined2.extend(ZAPParser().parse(zap_fixture(10), "zap.json"))
        combined2.extend(PrioritizationEngine.prioritize_findings(combined2) or [])
        ms = (time.perf_counter() - t0) * 1000
        e2e_times.append(round(ms, 0))
        print(f"  Run {i+1}: {ms:.0f} ms")
    results["Full pipeline E2E"] = e2e_times

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("Task 4 — Raw Timing Results")
    print(f"{'='*60}")
    for metric, vals in results.items():
        vals_str = ", ".join([f"{v}ms" for v in vals])
        print(f"  {metric:<28}: {vals_str}")

    # Save results
    with open("task4_timing.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n  📄  Results saved → task4_timing.json")


def zap_fixture(n):
    import assessment_engine.task3_ingestion as t3
    return t3.zap_fixture(n)


def main():
    output_dir = "."

    # ── Task 2 ────────────────────────────────────────────────────────────────
    print("\nChecking backend availability...")
    try:
        r = requests.get(f"{BASE}/api/status", timeout=5)
        print(f"  Backend: {r.status_code} — {r.json()}")
    except Exception as e:
        print(f"  ⚠️  Backend not reachable: {e}")
        print("  Skipping Task 2 live runs. Start with: uvicorn api:app --reload")
        task4_timing()
        return

    for name, desc in WORKLOADS.items():
        run_session(name, desc, output_dir)

    # ── Task 4 ────────────────────────────────────────────────────────────────
    task4_timing()


if __name__ == "__main__":
    main()
