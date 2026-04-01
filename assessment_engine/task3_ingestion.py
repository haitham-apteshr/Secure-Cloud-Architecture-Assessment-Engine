"""
SCAAE — Task 3: Multi-Scanner Ingestion Log
Generates minimal valid JSON fixtures for ZAP, Prowler, Checkov, Trivy (GenericParser).
Measures per-scanner ingestion time and runs a 100-finding batch pipeline.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assessment_engine.dast_parsers import ZAPParser, ProwlerParser, CheckovParser, GenericParser
from assessment_engine.dast_models import ScannerSource
from assessment_engine.prioritization import PrioritizationEngine

# ── Minimal valid fixture generators ─────────────────────────────────────────

def zap_fixture(n: int) -> bytes:
    alerts = []
    for i in range(n):
        risk_code = ["1","2","3","3"][i % 4]
        risk_desc = ["Low","Medium","High","High"][i % 4]
        alerts.append({
            "pluginid": str(10000 + i),
            "name": f"ZAP Finding {i+1}",
            "desc": f"Description for ZAP finding {i+1}.",
            "riskcode": risk_code,
            "riskdesc": risk_desc,
            "confidence": "2",
            "wascid": "1",
            "cweid": "79",
            "instances": [{"uri": f"https://example.com/path{i}", "method": "GET", "param": "q", "attack": "", "evidence": ""}]
        })
    return json.dumps({"site": [{"@name": "https://example.com", "alerts": alerts}]}).encode()


def prowler_fixture(n: int) -> bytes:
    findings = []
    sevs = ["high", "medium", "low", "medium"]
    for i in range(n):
        findings.append({
            "status": "FAIL",
            "check_id": f"prowler_check_{i:04d}",
            "check_title": f"Prowler Finding {i+1}",
            "severity": sevs[i % 4],
            "status_extended": f"Resource arn:aws:s3:::bucket-{i} failed check.",
            "resource_arn": f"arn:aws:s3:::bucket-{i}",
            "resource_type": "AWS::S3::Bucket",
            "region": "us-east-1",
            "compliance": {}
        })
    return json.dumps(findings).encode()


def checkov_fixture(n: int) -> bytes:
    checks = []
    sevs = ["HIGH","MEDIUM","LOW","HIGH"]
    for i in range(n):
        checks.append({
            "check_id": f"CKV_AWS_{100+i}",
            "check": {"name": f"Ensure resource {i} is compliant"},
            "resource": f"aws_s3_bucket.bucket_{i}",
            "file_path": f"/terraform/main.tf",
            "file_line_range": [10*i+1, 10*i+5],
            "severity": sevs[i % 4],
            "guideline": f"https://docs.bridgecrew.io/docs/bc_aws_{100+i}",
            "check_result": {"result": "failed", "evaluated_keys": [f"acl"]}
        })
    return json.dumps({"results": {"failed_checks": checks, "passed_checks": []}}).encode()


def trivy_fixture(n: int) -> bytes:
    """Trivy uses GenericParser — output a list of findings."""
    findings = []
    sevs = ["HIGH","MEDIUM","LOW","CRITICAL"]
    for i in range(n):
        findings.append({
            "id": f"CVE-2024-{1000+i}",
            "title": f"Trivy Finding {i+1}",
            "description": f"Vulnerability in package-{i} detected by Trivy.",
            "severity": sevs[i % 4],
            "resource": f"nginx:1.21.{i%10}",
            "cvss_score": round(5.0 + (i % 5) * 0.8, 1),
            "cwe_id": "CWE-78",
        })
    return json.dumps({"findings": findings}).encode()


# ── Per-scanner measurements ──────────────────────────────────────────────────

def measure(parser_cls, fixture_bytes, name, scanner_source=None):
    parser = parser_cls()
    start = time.perf_counter()
    if scanner_source:
        results = parser.parse(fixture_bytes, "test.json", scanner_source=scanner_source)
    else:
        results = parser.parse(fixture_bytes, "test.json")
    elapsed_ms = (time.perf_counter() - start) * 1000
    return results, elapsed_ms


COUNTS = {"ZAP": 20, "Prowler": 25, "Checkov": 20, "Trivy": 20}

def main():
    print("=" * 65)
    print("Task 3 — Multi-Scanner Ingestion Log")
    print("=" * 65)

    # fmt: off
    scanners = [
        ("ZAP",     ZAPParser,     zap_fixture(COUNTS["ZAP"]),         None),
        ("Prowler",  ProwlerParser, prowler_fixture(COUNTS["Prowler"]), None),
        ("Checkov",  CheckovParser, checkov_fixture(COUNTS["Checkov"]), None),
        ("Trivy",    GenericParser, trivy_fixture(COUNTS["Trivy"]),     ScannerSource.TRIVY),
    ]
    # fmt: on

    print(f"\n{'Scanner':<10} {'In':>5} {'Normalised':>12} {'Time (ms)':>12} {'GenericParser Fallback'}")
    print("-" * 65)
    all_normalised = []

    for name, cls, fixture, src in scanners:
        vulns, ms = measure(cls, fixture, name, scanner_source=src)
        fallback = "YES" if src is not None else "no"
        print(f"{name:<10} {COUNTS[name]:>5} {len(vulns):>12} {ms:>11.1f}  {fallback}")
        all_normalised.extend(vulns)

    # ── 100-finding batch: ingest + normalise + prioritise ───────────────────
    print("\n" + "=" * 65)
    print("100-Finding Full-Pipeline Batch Test")
    print("=" * 65)

    # Build batch: mix from all scanners (proportional)
    batch_bytes = {
        "ZAP":     zap_fixture(25),
        "Prowler":  prowler_fixture(30),
        "Checkov":  checkov_fixture(25),
        "Trivy":    trivy_fixture(20),
    }

    start_batch = time.perf_counter()

    combined = []
    combined.extend(ZAPParser().parse(batch_bytes["ZAP"], "zap.json"))
    combined.extend(ProwlerParser().parse(batch_bytes["Prowler"], "prowler.json"))
    combined.extend(CheckovParser().parse(batch_bytes["Checkov"], "checkov.json"))
    combined.extend(GenericParser().parse(batch_bytes["Trivy"], "trivy.json", scanner_source=ScannerSource.TRIVY))

    prioritised = PrioritizationEngine.prioritize_findings(combined)

    total_ms = (time.perf_counter() - start_batch) * 1000

    print(f"\n  Findings ingested : {len(combined)}")
    print(f"  Findings prioritised: {len(prioritised)}")
    print(f"  Total wall-clock time: {total_ms:.1f} ms")
    print(f"\n  ✅  100-finding batch: {total_ms:.0f} ms")


if __name__ == "__main__":
    main()
