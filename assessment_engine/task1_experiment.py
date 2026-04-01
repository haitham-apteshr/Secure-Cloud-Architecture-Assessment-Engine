"""
SCAAE — Task 1: Prioritization Sensitivity Experiment
Produces CSV + Spearman rho for IEEE TCC paper Section V.

Per-finding context variation is the KEY:
  Each finding has its own inherent context (asset criticality, exposure, data sensitivity).
  Profile A ignores context (severity-only baseline — simulates existing tools).
  Profile B amplifies context (high-criticality deployment — PCI fintech app).
  Profile C applies mitigations (low-risk internal tool with WAF + rate limiting).
  The variation in per-finding attributes causes genuine rank shifts between profiles.
"""
import csv
import copy
import scipy.stats

# ── Direct model usage (avoids relative import issues when run standalone) ────
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assessment_engine.dast_models import (
    UnifiedVulnerability, Severity, Confidence, ScannerSource,
    DiscoveryContext, BusinessContext, AssetCriticality, Exposure, DataSensitivity,
    RemediationTracking
)
from assessment_engine.prioritization import PrioritizationEngine

# ── 25 findings with intentionally varied per-finding context attributes ──────
FINDINGS_SPEC = [
    # (id, title, severity, scanner, asset_crit, exposure, data_sens, waf, rate_limit)
    # CRITICAL ×4
    ("F001", "SQL Injection — Checkout Endpoint",          Severity.CRITICAL, ScannerSource.OWASP_ZAP,        AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PCI,         False, False),
    ("F002", "Remote Code Execution — Image Upload",       Severity.CRITICAL, ScannerSource.OWASP_ZAP,        AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PII,         False, False),
    ("F003", "EC2 Instance with Public AMI — No Auth",     Severity.CRITICAL, ScannerSource.AMAZON_INSPECTOR, AssetCriticality.MEDIUM, Exposure.INTERNET_FACING, DataSensitivity.CONFIDENTIAL, True,  False),
    ("F004", "Unpatched Log4Shell — Internal Service",     Severity.CRITICAL, ScannerSource.AMAZON_INSPECTOR, AssetCriticality.LOW,    Exposure.INTERNAL,        DataSensitivity.PUBLIC,      False, False),
    # HIGH ×8
    ("F005", "Insecure Direct Object Reference (IDOR)",    Severity.HIGH,     ScannerSource.PROWLER,          AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PII,         False, True),
    ("F006", "S3 Bucket Public Read — Customer Data",      Severity.HIGH,     ScannerSource.PROWLER,          AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PCI,         False, False),
    ("F007", "MFA Disabled — Privileged IAM Account",      Severity.HIGH,     ScannerSource.PROWLER,          AssetCriticality.MEDIUM, Exposure.INTERNAL,        DataSensitivity.CONFIDENTIAL, False, False),
    ("F008", "Stored XSS — Product Review Form",           Severity.HIGH,     ScannerSource.OWASP_ZAP,        AssetCriticality.MEDIUM, Exposure.INTERNET_FACING, DataSensitivity.PUBLIC,      True,  False),
    ("F009", "SSRF — Metadata Endpoint Accessible",        Severity.HIGH,     ScannerSource.OWASP_ZAP,        AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PCI,         False, False),
    ("F010", "CVE-2023-44487 (HTTP/2 Rapid Reset)",        Severity.HIGH,     ScannerSource.NUCLEI,           AssetCriticality.LOW,    Exposure.INTERNAL,        DataSensitivity.PUBLIC,      False, True),
    ("F011", "Container Image — Critical OS Vulns",        Severity.HIGH,     ScannerSource.NUCLEI,           AssetCriticality.MEDIUM, Exposure.INTERNAL,        DataSensitivity.CONFIDENTIAL, False, False),
    ("F012", "Trivy: alpine:3.15 — 12 High CVEs",          Severity.HIGH,     ScannerSource.TRIVY,            AssetCriticality.LOW,    Exposure.VPN_ONLY,        DataSensitivity.PUBLIC,      False, False),
    # MEDIUM ×9
    ("F013", "HTTP Security Headers Missing (HSTS)",       Severity.MEDIUM,   ScannerSource.CHECKOV,          AssetCriticality.LOW,    Exposure.INTERNET_FACING, DataSensitivity.PUBLIC,      True,  True),
    ("F014", "CloudTrail Logging Disabled — us-east-1",    Severity.MEDIUM,   ScannerSource.CHECKOV,          AssetCriticality.HIGH,   Exposure.INTERNAL,        DataSensitivity.PCI,         False, False),
    ("F015", "Terraform: SG Allows 0.0.0.0/0 on Port 22", Severity.MEDIUM,   ScannerSource.CHECKOV,          AssetCriticality.MEDIUM, Exposure.INTERNET_FACING, DataSensitivity.CONFIDENTIAL, False, False),
    ("F016", "IMDSv1 Enabled on Production EC2",           Severity.MEDIUM,   ScannerSource.PROWLER,          AssetCriticality.HIGH,   Exposure.INTERNAL,        DataSensitivity.PCI,         False, False),
    ("F017", "Lambda: No Dead-Letter Queue Configured",    Severity.MEDIUM,   ScannerSource.PROWLER,          AssetCriticality.LOW,    Exposure.INTERNAL,        DataSensitivity.PUBLIC,      False, False),
    ("F018", "Reflected XSS — Search Parameter",           Severity.MEDIUM,   ScannerSource.OWASP_ZAP,        AssetCriticality.MEDIUM, Exposure.INTERNET_FACING, DataSensitivity.PUBLIC,      True,  True),
    ("F019", "Weak TLS 1.0 Supported — API Gateway",      Severity.MEDIUM,   ScannerSource.OWASP_ZAP,        AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PCI,         False, False),
    ("F020", "Unencrypted EBS Volume — DB Replica",        Severity.MEDIUM,   ScannerSource.TRIVY,            AssetCriticality.MEDIUM, Exposure.INTERNAL,        DataSensitivity.PII,         False, False),
    ("F021", "Docker Image Running as Root",               Severity.MEDIUM,   ScannerSource.TRIVY,            AssetCriticality.LOW,    Exposure.VPN_ONLY,        DataSensitivity.PUBLIC,      False, False),
    # LOW ×4
    ("F022", "Missing Resource Tags — Cost Allocation",   Severity.LOW,      ScannerSource.CHECKOV,          AssetCriticality.LOW,    Exposure.INTERNAL,        DataSensitivity.PUBLIC,      False, False),
    ("F023", "Verbose Error Messages Exposed",             Severity.LOW,      ScannerSource.CHECKOV,          AssetCriticality.HIGH,   Exposure.INTERNET_FACING, DataSensitivity.PCI,         False, True),
    ("F024", "Inspector: Outdated aws-cli in Dev Image",  Severity.LOW,      ScannerSource.AMAZON_INSPECTOR, AssetCriticality.LOW,    Exposure.VPN_ONLY,        DataSensitivity.PUBLIC,      False, False),
    ("F025", "Trivy: curl 7.68 — Informational CVE",      Severity.LOW,      ScannerSource.TRIVY,            AssetCriticality.MEDIUM, Exposure.VPN_ONLY,        DataSensitivity.PUBLIC,      False, False),
]


def make_vuln(spec, profile: str) -> UnifiedVulnerability:
    fid, title, severity, scanner, asset_crit, exposure, data_sens, waf, rate_limit = spec
    v = UnifiedVulnerability(
        original_id=fid,
        scanner_source=scanner,
        title=title,
        description=f"Auto-generated for Task 1 evaluation. ID={fid}.",
        severity=severity,
        confidence=Confidence.CERTAIN,
    )
    v.id = fid

    dc = DiscoveryContext()
    bc = BusinessContext()

    if profile == "A":
        # Baseline — severity only. Override all context to zero contribution.
        dc.asset_criticality = AssetCriticality.LOW   # +5
        dc.exposure          = Exposure.VPN_ONLY       # +0
        bc.data_sensitivity  = DataSensitivity.PUBLIC  # +0
        bc.security_controls = {}                      # no deduction
        # Net context = 5 for ALL findings.  The only differentiator is severity.
        # We further zero it by treating profile A purely by base score.
        # Simpler: just set everything to lowest possible so bonus ≈ 0.
        dc.asset_criticality = AssetCriticality.LOW    # +5
        dc.exposure          = Exposure.VPN_ONLY        # +0
        bc.data_sensitivity  = DataSensitivity.PUBLIC   # +0
        bc.security_controls = {}

    elif profile == "B":
        # High-criticality: global scale-up — each finding's own context is honoured.
        # The PrioritizationEngine reads from discovery_context / business_context.
        dc.asset_criticality = asset_crit
        dc.exposure          = exposure
        bc.data_sensitivity  = data_sens
        bc.security_controls = {}  # No mitigations assumed in worst-case fintech scenario

    elif profile == "C":
        # Low-criticality with controls in place.
        dc.asset_criticality = asset_crit
        dc.exposure          = Exposure.VPN_ONLY       # Push everything behind VPN
        bc.data_sensitivity  = DataSensitivity.PUBLIC  # Conservative treatment
        bc.security_controls = {
            "waf":          waf,
            "rate_limiting": rate_limit,
        }

    v.discovery_context = dc
    v.business_context  = bc
    return v


def rank_list(scored: list, key: str) -> dict:
    """Return {finding_id: rank} with rank 1 = highest score."""
    sorted_items = sorted(scored, key=lambda x: x[key], reverse=True)
    ranks = {}
    for i, item in enumerate(sorted_items):
        ranks[item["finding_id"]] = i + 1
    return ranks


def main():
    results = {}

    for profile in ["A", "B", "C"]:
        scored_profile = []
        for spec in FINDINGS_SPEC:
            v     = make_vuln(spec, profile)
            score = PrioritizationEngine.calculate_priority_score(v)
            scored_profile.append({"finding_id": spec[0], f"score_{profile}": round(score, 1)})
        results[profile] = scored_profile

    # Merge into rows indexed by finding_id
    rows = {}
    for spec in FINDINGS_SPEC:
        fid = spec[0]
        rows[fid] = {
            "finding_id": fid,
            "title":      spec[1],
            "severity":   spec[2].value,
            "scanner":    spec[3].value,
        }

    for profile in ["A", "B", "C"]:
        rank_map = rank_list(results[profile], f"score_{profile}")
        for item in results[profile]:
            fid = item["finding_id"]
            rows[fid][f"score_{profile}"] = item[f"score_{profile}"]
            rows[fid][f"rank_{profile}"]  = rank_map[fid]

    all_rows = [rows[spec[0]] for spec in FINDINGS_SPEC]

    # Write CSV
    fieldnames = ["finding_id","title","severity","scanner",
                  "score_A","rank_A","score_B","rank_B","score_C","rank_C"]
    with open("task1_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print("✅  CSV written → task1_results.csv")

    # Spearman correlations
    ranks_a = [rows[spec[0]]["rank_A"] for spec in FINDINGS_SPEC]
    ranks_b = [rows[spec[0]]["rank_B"] for spec in FINDINGS_SPEC]
    ranks_c = [rows[spec[0]]["rank_C"] for spec in FINDINGS_SPEC]

    rho_ab, p_ab = scipy.stats.spearmanr(ranks_a, ranks_b)
    rho_ac, p_ac = scipy.stats.spearmanr(ranks_a, ranks_c)

    print("\n─── Spearman Correlations ───────────────────────────────")
    print(f"  ρ (Rank_A vs Rank_B) : {rho_ab:.4f}  (p = {p_ab:.4f})")
    print(f"  ρ (Rank_A vs Rank_C) : {rho_ac:.4f}  (p = {p_ac:.4f})")

    # Top-5 rank shifts A → B
    for row in all_rows:
        row["delta_AB"] = abs(row["rank_A"] - row["rank_B"])

    top5 = sorted(all_rows, key=lambda x: x["delta_AB"], reverse=True)[:5]
    print("\n─── Top 5 Rank Shifts  (Profile A → Profile B) ─────────")
    print(f"{'Title':<45} {'Sev':<10} {'rank_A':>6} {'rank_B':>6} {'Δ':>5}")
    print("─" * 75)
    for r in top5:
        print(f"{r['title']:<45} {r['severity']:<10} {r['rank_A']:>6} {r['rank_B']:>6} {r['delta_AB']:>5}")


if __name__ == "__main__":
    main()
