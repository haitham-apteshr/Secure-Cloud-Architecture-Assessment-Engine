"""
DAST + CSPM Parsers — CloudSecurityApp
Supported: OWASP ZAP, Burp Suite, Nuclei, Prowler (v3), Checkov, Custom
All parsers output List[UnifiedVulnerability].
"""
from abc import ABC, abstractmethod
from typing import List, Union
import json
import datetime

from .dast_models import (
    UnifiedVulnerability, ScannerSource, Severity, Confidence,
    TechnicalDetails, Classification, DiscoveryContext, AssetCriticality, Exposure,
)


class BaseParser(ABC):
    @abstractmethod
    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  DAST Parsers
# ─────────────────────────────────────────────────────────────────────────────

class ZAPParser(BaseParser):
    """OWASP ZAP JSON report parser."""

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        vulnerabilities = []
        ts = datetime.datetime.now()

        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk_code = alert.get("riskcode", "0")
                risk_desc = alert.get("riskdesc", "").lower()
                severity  = Severity.INFO
                if "critical" in risk_desc or risk_code == "4": severity = Severity.CRITICAL
                elif "high"   in risk_desc or risk_code == "3": severity = Severity.HIGH
                elif "medium" in risk_desc or risk_code == "2": severity = Severity.MEDIUM
                elif "low"    in risk_desc or risk_code == "1": severity = Severity.LOW

                conf_val   = str(alert.get("confidence", "1"))
                confidence = Confidence.TENTATIVE
                if conf_val == "3": confidence = Confidence.CERTAIN
                elif conf_val == "2": confidence = Confidence.FIRM

                for instance in alert.get("instances", []):
                    vuln = UnifiedVulnerability(
                        original_id=alert.get("pluginid", "0"),
                        scanner_source=ScannerSource.OWASP_ZAP,
                        title=alert.get("name", "Unknown Alert"),
                        description=alert.get("desc", ""),
                        severity=severity,
                        confidence=confidence,
                        technical_details=TechnicalDetails(
                            endpoint=instance.get("uri"),
                            http_method=instance.get("method"),
                            parameter=instance.get("param"),
                            payload=instance.get("attack"),
                            evidence_snippet=instance.get("evidence"),
                        ),
                        classification=Classification(
                            cwe_id=alert.get("cweid"),
                            owasp_category=f"WASC-{alert.get('wascid')}",
                        ),
                        discovery_context=DiscoveryContext(scan_timestamp=ts),
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities


class BurpParser(BaseParser):
    """Burp Suite JSON report parser."""

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        vulnerabilities = []
        ts = datetime.datetime.now()

        for issue in data.get("issues", []):
            sev_str = issue.get("severity", "").lower()
            severity = Severity.INFO
            if "high"   in sev_str: severity = Severity.HIGH
            elif "medium" in sev_str: severity = Severity.MEDIUM
            elif "low"   in sev_str: severity = Severity.LOW

            conf_str   = issue.get("confidence", "").lower()
            confidence = Confidence.TENTATIVE
            if "certain" in conf_str: confidence = Confidence.CERTAIN
            elif "firm" in conf_str:  confidence = Confidence.FIRM

            req_resp = issue.get("request_response", {})
            raw_req  = req_resp.get("request", "") if req_resp else ""
            method   = raw_req.split(" ")[0] if raw_req else None

            vuln = UnifiedVulnerability(
                original_id=issue.get("issue_type", {}).get("issue_type_id", "0"),
                scanner_source=ScannerSource.BURP_SUITE,
                title=issue.get("issue_type", {}).get("name", "Unknown Issue"),
                description=issue.get("issue_detail", "") or issue.get("issue_background", ""),
                severity=severity,
                confidence=confidence,
                technical_details=TechnicalDetails(
                    endpoint=issue.get("path"),
                    http_method=method,
                    evidence_snippet=issue.get("issue_detail"),
                ),
                discovery_context=DiscoveryContext(scan_timestamp=ts),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


class NucleiParser(BaseParser):
    """Nuclei JSONL (newline-delimited JSON) report parser."""

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        vulnerabilities = []
        ts = datetime.datetime.now()

        for line in content.strip().split("\n"):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info    = data.get("info", {})
            sev_str = info.get("severity", "").lower()
            severity = Severity.INFO
            if "critical" in sev_str: severity = Severity.CRITICAL
            elif "high"   in sev_str: severity = Severity.HIGH
            elif "medium" in sev_str: severity = Severity.MEDIUM
            elif "low"    in sev_str: severity = Severity.LOW

            clf = info.get("classification", {})
            vuln = UnifiedVulnerability(
                original_id=data.get("template", "nuclei-template"),
                scanner_source=ScannerSource.NUCLEI,
                title=info.get("name", "Nuclei Finding"),
                description=info.get("description", ""),
                severity=severity,
                confidence=Confidence.FIRM,
                technical_details=TechnicalDetails(
                    endpoint=data.get("matched-at"),
                    payload=data.get("matcher_name"),
                    evidence_snippet=str(data.get("extracted-results", "")),
                ),
                classification=Classification(
                    cwe_id=", ".join(clf.get("cwe-id", [])) if clf else None,
                    mitre_attack_id=", ".join(clf.get("cve-id", [])) if clf else None,
                ),
                discovery_context=DiscoveryContext(scan_timestamp=ts),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


# ─────────────────────────────────────────────────────────────────────────────
#  CSPM Parsers (NEW)
# ─────────────────────────────────────────────────────────────────────────────

class ProwlerParser(BaseParser):
    """
    Prowler v3 JSON output parser (Cloud Security Posture Management).
    Prowler v3 outputs a JSON array of findings.
    Each finding has: status, severity, title, description, resource_arn,
    check_id, compliance, region, etc.

    Run Prowler with: prowler aws -M json
    """

    _SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        try:
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        # Prowler v3: top-level is an array of findings
        findings = data if isinstance(data, list) else data.get("findings", [])
        vulnerabilities = []
        ts = datetime.datetime.now()

        for finding in findings:
            # Only process FAIL status (PASS findings are not vulnerabilities)
            if finding.get("status", "").upper() not in ("FAIL", "FAILED"):
                continue

            sev_str  = finding.get("severity", "medium").lower()
            severity = self._SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

            # Prowler findings are cloud config issues — treat as internet-facing
            exposure = Exposure.INTERNET_FACING if finding.get("region") else Exposure.INTERNAL

            resource_arn  = finding.get("resource_arn") or finding.get("resource_id", "")
            resource_type = finding.get("resource_type", "")
            check_id      = finding.get("check_id", "prowler-check")
            compliance    = finding.get("compliance", {})

            # Extract WAF/CIS references
            cwe_id    = None
            owasp_cat = None
            if isinstance(compliance, dict):
                cwe_ids = compliance.get("CWE", [])
                cwe_id  = cwe_ids[0] if cwe_ids else None
                owasp   = compliance.get("OWASP", [])
                owasp_cat = owasp[0] if owasp else None

            vuln = UnifiedVulnerability(
                original_id=check_id,
                scanner_source=ScannerSource.PROWLER,
                title=finding.get("check_title") or finding.get("title", check_id),
                description=(
                    finding.get("status_extended")
                    or finding.get("description", "Prowler CSPM finding.")
                ),
                severity=severity,
                confidence=Confidence.FIRM,   # Prowler checks are deterministic
                technical_details=TechnicalDetails(
                    affected_component=resource_type,
                    endpoint=resource_arn,
                    evidence_snippet=finding.get("status_extended", ""),
                ),
                classification=Classification(
                    cwe_id=cwe_id,
                    owasp_category=owasp_cat,
                    security_pillar="Security",   # All CSPM = Security pillar
                ),
                discovery_context=DiscoveryContext(
                    scan_timestamp=ts,
                    environment=finding.get("region", "cloud"),
                    exposure=exposure,
                    asset_criticality=AssetCriticality.HIGH,
                ),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


class CheckovParser(BaseParser):
    """
    Checkov JSON output parser (IaC Security — Terraform, CloudFormation, etc.).
    Checkov outputs: { "results": { "failed_checks": [...], "passed_checks": [...] } }

    Run Checkov with: checkov -d . -o json
    """

    _SEVERITY_FALLBACK = {
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
        "CRITICAL": Severity.CRITICAL,
    }

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        try:
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        # Checkov can produce a list (multiple runners) or a single object
        if isinstance(data, list):
            all_checks = []
            for runner_result in data:
                res = runner_result.get("results", {})
                all_checks.extend(res.get("failed_checks", []))
        else:
            all_checks = data.get("results", {}).get("failed_checks", [])

        vulnerabilities = []
        ts = datetime.datetime.now()

        for check in all_checks:
            check_id   = check.get("check_id", "CKV_UNKNOWN")
            check_name = check.get("check", {})
            if isinstance(check_name, dict):
                title = check_name.get("name", check_id)
            else:
                title = str(check_name) or check_id

            resource  = check.get("resource", "")
            file_path = check.get("file_path", "")
            file_line = check.get("file_line_range", [])
            guideline = check.get("guideline", "")

            # Checkov doesn't always include severity; infer from check_id prefix
            raw_sev  = check.get("severity") or ""
            severity = self._SEVERITY_FALLBACK.get(raw_sev.upper(), Severity.MEDIUM)

            endpoint = f"{file_path}:{file_line[0]}-{file_line[1]}" if file_line else file_path

            vuln = UnifiedVulnerability(
                original_id=check_id,
                scanner_source=ScannerSource.CHECKOV,
                title=f"[{check_id}] {title}",
                description=guideline or f"IaC misconfiguration: {title}",
                severity=severity,
                confidence=Confidence.CERTAIN,  # IaC checks are deterministic
                technical_details=TechnicalDetails(
                    affected_component=resource,
                    endpoint=endpoint,
                    evidence_snippet=str(check.get("check_result", {}).get("evaluated_keys", "")),
                ),
                classification=Classification(
                    security_pillar="Security",
                    owasp_category="A05:2021 Security Misconfiguration",
                ),
                discovery_context=DiscoveryContext(
                    scan_timestamp=ts,
                    environment="iac",
                    asset_criticality=AssetCriticality.HIGH,
                ),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


# ─────────────────────────────────────────────────────────────────────────────
#  Generic Custom Parser
# ─────────────────────────────────────────────────────────────────────────────

class CustomParser(BaseParser):
    """
    Generic parser for the CloudSecurityApp custom JSON format:
    { "vulnerabilities": [ { "id", "title", "description", "severity",
                              "cvss_score", "location": { "url", "method", "parameter" },
                              "cwe_ids", "owasp_category", "evidence" } ] }
    """

    def parse(self, content: Union[str, bytes], filename: str) -> List[UnifiedVulnerability]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        vulnerabilities = []
        ts = datetime.datetime.now()

        for v in data.get("vulnerabilities", []):
            sev_str = v.get("severity", "").lower()
            severity = Severity.INFO
            if "critical" in sev_str: severity = Severity.CRITICAL
            elif "high"   in sev_str: severity = Severity.HIGH
            elif "medium" in sev_str: severity = Severity.MEDIUM
            elif "low"    in sev_str: severity = Severity.LOW

            loc = v.get("location", {})

            vuln = UnifiedVulnerability(
                original_id=v.get("id", "0"),
                scanner_source=ScannerSource.CUSTOM,
                title=v.get("title", "Custom Vulnerability"),
                description=v.get("description", ""),
                severity=severity,
                confidence=Confidence.FIRM,
                cvss_score=v.get("cvss_score"),
                technical_details=TechnicalDetails(
                    endpoint=loc.get("url"),
                    http_method=loc.get("method"),
                    parameter=loc.get("parameter"),
                    evidence_snippet=str(v.get("evidence", "")),
                ),
                classification=Classification(
                    cwe_id=", ".join(v.get("cwe_ids", [])),
                    owasp_category=v.get("owasp_category"),
                ),
                discovery_context=DiscoveryContext(scan_timestamp=ts),
            )
            vulnerabilities.append(vuln)

class GenericParser(BaseParser):
    """
    Generic / fallback JSON parser for tools that output similar structures.
    Handles: ScoutSuite, CloudSploit, Amazon Inspector, StackHawk, Bright Security,
             Nikto, Arachni, Shodan, Pacu, CloudGoat, Qualys, Kube-hunter,
             Kube-bench, Kubescape, OpenVAS.
    
    Tries multiple well-known structures:
      1. List of findings at root level.
      2. { "vulnerabilities": [...] } — Custom format
      3. { "results": [...] } — Generic results
      4. { "findings": [...] } — Generic findings
      5. { "issues": [...] } — Inspector / Qualys style
      6. Flat object with title/severity
    """

    def _normalize_severity(self, sev: str) -> Severity:
        sev = (sev or "").lower()
        if "critical" in sev: return Severity.CRITICAL
        if "high" in sev:     return Severity.HIGH
        if "medium" in sev or "moderate" in sev: return Severity.MEDIUM
        if "low" in sev:      return Severity.LOW
        return Severity.INFO

    def _extract_items(self, data) -> list:
        if isinstance(data, list):
            return data
        for key in ("vulnerabilities", "findings", "results", "issues", "alerts", "checks"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Nested: e.g. { "report": { "findings": [...] } }
        for v in data.values():
            if isinstance(v, dict):
                for key in ("vulnerabilities", "findings", "results", "issues"):
                    if key in v and isinstance(v[key], list):
                        return v[key]
            elif isinstance(v, list) and len(v) > 0:
                return v
        return []

    def parse(self, content, filename: str, scanner_source: ScannerSource = ScannerSource.CUSTOM) -> list:
        try:
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        ts = datetime.datetime.now()
        items = self._extract_items(data)
        vulnerabilities = []

        for item in items:
            if not isinstance(item, dict):
                continue

            # Try to pull a title from multiple possible fields
            title = (
                item.get("title") or item.get("name") or item.get("check_name")
                or item.get("issue") or item.get("finding") or item.get("summary", "Unknown Finding")
            )
            description = (
                item.get("description") or item.get("details") or item.get("info")
                or item.get("message") or item.get("desc", "")
            )
            raw_sev = (
                item.get("severity") or item.get("risk") or item.get("level")
                or item.get("priority", "info")
            )
            endpoint = (
                item.get("endpoint") or item.get("url") or item.get("resource")
                or item.get("host") or item.get("target") or item.get("arn")
            )
            raw_id = item.get("id") or item.get("check_id") or item.get("plugin_id") or "0"

            vuln = UnifiedVulnerability(
                original_id=str(raw_id),
                scanner_source=scanner_source,
                title=str(title),
                description=str(description),
                severity=self._normalize_severity(str(raw_sev)),
                confidence=Confidence.FIRM,
                cvss_score=item.get("cvss_score") or item.get("cvss"),
                technical_details=TechnicalDetails(
                    endpoint=str(endpoint) if endpoint else None,
                    evidence_snippet=str(item.get("evidence") or item.get("proof") or ""),
                ),
                classification=Classification(
                    cwe_id=str(item.get("cwe_id") or item.get("cwe") or ""),
                    owasp_category=item.get("owasp") or item.get("owasp_category"),
                ),
                discovery_context=DiscoveryContext(scan_timestamp=ts),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities
