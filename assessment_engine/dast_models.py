from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
import datetime
import uuid

# --- Enums ---

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class Confidence(str, Enum):
    CERTAIN   = "certain"
    FIRM      = "firm"
    TENTATIVE = "tentative"

class ScannerSource(str, Enum):
    # DAST / Web Scanners
    OWASP_ZAP        = "OWASP_ZAP"
    BURP_SUITE       = "Burp_Suite"
    NUCLEI           = "Nuclei"
    NIKTO            = "Nikto"
    ARACHNI          = "Arachni"
    STACKHAWK        = "StackHawk"
    BRIGHT_SECURITY  = "Bright_Security"
    # Cloud Security / CSPM
    PROWLER          = "Prowler"
    SCOUTSUITE       = "ScoutSuite"
    CLOUDSPLOIT      = "CloudSploit"
    AMAZON_INSPECTOR = "Amazon_Inspector"
    QUALYS_CLOUD     = "Qualys_Cloud_Platform"
    # Container / Kubernetes Security
    TRIVY            = "Trivy"
    KUBE_HUNTER      = "Kube_hunter"
    KUBE_BENCH       = "Kube_bench"
    KUBESCAPE        = "Kubescape"
    # IaC / Configuration
    CHECKOV          = "Checkov"
    # Network / Recon
    OPENVAS          = "OpenVAS"
    SHODAN           = "Shodan"
    # Offensive / Red Team
    PACU             = "Pacu"
    CLOUDGOAT        = "CloudGoat"
    # Generic
    CUSTOM           = "Custom"

class AssetCriticality(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"

class Exposure(str, Enum):
    INTERNET_FACING = "internet_facing"
    INTERNAL        = "internal"
    VPN_ONLY        = "vpn_only"

class DataSensitivity(str, Enum):
    PII          = "pii"
    PCI          = "pci"
    PHI          = "phi"
    CONFIDENTIAL = "confidential"
    PUBLIC       = "public"

class RemediationStatus(str, Enum):
    NEW             = "new"
    IN_PROGRESS     = "in_progress"
    REMEDIATED      = "remediated"
    FALSE_POSITIVE  = "false_positive"
    RISK_ACCEPTED   = "risk_accepted"

# --- Component Models ---

class TechnicalDetails(BaseModel):
    affected_component: Optional[str] = None
    endpoint:           Optional[str] = None
    http_method:        Optional[str] = None
    parameter:          Optional[str] = None
    payload:            Optional[str] = None
    evidence_snippet:   Optional[str] = None
    http_status_code:   Optional[int] = None
    response_time:      Optional[int] = None

class Classification(BaseModel):
    cwe_id:            Optional[str] = None
    cwe_name:          Optional[str] = None
    owasp_category:    Optional[str] = None
    mitre_attack_id:   Optional[str] = None
    security_pillar:   Optional[str] = None

class DiscoveryContext(BaseModel):
    scan_timestamp:   datetime.datetime = Field(default_factory=datetime.datetime.now)
    environment:      Optional[str] = None
    commit_hash:      Optional[str] = None
    build_id:         Optional[str] = None
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM
    exposure:          Exposure          = Exposure.INTERNAL

class BusinessContext(BaseModel):
    data_sensitivity:  DataSensitivity = DataSensitivity.CONFIDENTIAL
    regulatory_scope:  List[str]       = Field(default_factory=list)
    service_tier:      Optional[str]   = None
    # e.g. {"waf": True, "rate_limiting": False, "ids_ips": False}
    security_controls: Dict[str, bool] = Field(default_factory=dict)

class RemediationTracking(BaseModel):
    status:         RemediationStatus = RemediationStatus.NEW
    priority_score: float             = 0.0
    assigned_to:    Optional[str]     = None
    due_date:       Optional[datetime.date] = None
    jira_ticket:    Optional[str]     = None

# --- Main Unified Vulnerability Model ---

class UnifiedVulnerability(BaseModel):
    id:              str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_id:     str
    scanner_source:  ScannerSource
    title:           str
    description:     str
    severity:        Severity
    confidence:      Confidence
    cvss_score:      Optional[float] = None
    cvss_vector:     Optional[str]   = None

    technical_details:    TechnicalDetails    = Field(default_factory=TechnicalDetails)
    classification:       Classification      = Field(default_factory=Classification)
    discovery_context:    DiscoveryContext    = Field(default_factory=DiscoveryContext)
    business_context:     BusinessContext     = Field(default_factory=BusinessContext)
    remediation_tracking: RemediationTracking = Field(default_factory=RemediationTracking)
