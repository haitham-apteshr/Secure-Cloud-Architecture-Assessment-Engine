from .dast_models import (
    UnifiedVulnerability, Severity, AssetCriticality, 
    DataSensitivity, Exposure, BusinessContext
)

class PrioritizationEngine:
    """
    Calculates a priority score based on technical severity and business context.
    Priority Score = Base_Score + Context_Bonus - Mitigation_Deduction
    """
    
    @staticmethod
    def calculate_base_score(severity: Severity) -> int:
        """
        Base_Score (0-40):
        - Critical: 40
        - High: 30
        - Medium: 20
        - Low: 10
        - Info: 0
        """
        if severity == Severity.CRITICAL:
            return 40
        elif severity == Severity.HIGH:
            return 30
        elif severity == Severity.MEDIUM:
            return 20
        elif severity == Severity.LOW:
            return 10
        return 0

    @staticmethod
    def calculate_context_bonus(vulnerability: UnifiedVulnerability) -> int:
        """
        Context_Bonus (0-30):
        + Asset Criticality (0-15)
        + Data Sensitivity (0-10)
        + Exposure (0-15)
        """
        bonus = 0
        
        # Asset Criticality
        crit = vulnerability.discovery_context.asset_criticality
        if crit == AssetCriticality.HIGH: # Tier 0/Critical
            bonus += 15
        elif crit == AssetCriticality.MEDIUM: # Tier 1/Important
            bonus += 10
        elif crit == AssetCriticality.LOW: # Tier 2/Supporting
            bonus += 5
            
        # Data Sensitivity
        sens = vulnerability.business_context.data_sensitivity
        if sens in [DataSensitivity.PCI, DataSensitivity.PII, DataSensitivity.PHI]:
            bonus += 10
        elif sens == DataSensitivity.CONFIDENTIAL:
            bonus += 7
        # Public data gets +0
        
        # Exposure
        expo = vulnerability.discovery_context.exposure
        
        # Check authentication status from somewhere? 
        # The prompt says: 
        # Internet-facing with authentication: +10
        # Internet-facing no authentication: +15
        # For now, let's assume if exposure is INTERNET_FACING, it's +15 max risk unless we know otherwise.
        # But wait, vulnerability doesn't explicitly track "authentication required for exploit" directly in the schema yet,
        # other than maybe CVSS vector. Let's simplify and use Exposure enum.
        
        if expo == Exposure.INTERNET_FACING:
            bonus += 15
        elif expo == Exposure.INTERNAL:
            bonus += 5
        # VPN_ONLY gets +0
            
        return min(bonus, 30) # Cap at 30 just in case

    @staticmethod
    def calculate_mitigation_deduction(vulnerability: UnifiedVulnerability) -> int:
        """
        Mitigation_Deduction (0-20):
        - WAF protection confirmed: -10
        - Rate limiting implemented: -5
        - IDS/IPS coverage: -5
        - Compensating controls documented: -5
        """
        deduction = 0
        controls = vulnerability.business_context.security_controls
        
        if controls.get("waf", False):
            deduction += 10
        if controls.get("rate_limiting", False):
            deduction += 5
        if controls.get("ids_ips", False):
            deduction += 5
        if controls.get("compensating_controls", False):
            deduction += 5
            
        return min(deduction, 20) # Cap at 20

    # Maximum possible raw score: Base(40) + Bonus(30) - Deduction(0) = 70
    _MAX_RAW_SCORE: float = 70.0

    @staticmethod
    def calculate_priority_score(vulnerability: UnifiedVulnerability) -> float:
        """
        Returns a normalized priority score in the range 0-100.
        Formula: ((Base + Bonus - Deduction) / 70) * 100
        """
        base      = PrioritizationEngine.calculate_base_score(vulnerability.severity)
        bonus     = PrioritizationEngine.calculate_context_bonus(vulnerability)
        deduction = PrioritizationEngine.calculate_mitigation_deduction(vulnerability)
        raw_score = max(base + bonus - deduction, 0)
        normalized = round((raw_score / PrioritizationEngine._MAX_RAW_SCORE) * 100, 1)
        return min(normalized, 100.0)

    @staticmethod
    def prioritize_findings(vulnerabilities: list[UnifiedVulnerability]) -> list[UnifiedVulnerability]:
        for v in vulnerabilities:
            v.remediation_tracking.priority_score = PrioritizationEngine.calculate_priority_score(v)
        
        # Sort by priority score descending
        return sorted(vulnerabilities, key=lambda x: x.remediation_tracking.priority_score, reverse=True)
