from typing import List, Optional
from .models import Question, Pillar, QuestionType, QuestionOption

class QuestionCatalog:
    def __init__(self):
        self.profile_questions = self._load_profile_questions()
        self.pillar_questions = self._load_pillar_questions()

    def get_profile_questions(self) -> List[Question]:
        return self.profile_questions

    def get_questions_for_pillar(self, pillar: Pillar) -> List[Question]:
        return self.pillar_questions.get(pillar, [])

    def _load_profile_questions(self) -> List[Question]:
        return [
            Question(
                id="Q1",
                text="What is the nature and business criticality of this workload?",
                pillar=Pillar.PROFILING,
                topic="Workload Context",
                type=QuestionType.MULTIPLE_CHOICE,
                options=[
                    QuestionOption(label="Critical_Prod", text="Mission-critical production system (e.g. Core Banking, E-commerce)", score=5),
                    QuestionOption(label="High_Internal", text="High-priority internal service (e.g. HR System, Analytics)", score=4),
                    QuestionOption(label="Medium_Dev", text="Medium-priority Development/Staging environment", score=3),
                    QuestionOption(label="Low_Lab", text="Low-priority experiment or sandbox", score=2)
                ]
            ),
            Question(
                id="Q2",
                text="What is the primary technical footprint and deployment model?",
                pillar=Pillar.PROFILING,
                topic="Cloud & Deployment",
                type=QuestionType.MULTIPLE_CHOICE,
                options=[
                    QuestionOption(label="Cloud_Native_K8s", text="Cloud-native Containers/K8s (e.g. EKS, AKS, GKE)", score=0),
                    QuestionOption(label="Serverless_FaaS", text="Serverless/Event-driven (e.g. Lambda, Azure Functions)", score=0),
                    QuestionOption(label="Traditional_VM", text="Traditional VMs with standard networking", score=0),
                    QuestionOption(label="Hybrid_Edge", text="Hybrid Cloud or Edge Computing deployment", score=0)
                ]
            )
        ]

    def _load_pillar_questions(self) -> dict:
        questions = {
            Pillar.SECURITY: [
                Question(
                    id="SEC-001",
                    text="How do workloads authenticate to cloud services?",
                    pillar=Pillar.SECURITY,
                    topic="Identity & Access",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="IAM_OIDC", text="IAM Roles with OIDC (e.g., IRSA for K8s), no static keys", score=5),
                        QuestionOption(label="ManagedID", text="Managed Identities with auto-rotation", score=5),
                        QuestionOption(label="WorkloadID", text="Workload Identity Federation", score=5),
                        QuestionOption(label="Mixed", text="Mixed: IAM Roles + Secrets Manager for external tokens", score=4),
                        QuestionOption(label="Transition", text="Transition: Some static keys in env vars/config", score=2)
                    ]
                ),
                Question(
                    id="SEC-002",
                    text="Is Least Privilege enforced via roles and policies?",
                    pillar=Pillar.SECURITY,
                    topic="Identity & Access",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Yes_Automated", text="Yes + Automated Analysis (Access Analyzer, CloudQuery)", score=5),
                        QuestionOption(label="Yes_Manual", text="Yes, distinct roles per service, manual quarterly reviews", score=4),
                        QuestionOption(label="Partial_Tools", text="Partially, using tools to identify unused permissions", score=3),
                        QuestionOption(label="Partial", text="Partially - some roles are too permissive for convenience", score=2),
                        QuestionOption(label="No", text="No - General admin access, on roadmap to fix", score=1)
                    ]
                ),
                Question(
                    id="SEC-003",
                    text="How is privileged/admin access managed?",
                    pillar=Pillar.SECURITY,
                    topic="Identity & Access",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="JIT", text="Just-In-Time (JIT) access (e.g., measured sessions, MFA)", score=5),
                        QuestionOption(label="BreakGlass", text="Break-glass accounts with multi-party approval and audit", score=5),
                        QuestionOption(label="PAM", text="PAM (Privileged Access Management) with credential rotation", score=4),
                        QuestionOption(label="Restricted", text="Restricted to few admins, logs centralized", score=3),
                        QuestionOption(label="RBAC_Only", text="Standard RBAC, no JIT or special PAM controls", score=2)
                    ]
                ),
                Question(
                    id="SEC-004",
                    text="Network Security: What edge controls are in place?",
                    pillar=Pillar.SECURITY,
                    topic="Network & Perimeter",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="WAF_Shield", text="WAF + CDN + DDoS Protection (e.g., Shield Advanced)", score=5),
                         QuestionOption(label="CloudArmor", text="Cloud Armor / Front Door with OWASP rules", score=5),
                         QuestionOption(label="Standard", text="Standard WAF and Load Balancer rules", score=4),
                         QuestionOption(label="VPN", text="Not exposed (VPN/Internal Only)", score=5),
                         QuestionOption(label="Nginx", text="Custom Nginx/Reverse Proxy rules, no managed WAF", score=2)
                    ]
                ),
                Question(
                    id="SEC-005",
                    text="How is sensitive data protected at rest and in transit?",
                    pillar=Pillar.SECURITY,
                    topic="Data Protection",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Full_Automation", text="Automated encryption (KMS/HSM) + TLS 1.3 everywhere", score=5),
                        QuestionOption(label="Managed_Encryption", text="Cloud-managed encryption (SSE-S3, EBS) + TLS 1.2+", score=4),
                        QuestionOption(label="Manual_Keys", text="Manual key management, encryption implemented", score=3),
                        QuestionOption(label="At_Rest_Only", text="Encryption at rest only, transit is internal/HTTP", score=2),
                        QuestionOption(label="None", text="No formal encryption strategy", score=1)
                    ]
                )
            ],
            Pillar.RELIABILITY: [
                Question(
                    id="REL-001",
                    text="Have you defined SLOs/SLIs and Error Budgets?",
                    pillar=Pillar.RELIABILITY,
                    topic="Resilience",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="SLO_Budget", text="Yes, SLOs defined (e.g. 99.9%) and Error Budgets enforced", score=5),
                         QuestionOption(label="SLO_Budget_Influence", text="SLOs defined, Error Budget influences backlog prioritization", score=5),
                         QuestionOption(label="SLO_NoBudget", text="SLOs defined but no Error Budget policy yet", score=3),
                         QuestionOption(label="Measured", text="Availability measured but no formal SLOs", score=2),
                         QuestionOption(label="None", text="No specific SLO/SLI practice", score=1)
                    ]
                ),
                Question(
                    id="REL-002",
                    text="What are your RTO/RPO targets and testing strategy?",
                    pillar=Pillar.RELIABILITY,
                    topic="Resilience",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="Tested_Quarterly", text="Tight targets (e.g. RTO 4h), Restore tested quarterly", score=5),
                         QuestionOption(label="Drills", text="Critical services have defined targets and semi-annual drills", score=5),
                         QuestionOption(label="Backups_Tested", text="Daily backups taken, restore tested annually", score=3),
                         QuestionOption(label="RTO_NoTests", text="Targets defined but restore process not regularly tested", score=2),
                         QuestionOption(label="Snapshots", text="Automated snapshots only, no formal RTO/RPO", score=1)
                    ]
                ),
                Question(
                    id="REL-003",
                    text="How is high availability achieved for this workload?",
                    pillar=Pillar.RELIABILITY,
                    topic="Availability",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Multi_Region", text="Active-Active Multi-Region with global routing", score=5),
                        QuestionOption(label="Multi_AZ", text="Multi-Availability Zone with automated failover", score=4),
                        QuestionOption(label="Regional_Autoscale", text="Single Region, Multi-AZ Autoscaling", score=3),
                        QuestionOption(label="Single_Inst", text="Single instance with manual restore", score=1)
                    ]
                ),
                Question(
                    id="REL-004",
                    text="How do you handle changes to infrastructure and application?",
                    pillar=Pillar.RELIABILITY,
                    topic="Change Management",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Full_Canary", text="Fully automated Canary/Blue-Green deployments with auto-rollback", score=5),
                        QuestionOption(label="Automated_Rollback", text="Automated CI/CD with health-check based rollback", score=4),
                        QuestionOption(label="Manual_Rollback", text="Automated deployment, but manual rollback via script", score=3),
                        QuestionOption(label="Manual_Only", text="Manual deployments and manual rollbacks", score=1)
                    ]
                ),
                Question(
                    id="REL-005",
                    text="How does the system handle dependency failures?",
                    pillar=Pillar.RELIABILITY,
                    topic="Dependency Management",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Resilient_Patterns", text="Circuit breakers, retries, and graceful degradation implemented", score=5),
                        QuestionOption(label="Basic_Retries", text="Basic retry logic with exponential backoff", score=3),
                        QuestionOption(label="No_Isolation", text="Failure in one component causes cascading failures", score=1)
                    ]
                )
            ],
            Pillar.OPERATIONAL_EXCELLENCE: [
                Question(
                    id="OPS-001",
                    text="Observability: What is the coverage for Metrics, Logs, and Traces?",
                    pillar=Pillar.OPERATIONAL_EXCELLENCE,
                    topic="Observability",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="FullStack_DD", text="Full Observability (Datadog/NewRelic): APM, Logs, Traces correlated", score=5),
                         QuestionOption(label="FullStack_Custom", text="Full Stack: Prometheus, Grafana, ELK, Jaeger", score=5),
                         QuestionOption(label="CloudNative", text="Cloud Native: CloudWatch/Azure Monitor + X-Ray/Insights", score=4),
                         QuestionOption(label="Basic", text="Basic Logs and Metrics, no distributed tracing", score=2),
                         QuestionOption(label="None", text="Ad-hoc logging only", score=1)
                    ]
                ),
                Question(
                    id="OPS-002",
                    text="Incident Management: Runbooks and Post-mortems?",
                    pillar=Pillar.OPERATIONAL_EXCELLENCE,
                    topic="Incident Management",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="SRE", text="Mature SRE: Automated Runbooks, Blameless Post-mortems, Error Budget tracking", score=5),
                         QuestionOption(label="Blameless", text="Documented Runbooks, Regular Blameless Post-mortems", score=5),
                         QuestionOption(label="Process_Defined", text="Defined Incident Process (Sev1-Sev4), Post-mortems for major issues", score=3),
                         QuestionOption(label="AdHoc", text="Ad-hoc response, informal post-mortems", score=2),
                         QuestionOption(label="None", text="No formal process", score=1)
                    ]
                ),
                Question(
                   id="OPS-003",
                   text="How is Infrastructure as Code (IaC) and Version Control utilized?",
                   pillar=Pillar.OPERATIONAL_EXCELLENCE,
                   topic="Governance",
                   type=QuestionType.MULTIPLE_CHOICE,
                   options=[
                        QuestionOption(label="Everything_IaC", text="100% IaC (Terraform/CDK), strict PR reviews, and drift detection", score=5),
                        QuestionOption(label="Majority_IaC", text="Majority of infra in IaC, manual changes are rare", score=4),
                        QuestionOption(label="AdHoc_Scripts", text="Combination of scripts and manual console changes", score=2),
                        QuestionOption(label="Manual", text="Primarily manual configuration (Click-ops)", score=1)
                   ]
                ),
                Question(
                   id="OPS-004",
                   text="How is the deployment process automated and verified?",
                   pillar=Pillar.OPERATIONAL_EXCELLENCE,
                   topic="Automation",
                   type=QuestionType.MULTIPLE_CHOICE,
                   options=[
                        QuestionOption(label="CI_CD_Verified", text="Fully automated CI/CD with automated testing and security scanning", score=5),
                        QuestionOption(label="CI_CD_Basic", text="Automated build and deploy, manual testing/verification", score=3),
                        QuestionOption(label="Manual_Release", text="Manual release process with some script assistance", score=2)
                   ]
                ),
                Question(
                   id="OPS-005",
                   text="How do you perform post-incident analysis and knowledge sharing?",
                   pillar=Pillar.OPERATIONAL_EXCELLENCE,
                   topic="Feedback",
                   type=QuestionType.MULTIPLE_CHOICE,
                   options=[
                        QuestionOption(label="Blameless_Wiki", text="Blameless post-mortems shared via internal wiki/knowledge base", score=5),
                        QuestionOption(label="PostMortem_Only", text="Post-mortems performed but results are not widely publicized", score=3),
                        QuestionOption(label="None", text="No formal post-incident analysis", score=1)
                   ]
                )
            ],
            Pillar.COST_OPTIMIZATION: [
                Question(
                    id="COST-001",
                    text="Cost Allocation: Tagging and Labeling Strategy?",
                    pillar=Pillar.COST_OPTIMIZATION,
                    topic="Financial Management",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="Mandatory", text="Mandatory Tags (Env, Team, CostCenter) with automated validation/enforcement", score=5),
                         QuestionOption(label="Automated_Terraform", text="Tags applied via IaC (Terraform), Monthly Showback reports", score=5),
                         QuestionOption(label="Reporting", text="Cloud/K8s tagging implemented, regular reporting", score=4),
                         QuestionOption(label="Partial", text="Partial tagging, inconsistent application", score=2),
                         QuestionOption(label="None", text="No tagging strategy, difficult to attribute costs", score=1)
                    ]
                ),
                Question(
                    id="COST-002",
                    text="Resource Management: Autoscaling and Rightsizing?",
                    pillar=Pillar.COST_OPTIMIZATION,
                    topic="Resource Management",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="Optimizer", text="Automated Rightsizing (e.g. Compute Optimizer) + Aggressive Autoscaling", score=5),
                         QuestionOption(label="K8s_HPA", text="K8s HPA + Cluster Autoscaler based on custom metrics", score=5),
                         QuestionOption(label="Serverless", text="Serverless / Managed Scaling mostly", score=4),
                         QuestionOption(label="VM_ScaleSets", text="VM Scale Sets with basic CPU/RAM scaling", score=3),
                         QuestionOption(label="Manual", text="Manual scaling, fixed capacity", score=2)
                    ]
                ),
                Question(
                    id="COST-003",
                    text="How do you leverage cloud pricing models?",
                    pillar=Pillar.COST_OPTIMIZATION,
                    topic="Financial Optimization",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Spot_Reserved", text="Aggressive use of Spot instances and Reserved Instances/Savings Plans", score=5),
                        QuestionOption(label="Savings_Plans", text="Utilization of Savings Plans for baseline compute", score=4),
                        QuestionOption(label="OnDemand_Mixed", text="Mostly On-Demand with some Reserved Instances", score=3),
                        QuestionOption(label="OnDemand_Only", text="100% On-Demand pricing", score=1)
                    ]
                ),
                Question(
                    id="COST-004",
                    text="How is cost monitored and how are anomalies handled?",
                    pillar=Pillar.COST_OPTIMIZATION,
                    topic="Monitoring",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Anomaly_Alerts", text="Real-time anomaly detection with automated alerts to team leads", score=5),
                        QuestionOption(label="Monthly_Review", text="Monthly cost analysis and review of budgets", score=3),
                        QuestionOption(label="Manual_Check", text="Ad-hoc checks of cloud billing dashboard", score=2)
                    ]
                ),
                Question(
                    id="COST-005",
                    text="How do you identify and eliminate orphaned resources/waste?",
                    pillar=Pillar.COST_OPTIMIZATION,
                    topic="Waste Reduction",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Auto_Cleanup", text="Automated scripts to delete unused volumes, IPs, and old snapshots", score=5),
                        QuestionOption(label="Regular_Audit", text="Manual quarterly audits to identify wasteful resources", score=3),
                        QuestionOption(label="None", text="No process for identifying idle or orphaned resources", score=1)
                    ]
                )
            ],
            Pillar.SUSTAINABILITY: [
                Question(
                    id="SUST-001",
                    text="Sustainability: Is Carbon Intensity considered in Region Selection?",
                    pillar=Pillar.SUSTAINABILITY,
                    topic="Region Selection",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                         QuestionOption(label="Green_Regions", text="Yes, we strictly select regions with >95% renewable energy", score=5),
                         QuestionOption(label="Carbon_Neutral", text="We use Carbon Neutral regions (e.g. GCP/Azure specific)", score=5),
                         QuestionOption(label="Prioritized", text="It is a factor in selection alongside latency and cost", score=4),
                         QuestionOption(label="Tracking", text="We track carbon footprint but do not optimize for it yet", score=3),
                         QuestionOption(label="Not_Considered", text="Not considered / focusing on other priorities", score=1)
                    ]
                ),
                Question(
                    id="SUST-002",
                    text="How do you manage hardware utilization and density?",
                    pillar=Pillar.SUSTAINABILITY,
                    topic="Efficiency",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="High_Density", text="Serverless or high-density container orchestration (>50% CPU util)", score=5),
                        QuestionOption(label="Managed_Scaling", text="Standard autoscaling to maintain moderate utilization", score=3),
                        QuestionOption(label="Overprovisioned", text="Fixed capacity with low average utilization", score=1)
                    ]
                ),
                Question(
                    id="SUST-003",
                    text="How are storage lifecycles managed for sustainability?",
                    pillar=Pillar.SUSTAINABILITY,
                    topic="Storage",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Auto_Lifecycle", text="Automated lifecycle policies (Hot -> Cold -> Delete)", score=5),
                        QuestionOption(label="Manual_Cleanup", text="Periodic manual cleanup of old data", score=3),
                        QuestionOption(label="Keep_Forever", text="No data deletion or lifecycle policy", score=1)
                    ]
                ),
                Question(
                    id="SUST-004",
                    text="What strategies are in place for network efficiency?",
                    pillar=Pillar.SUSTAINABILITY,
                    topic="Network",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Optimized_Transfer", text="CDN caching and compression (Brotli/Gzip) for all traffic", score=5),
                        QuestionOption(label="Basic_Compression", text="Basic compression enabled on load balancers", score=3),
                        QuestionOption(label="No_Optimization", text="Heavy data transfer without caching or compression", score=1)
                    ]
                ),
                Question(
                    id="SUST-005",
                    text="How is energy efficiency considered in software development?",
                    pillar=Pillar.SUSTAINABILITY,
                    topic="Development",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Efficiency_Aware", text="Optimized code (Big O), minimized polling, and async processing", score=5),
                        QuestionOption(label="Standard_Practice", text="Standard development practices without specific energy focus", score=3),
                        QuestionOption(label="Resource_Intensive", text="High-polling or CPU-intensive background tasks", score=1)
                    ]
                )
            ],
            Pillar.PERFORMANCE_EFFICIENCY: [
                Question(
                    id="PERF-001",
                    text="Do you conduct Load Testing/Stress Testing?",
                    pillar=Pillar.PERFORMANCE_EFFICIENCY,
                    topic="Performance",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Continuous", text="Continuous Load Testing in CI/CD pipeline", score=5),
                        QuestionOption(label="PreRelease", text="Load testing before every major release", score=4),
                        QuestionOption(label="AdHoc", text="Ad-hoc load testing for specific campaigns", score=3),
                        QuestionOption(label="None", text="No load testing performed", score=1)
                    ]
                ),
                Question(
                    id="PERF-002",
                    text="How do you select the appropriate compute and storage resources?",
                    pillar=Pillar.PERFORMANCE_EFFICIENCY,
                    topic="Selection",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Data_Driven", text="Selection based on benchmarking and performance profiles", score=5),
                        QuestionOption(label="Instance_Families", text="Matching workload characteristics to instance families (e.g. C7g, R7g)", score=4),
                        QuestionOption(label="Best_Guess", text="Selection based on general experience and 'safe' defaults", score=3),
                        QuestionOption(label="Fixed_Standard", text="Same instance types used for all workloads regardless of profile", score=1)
                    ]
                ),
                Question(
                    id="PERF-003",
                    text="What is your caching and content delivery strategy?",
                    pillar=Pillar.PERFORMANCE_EFFICIENCY,
                    topic="Latency",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Multi_Layer_Cache", text="Global CDN + In-memory cache (Redis/Memcached) + Browser cache", score=5),
                        QuestionOption(label="CDN_Basic", text="CDN used for static assets only", score=3),
                        QuestionOption(label="No_Caching", text="All requests hit the backend application directly", score=1)
                    ]
                ),
                Question(
                    id="PERF-004",
                    text="How is database performance optimized?",
                    pillar=Pillar.PERFORMANCE_EFFICIENCY,
                    topic="Database",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Advanced_Optim", text="Read replicas, connection pooling, and automated index analysis", score=5),
                        QuestionOption(label="Basic_Indexing", text="Standard indexing and simple vertical scaling", score=3),
                        QuestionOption(label="Manual_Optim", text="Reactive optimization only when performance degrades", score=2)
                    ]
                ),
                Question(
                    id="PERF-005",
                    text="How do you monitor and optimize network latency?",
                    pillar=Pillar.PERFORMANCE_EFFICIENCY,
                    topic="Network",
                    type=QuestionType.MULTIPLE_CHOICE,
                    options=[
                        QuestionOption(label="Global_Monitoring", text="Real User Monitoring (RUM) and latency tracking per region", score=5),
                        QuestionOption(label="Synthetic_Tests", text="Regular synthetic tests from various locations", score=4),
                        QuestionOption(label="Server_Side_Metric", text="Server-side response time monitoring only", score=3),
                        QuestionOption(label="None", text="No specific network latency monitoring", score=1)
                    ]
                )
            ]
        }
        return questions
