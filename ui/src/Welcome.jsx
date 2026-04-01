import { Shield, Cloud, Terminal, CheckCircle } from 'lucide-react'

function Welcome({ onStartAssessment, onStartPentesting }) {
    return (
        <div className="welcome-container">
            <div className="welcome-hero">
                <Shield size={64} className="hero-icon" />
                <h1>Secure Cloud Architecture Assessment Engine</h1>
                <p className="hero-subtitle">
                    Intelligent Multi-Phase WAF Assessment & Automated Cloud Pentesting Orchestration
                </p>
            </div>

            <div className="module-grid">
                <div className="module-card">
                    <div className="card-header">
                        <CheckCircle className="card-icon blue" />
                        <h3>AWS Well-Architected Assessment</h3>
                    </div>
                    <p>
                        Conduct a deep-dive technical interview across all 6 WAF pillars.
                        Features multi-layered discovery, pillar checks, and forced trade-off resolution.
                    </p>
                    <button className="card-btn" onClick={onStartAssessment}>
                        Start WAF Interview
                    </button>
                </div>

                <div className="module-card">
                    <div className="card-header">
                        <Terminal className="card-icon indigo" />
                        <h3>Cloud Pentesting Assistant</h3>
                    </div>
                    <p>
                        Orchestrate 20+ professional security tools including Prowler, Nuclei, and ScoutSuite.
                        Unified ingestion and AI-powered remediation prioritization.
                    </p>
                    <button className="card-btn secondary" onClick={onStartPentesting}>
                        Explore Scanners
                    </button>
                </div>
            </div>

            <div className="trust-badges">
                <div className="badge">
                    <Cloud size={20} />
                    <span>Multi-Cloud Ready</span>
                </div>
                <div className="badge">
                    <Shield size={20} />
                    <span>Evidence-Based</span>
                </div>
            </div>
        </div>
    )
}

export default Welcome
