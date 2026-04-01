import json
import os
from .models import AssessmentSession

class ReportGenerator:
    def generate_json_report(self, session: AssessmentSession, filename: str):
        with open(filename, 'w') as f:
            f.write(session.model_dump_json(indent=2))
        return os.path.abspath(filename)

    def generate_markdown_report(self, session: AssessmentSession, filename: str):
        lines = []
        lines.append(f"# Well-Architected Assessment Report")
        lines.append(f"**Session ID:** {session.session_id}")
        lines.append(f"**Date:** {session.start_time}")
        lines.append("")
        
        lines.append("## Executive Summary")
        lines.append("| Pillar | Score | Maturity Level |")
        lines.append("|---|---|---|")
        for score in session.pillar_scores:
            lines.append(f"| {score.pillar.value} | {score.score} | {score.maturity_level} |")
        lines.append("")

        lines.append("## Key Risks & Recommendations")
        if session.recommendations:
            for rec in session.recommendations:
                lines.append(f"### [{rec.priority}] {rec.description}")
                lines.append(f"- **Pillar:** {rec.pillar.value}")
                lines.append(f"- **Effort:** {rec.effort} | **Impact:** {rec.impact}")
                lines.append(f"- **Acceptance Criteria:**")
                for ac in rec.acceptance_criteria:
                    lines.append(f"  - {ac}")
                lines.append("")
        else:
            lines.append("No critical recommendations found based on the provided answers.")

        lines.append("## Appendix: Evidence Log")
        for q_id, ans in session.answers.items():
            lines.append(f"- **{q_id}**: {ans.value} (Confidence: {ans.confidence.value})")
            if ans.evidence:
                for ev in ans.evidence:
                    lines.append(f"  - Evidence: {ev.description} ({ev.link or 'No Link'})")

        with open(filename, 'w') as f:
            f.write("\n".join(lines))
        return os.path.abspath(filename)
