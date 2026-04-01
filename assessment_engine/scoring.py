from typing import List
from .models import AssessmentSession, Pillar, PillarScore, Recommendation, ComplianceGap, QuestionType, QuestionOption

class ScoringEngine:
    def compute_all(self, session: AssessmentSession, catalog):
        
        pillar_data = {p: {"total": 0, "count": 0} for p in Pillar}
        
        # Iterate all answers
        for q_id, ans in session.answers.items():
            # Find question in catalog
            question = None
            # Search profile
            for q in catalog.get_profile_questions():
                if q.id == q_id: question = q
            
            # Search pillars
            if not question:
                for p in Pillar:
                    for q in catalog.get_questions_for_pillar(p):
                        if q.id == q_id: question = q
            
            if question:
                score = self._score_answer(ans, question)
                # Only count score if it's not strictly 0 (0 might mean informational or skipped)
                # But typically 0 is a valid score for "bad".
                # However, for Profiling questions (score=0), we don't want to dilute other pillars (if they were assigned to one).
                # In the new catalog, Q1-Q8 are Pillar.PROFILING. We might ignore them for pillar scores except where they map?
                # The Profile questions have score=0 mostly, except Q2 (Criticality) and Q7 (Frequency) where I added scores.
                # Let's count them if the pillar matches.
                
                if question.pillar in pillar_data:
                    pillar_data[question.pillar]["total"] += score
                    pillar_data[question.pillar]["count"] += 1

        # Create PillarResult objects
        results = []
        for pillar, data in pillar_data.items():
            if data["count"] > 0:
                avg = data["total"] / data["count"]
                results.append(PillarScore(
                    pillar=pillar,
                    score=round(avg, 2),
                    rationale=f"Based on {data['count']} answers.",
                    maturity_level=self._get_maturity_label(avg)
                ))
            else:
                 # Don't output score for pillars with no questions answered (e.g. Profiling if we ignore it, or PERF if skipped)
                 if pillar != Pillar.PROFILING: # We might want to see Profiling score if it exists
                     results.append(PillarScore(
                        pillar=pillar,
                        score=0.0,
                        rationale="No data collected.",
                        maturity_level="Unknown"
                    ))
        
        session.pillar_scores = results
        
        # Generate Recommendations
        self._generate_recommendations(session, catalog)

    def _score_answer(self, answer, question):
        if question.type == QuestionType.BOOLEAN:
            return 5.0 if answer.value else 1.0
        
        if question.type == QuestionType.MULTIPLE_CHOICE:
            # answer.value is the stored value.
            # In main.py, we should store the option label or text.
            # Let's assume we store the 'label' for stability, or 'text'.
            # I will assume we store the LABEL in the new implementation to be safe, 
            # OR we try to match both.
            val = answer.value
            if isinstance(val, str):
                for opt in question.options:
                    if opt.label == val or opt.text == val:
                        return opt.score
            
        return 0.0

    def _get_maturity_label(self, score):
        if score < 1.5: return "Ad-hoc / Initial"
        if score < 2.5: return "Baseline / Defined"
        if score < 3.5: return "Standardized / Managed"
        if score < 4.5: return "Optimized / Quantitatively Managed"
        return "Continuously Improved / Optimizing"

    def _generate_recommendations(self, session, catalog):
        # Example: SEC-002 (Least Privilege)
        # If score for SEC-002 is low (< 3), add recommendation
        ans = session.get_answer("SEC-002")
        if ans:
            # We need to calculate the score again or look it up.
            # Simplification: find the question and check score.
            q = None
            for x in catalog.get_questions_for_pillar(Pillar.SECURITY):
                if x.id == "SEC-002": q = x
            
            if q:
                sc = self._score_answer(ans, q)
                if sc < 3:
                     session.recommendations.append(Recommendation(
                        id="REC-SEC-002",
                        pillar=Pillar.SECURITY,
                        priority="High",
                        description="Implement automatd least privilege analysis and remediation.",
                        effort="High",
                        impact="Critical",
                        acceptance_criteria=["CloudQuery/Access Analyzer enabled", "Review cadence established"]
                    ))
