from assessment_engine.engine import ConversationEngine
from assessment_engine.models import Answer
from assessment_engine.scoring import ScoringEngine
from assessment_engine.reporting import ReportGenerator
import os

def verify():
    print("Verifying updated WAF assessment engine...")
    engine = ConversationEngine()
    session = engine.start_session()
    
    # Answers for the 2 profiling questions
    profiling_answers = {
        "Q1": "Critical_Prod",
        "Q2": "Cloud_Native_K8s"
    }
    
    # Generic answers for pillar questions (just to complete the session)
    # We will just pick the first option for each
    
    questions_count = 0
    while True:
        q = engine.get_next_question()
        if not q:
            break
        
        print(f"[{q.pillar.value}] Question: {q.id} - {q.text[:50]}...")
        
        if q.id in profiling_answers:
            val = profiling_answers[q.id]
        else:
            # Pick first option label
            val = q.options[0].label
            
        answer = Answer(question_id=q.id, value=val)
        engine.submit_answer(answer)
        questions_count += 1
        
    print(f"\nTotal questions answered: {questions_count}")
    
    # Expected: 2 profiling + 6 pillars * 5 q = 32 questions
    if questions_count != 32:
        print(f"FAILURE: Expected 32 questions, but got {questions_count}")
        # exit(1) # Don't exit yet, let's see what happened
    else:
        print("SUCCESS: 32 questions processed correctly.")

    # Scoring
    scorer = ScoringEngine()
    scorer.compute_all(session, engine.catalog)
    
    print("\nPillar Scores:")
    for score in session.pillar_scores:
        print(f" - {score.pillar.value}: {score.score:.1f} ({score.maturity_level})")
        
    # Reporting
    reporter = ReportGenerator()
    reporter.generate_markdown_report(session, "verification_report.md")
    
    if os.path.exists("verification_report.md"):
        print("\nSUCCESS: verification_report.md generated.")
    else:
        print("\nFAILURE: verification_report.md NOT generated.")

if __name__ == "__main__":
    verify()
