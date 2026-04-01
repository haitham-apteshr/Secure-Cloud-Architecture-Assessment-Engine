import sys
import os
sys.path.append(os.getcwd())

from assessment_engine.engine import ConversationEngine
from assessment_engine.scoring import ScoringEngine
from assessment_engine.reporting import ReportGenerator
from assessment_engine.models import Answer, QuestionType, Confidence, Evidence

def print_header(text):
    print(f"\n{'='*60}")
    print(f" {text}")
    print(f"{'='*60}\n")

def get_user_input(prompt, allowed=None):
    while True:
        val = input(f"{prompt}: ").strip()
        if not val:
            continue
        if allowed and val.lower() not in allowed:
            print(f"Invalid input. Allowed: {allowed}")
            continue
        return val

def main():
    print_header("Conversational AI Assessment Engine - Phase 1.5 (Advanced)")
    print("Initialize Workload Assessment...")
    
    engine = ConversationEngine()
    session = engine.start_session()
    
    print(f"Session ID: {session.session_id}")
    print("Starting Interview. Type 'exit' to quit at any time.\n")
    
    while True:
        question = engine.get_next_question()
        if not question:
            print("\nAssessment Complete. Generating Report...")
            break
            
        print(f"\n[?] {question.text}")
        
        answer_val = None
        
        if question.type == QuestionType.MULTIPLE_CHOICE:
            # Display options with their text
            for idx, opt in enumerate(question.options):
                print(f"  {idx + 1}. {opt.text}") # Display full text
            
            while True:
                resp = input("Select option (number): ")
                if resp.lower() == 'exit': return
                try:
                    idx = int(resp) - 1
                    if 0 <= idx < len(question.options):
                        # Store the LABEL as the value for logic/scoring uniqueness
                        answer_val = question.options[idx].label 
                        print(f"Selected: {question.options[idx].label}") # Feedback
                        break
                    print("Invalid selection.")
                except ValueError:
                    print("Please enter a number.")
                    
        elif question.type == QuestionType.BOOLEAN:
            resp = get_user_input("Yes/No (y/n)", allowed=['y', 'n', 'yes', 'no', 'exit'])
            if resp == 'exit': return
            answer_val = True if resp[0] == 'y' else False
            
        else:
            answer_val = input("Answer: ")
            if answer_val.lower() == 'exit': return

        # Evidence Collection
        # Evidence Collection
        has_evidence = input(" > Do you have evidence/links? (y/n): ")
        evidence_list = []
        if has_evidence.lower().startswith('y'):
            desc = input("   Description: ")
            link = input("   Link (optional): ")
            evidence_list.append(Evidence(description=desc, link=link or None))
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW
            
        # Submit
        answer = Answer(
            question_id=question.id,
            value=answer_val,
            confidence=conf,
            evidence=evidence_list
        )
        engine.submit_answer(answer)
    
    # Synthesis
    print_header("Synthesis & Reporting")
    scorer = ScoringEngine()
    scorer.compute_all(session, engine.catalog)
    
    reporter = ReportGenerator()
    json_path = reporter.generate_json_report(session, "assessment_report.json")
    md_path = reporter.generate_markdown_report(session, "assessment_report.md")
    
    print(f"JSON Report: {json_path}")
    print(f"Readable Report: {md_path}")
    print_header("Done")

if __name__ == "__main__":
    main()
