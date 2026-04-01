from typing import List, Dict, Optional
from .models import AssessmentSession, Question, Answer, Evidence, Pillar, Confidence, QuestionType
from .catalog import QuestionCatalog

class ConversationEngine:
    def __init__(self):
        self.catalog = QuestionCatalog()
        self.session = None

    def start_session(self) -> AssessmentSession:
        import uuid
        self.session = AssessmentSession(session_id=str(uuid.uuid4()))
        return self.session

    def get_next_question(self) -> Optional[Question]:
        if not self.session:
            return None

        # 1. Profiling Phase
        profile_questions = self.catalog.get_profile_questions()
        for q in profile_questions:
            if q.id not in self.session.answers:
                return q

        # 2. Pillar Phase
        pillars_order = [
            Pillar.SECURITY,
            Pillar.RELIABILITY,
            Pillar.OPERATIONAL_EXCELLENCE,
            Pillar.COST_OPTIMIZATION,
            Pillar.SUSTAINABILITY,
            Pillar.PERFORMANCE_EFFICIENCY
        ]

        for pillar in pillars_order:
            questions = self.catalog.get_questions_for_pillar(pillar)
            for q in questions:
                if q.id not in self.session.answers:
                    if self._should_skip(q):
                        continue
                    return q
        
        return None

    def _should_skip(self, question: Question) -> bool:
        # Check if question should be skipped based on previous answers
        # For now, we will ask all 5 questions per pillar to ensure full coverage
        # unless explicitly requested otherwise.
        return False

    def submit_answer(self, answer: Answer):
        if self.session:
            self.session.add_answer(answer)
