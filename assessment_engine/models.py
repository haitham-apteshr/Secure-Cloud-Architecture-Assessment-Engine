from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
import datetime

class Pillar(str, Enum):
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    PERFORMANCE_EFFICIENCY = "Performance Efficiency"
    COST_OPTIMIZATION = "Cost Optimization"
    SUSTAINABILITY = "Sustainability"
    PROFILING = "Profiling" # Added for Q1-Q8

class Confidence(str, Enum):
    LOW = "Low (Self-reported)"
    MEDIUM = "Medium (Some evidence)"
    HIGH = "High (Verified)"

class QuestionType(str, Enum):
    MULTIPLE_CHOICE = "multiple_choice"
    FREE_TEXT = "free_text"
    BOOLEAN = "boolean"

class Evidence(BaseModel):
    description: str
    link: Optional[str] = None
    path: Optional[str] = None

class QuestionOption(BaseModel):
    text: str
    score: float = 0.0 # Score contribution (0-5 scale usually)
    label: str # Short label for code references if needed

class Answer(BaseModel):
    question_id: str
    value: Union[str, bool, int] # Can be the option label, boolean, or text
    confidence: Confidence = Confidence.LOW
    evidence: List[Evidence] = Field(default_factory=list)
    notes: Optional[str] = None
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.now)

class Question(BaseModel):
    id: str
    text: str
    pillar: Pillar
    topic: str
    type: QuestionType
    options: List[QuestionOption] = Field(default_factory=list) # Updated to use structured options
    required: bool = True
    next_question_map: Optional[Dict[str, str]] = None 

class Recommendation(BaseModel):
    id: str
    pillar: Pillar
    priority: str 
    description: str
    effort: str
    impact: str
    acceptance_criteria: List[str]

class ComplianceGap(BaseModel):
    id: str
    pillar: Pillar
    description: str
    risk_level: str

class PillarScore(BaseModel):
    pillar: Pillar
    score: float 
    rationale: str
    maturity_level: str 

class AssessmentSession(BaseModel):
    session_id: str
    start_time: datetime.datetime = Field(default_factory=datetime.datetime.now)
    workload_profile: Dict[str, Any] = Field(default_factory=dict)
    answers: Dict[str, Answer] = Field(default_factory=dict)
    
    pillar_scores: List[PillarScore] = Field(default_factory=list)
    gaps: List[ComplianceGap] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)

    def get_answer(self, question_id: str) -> Optional[Answer]:
        return self.answers.get(question_id)

    def add_answer(self, answer: Answer):
        self.answers[answer.question_id] = answer
