"""
Questionnaire data models.

Defines question types, answer validation, and questionnaire workflows.
"""
from typing import Dict, Any, List, Optional, Union, Callable
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


class QuestionType(str, Enum):
    """Supported question types."""
    TEXT = "text"
    CHOICE = "choice"
    MULTI_CHOICE = "multi_choice"
    BOOLEAN = "boolean"
    NUMBER = "number"
    EMAIL = "email"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class AnswerValidation(BaseModel):
    """Validation rules for answers."""
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None  # Regex pattern
    allowed_values: Optional[List[str]] = None


class Question(BaseModel):
    """A single question in a questionnaire."""
    id: str = Field(..., description="Unique question identifier")
    text: str = Field(..., description="Question text")
    type: QuestionType = Field(..., description="Question type")
    description: Optional[str] = None
    validation: AnswerValidation = Field(default_factory=AnswerValidation)
    choices: Optional[List[str]] = None  # For choice and multi_choice types
    conditional: Optional[Dict[str, Any]] = None  # Conditions to show this question
    next_question: Optional[str] = None  # ID of next question (linear flow)
    branching: Optional[Dict[str, str]] = None  # {answer: next_question_id} for branching
    help_text: Optional[str] = None
    default_value: Optional[Union[str, int, bool, List[str]]] = None


class Answer(BaseModel):
    """A user's answer to a question."""
    question_id: str
    value: Union[str, int, bool, List[str]]
    confidence: Optional[float] = None  # 0.0-1.0, user's confidence in answer
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Questionnaire(BaseModel):
    """A complete questionnaire workflow."""
    id: str = Field(..., description="Unique questionnaire identifier")
    name: str = Field(..., description="Human-readable name")
    description: Optional[str] = None
    version: str = Field(default="1.0")
    questions: List[Question] = Field(..., description="List of questions")
    start_question_id: str = Field(..., description="ID of first question")
    category: Optional[str] = None  # threat_intel, investigation, reconnaissance, etc.
    tags: List[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class QuestionnaireResponse(BaseModel):
    """User's complete response to a questionnaire."""
    id: str = Field(default_factory=lambda: str(__import__("uuid").uuid4()))
    questionnaire_id: str
    answers: List[Answer] = Field(default_factory=list)
    completed: bool = False
    completion_time_seconds: Optional[float] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class QueryGenerationResult(BaseModel):
    """Result of converting questionnaire answers to API queries."""
    extracted_indicators: List[Dict[str, str]] = Field(
        default_factory=list,
        description="List of {type, value} indicators to query"
    )
    recommended_apis: List[str] = Field(
        default_factory=list,
        description="APIs recommended based on indicators"
    )
    search_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Context for searches (scope, timeframe, etc.)"
    )
    priority: Optional[str] = None  # high, medium, low


class InvestigationContext(BaseModel):
    """Context for an investigation from questionnaire responses."""
    target_type: str  # ip, domain, email, hash, etc.
    target_value: str
    investigation_type: str  # threat_assessment, compliance_check, reconnaissance, etc.
    scope: Optional[str] = None  # internal, external, both
    timeframe: Optional[str] = None  # past_24h, past_week, past_month, all_time
    severity: Optional[str] = None  # low, medium, high, critical
    jurisdictions: Optional[List[str]] = None  # Countries/regions of interest
    custom_context: Dict[str, Any] = Field(default_factory=dict)
