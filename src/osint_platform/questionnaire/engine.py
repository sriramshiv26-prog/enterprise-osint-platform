"""
Questionnaire Engine.

Handles questionnaire logic, answer validation, query generation, and workflow orchestration.
"""
import logging
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from src.osint_platform.questionnaire.models import (
    Question, QuestionType, Questionnaire, Answer, QuestionnaireResponse,
    QueryGenerationResult, InvestigationContext, AnswerValidation,
)

logger = logging.getLogger(__name__)


class QuestionValidator:
    """Validates answers to questions."""

    @staticmethod
    def validate_answer(question: Question, value: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate an answer against question requirements.

        Returns: (is_valid, error_message)
        """
        # Check required
        if question.validation.required:
            if value is None or value == "" or (isinstance(value, list) and len(value) == 0):
                return False, "Answer is required"

        # Type-specific validation
        if question.type == QuestionType.EMAIL:
            if value and not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", str(value)):
                return False, "Invalid email format"

        elif question.type == QuestionType.IP:
            if value and not re.match(r"^\d+\.\d+\.\d+\.\d+$", str(value)):
                return False, "Invalid IP address format"

        elif question.type == QuestionType.DOMAIN:
            if value and not re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", str(value)):
                return False, "Invalid domain format"

        elif question.type == QuestionType.URL:
            if value and not re.match(r"^https?://", str(value)):
                return False, "URL must start with http:// or https://"

        elif question.type == QuestionType.HASH:
            hash_str = str(value)
            if value and len(hash_str) not in [32, 40, 64]:
                return False, "Hash must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters"
            if value and not all(c in "0123456789abcdefABCDEF" for c in hash_str):
                return False, "Hash must contain only hexadecimal characters"

        elif question.type == QuestionType.NUMBER:
            try:
                num = float(value) if value else None
            except (ValueError, TypeError):
                return False, "Must be a valid number"

        elif question.type == QuestionType.CHOICE:
            if value and question.choices and value not in question.choices:
                return False, f"Must be one of: {', '.join(question.choices)}"

        elif question.type == QuestionType.MULTI_CHOICE:
            if value and question.choices:
                if isinstance(value, list):
                    invalid = [v for v in value if v not in question.choices]
                    if invalid:
                        return False, f"Invalid choices: {', '.join(invalid)}"

        # Length validation
        if question.validation.min_length and isinstance(value, str):
            if len(value) < question.validation.min_length:
                return False, f"Minimum length is {question.validation.min_length}"

        if question.validation.max_length and isinstance(value, str):
            if len(value) > question.validation.max_length:
                return False, f"Maximum length is {question.validation.max_length}"

        # Pattern validation
        if question.validation.pattern and isinstance(value, str):
            if not re.match(question.validation.pattern, value):
                return False, f"Invalid format: {question.validation.pattern}"

        # Allowed values validation
        if question.validation.allowed_values and value:
            if value not in question.validation.allowed_values:
                return False, f"Must be one of: {', '.join(question.validation.allowed_values)}"

        return True, None


class QuestionnaireWorkflow:
    """Manages questionnaire flow and logic."""

    def __init__(self, questionnaire: Questionnaire):
        """Initialize workflow with a questionnaire."""
        self.questionnaire = questionnaire
        self.question_map: Dict[str, Question] = {q.id: q for q in questionnaire.questions}

    def get_next_question(
        self, current_question_id: str, answer: Answer
    ) -> Optional[Question]:
        """
        Determine the next question based on current answer.

        Supports linear flow (next_question) and branching (branching map).
        """
        question = self.question_map.get(current_question_id)
        if not question:
            return None

        # Check branching logic
        if question.branching:
            answer_value = str(answer.value)
            next_id = question.branching.get(answer_value)
            if next_id:
                return self.question_map.get(next_id)

        # Fall back to linear flow
        if question.next_question:
            return self.question_map.get(question.next_question)

        return None

    def is_question_visible(
        self, question: Question, answers: Dict[str, Any]
    ) -> bool:
        """
        Determine if a question should be shown based on conditionals.

        Conditionals format: {"question_id": "value"} or {"question_id": ["value1", "value2"]}
        """
        if not question.conditional:
            return True

        for question_id, expected_value in question.conditional.items():
            actual_value = answers.get(question_id)

            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            else:
                if str(actual_value) != str(expected_value):
                    return False

        return True

    def get_starting_question(self) -> Optional[Question]:
        """Get the first question."""
        return self.question_map.get(self.questionnaire.start_question_id)

    def get_all_questions(self) -> List[Question]:
        """Get all questions in the questionnaire."""
        return self.questionnaire.questions


class QueryGenerator:
    """Generates API queries from questionnaire answers."""

    @staticmethod
    def extract_indicators(answers: Dict[str, Any], questions: List[Question]) -> List[Dict[str, str]]:
        """
        Extract threat indicators from questionnaire answers.

        Returns list of {type, value} dicts.
        """
        indicators = []
        question_map = {q.id: q for q in questions}

        for question_id, answer_value in answers.items():
            question = question_map.get(question_id)
            if not question:
                continue

            # Map question types to indicator types
            indicator_type = None
            if question.type == QuestionType.IP:
                indicator_type = "ip"
            elif question.type == QuestionType.DOMAIN:
                indicator_type = "domain"
            elif question.type == QuestionType.EMAIL:
                indicator_type = "email"
            elif question.type == QuestionType.URL:
                indicator_type = "url"
            elif question.type == QuestionType.HASH:
                indicator_type = "hash"

            if indicator_type and answer_value:
                if isinstance(answer_value, list):
                    for val in answer_value:
                        indicators.append({"type": indicator_type, "value": str(val)})
                else:
                    indicators.append({"type": indicator_type, "value": str(answer_value)})

        return indicators

    @staticmethod
    def generate_query_result(
        answers: Dict[str, Any],
        questions: List[Question],
    ) -> QueryGenerationResult:
        """
        Generate query parameters from questionnaire answers.

        Determines which APIs to use and with what context.
        """
        indicators = QueryGenerator.extract_indicators(answers, questions)

        # Determine recommended APIs based on indicator types
        recommended_apis = set()
        for indicator in indicators:
            ind_type = indicator["type"]

            if ind_type == "ip":
                recommended_apis.update(["abuseipdb", "shodan", "virustotal"])
            elif ind_type == "domain":
                recommended_apis.update(["securitytrails", "virustotal", "whois"])
            elif ind_type == "email":
                recommended_apis.update(["haveibeenpwned", "emailrep"])
            elif ind_type == "url":
                recommended_apis.update(["urlscan", "virustotal"])
            elif ind_type == "hash":
                recommended_apis.update(["virustotal"])

        # Extract investigation context
        context: Dict[str, Any] = {}
        question_map = {q.id: q for q in questions}

        for question_id, answer_value in answers.items():
            question = question_map.get(question_id)
            if not question:
                continue

            # Map special question IDs to context fields
            if "timeframe" in question.id.lower():
                context["timeframe"] = answer_value
            elif "severity" in question.id.lower():
                context["severity"] = answer_value
            elif "jurisdiction" in question.id.lower():
                context["jurisdictions"] = answer_value if isinstance(answer_value, list) else [answer_value]
            elif "scope" in question.id.lower():
                context["scope"] = answer_value

        return QueryGenerationResult(
            extracted_indicators=indicators,
            recommended_apis=list(recommended_apis),
            search_context=context,
        )


class QuestionnaireEngine:
    """Main questionnaire engine."""

    def __init__(self):
        """Initialize engine."""
        self.questionnaires: Dict[str, Questionnaire] = {}
        self.responses: Dict[str, QuestionnaireResponse] = {}

    def register_questionnaire(self, questionnaire: Questionnaire) -> None:
        """Register a questionnaire."""
        self.questionnaires[questionnaire.id] = questionnaire
        logger.info(f"Registered questionnaire: {questionnaire.id}")

    def get_questionnaire(self, questionnaire_id: str) -> Optional[Questionnaire]:
        """Get a questionnaire by ID."""
        return self.questionnaires.get(questionnaire_id)

    def start_response(self, questionnaire_id: str) -> Tuple[QuestionnaireResponse, Optional[Question]]:
        """
        Start a new questionnaire response.

        Returns (response, first_question)
        """
        questionnaire = self.get_questionnaire(questionnaire_id)
        if not questionnaire:
            raise ValueError(f"Questionnaire not found: {questionnaire_id}")

        response = QuestionnaireResponse(questionnaire_id=questionnaire_id)
        self.responses[response.id] = response

        # Get first question
        workflow = QuestionnaireWorkflow(questionnaire)
        first_question = workflow.get_starting_question()

        return response, first_question

    def submit_answer(
        self,
        response_id: str,
        question_id: str,
        answer_value: Any,
    ) -> Tuple[bool, Optional[str], Optional[Question]]:
        """
        Submit an answer to a question.

        Returns (success, error_message, next_question)
        """
        response = self.responses.get(response_id)
        if not response:
            return False, "Response not found", None

        questionnaire = self.questionnaires.get(response.questionnaire_id)
        if not questionnaire:
            return False, "Questionnaire not found", None

        # Find question
        question = next((q for q in questionnaire.questions if q.id == question_id), None)
        if not question:
            return False, "Question not found", None

        # Validate answer
        is_valid, error = QuestionValidator.validate_answer(question, answer_value)
        if not is_valid:
            return False, error, None

        # Store answer
        answer = Answer(question_id=question_id, value=answer_value)
        response.answers.append(answer)

        # Get next question
        workflow = QuestionnaireWorkflow(questionnaire)
        next_question = workflow.get_next_question(question_id, answer)

        # Check if questionnaire is complete
        if next_question is None:
            response.completed = True
            response.completed_at = datetime.utcnow()

        return True, None, next_question

    def get_investigation_context(self, response_id: str) -> Optional[InvestigationContext]:
        """
        Generate investigation context from completed response.

        Returns None if response not completed.
        """
        response = self.responses.get(response_id)
        if not response or not response.completed:
            return None

        # Build answers dict
        answers = {ans.question_id: ans.value for ans in response.answers}

        # Generate query result
        questionnaire = self.questionnaires.get(response.questionnaire_id)
        query_result = QueryGenerator.generate_query_result(answers, questionnaire.questions)

        # Extract primary indicator
        if query_result.extracted_indicators:
            primary = query_result.extracted_indicators[0]
            context = InvestigationContext(
                target_type=primary["type"],
                target_value=primary["value"],
                investigation_type=questionnaire.category or "general",
                **query_result.search_context,
            )
            return context

        return None

    def get_response(self, response_id: str) -> Optional[QuestionnaireResponse]:
        """Get a response by ID."""
        return self.responses.get(response_id)


# Global engine instance
_engine: Optional[QuestionnaireEngine] = None


def get_questionnaire_engine() -> QuestionnaireEngine:
    """Get or create global questionnaire engine."""
    global _engine
    if _engine is None:
        _engine = QuestionnaireEngine()
    return _engine
