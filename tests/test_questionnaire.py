"""
Tests for Questionnaire Engine.

Tests question validation, workflow logic, and query generation.
"""
import pytest
from src.osint_platform.questionnaire.models import (
    Question, QuestionType, Questionnaire, Answer, QuestionnaireResponse,
    AnswerValidation, QueryGenerationResult,
)
from src.osint_platform.questionnaire.engine import (
    QuestionValidator, QuestionnaireWorkflow, QueryGenerator, QuestionnaireEngine,
)
from src.osint_platform.questionnaire.library import get_questionnaire_template


class TestQuestionValidator:
    """Tests for question validation."""

    def test_validate_required_answer(self):
        """Test required field validation."""
        question = Question(
            id="test",
            text="Test question",
            type=QuestionType.TEXT,
            validation=AnswerValidation(required=True),
        )

        is_valid, error = QuestionValidator.validate_answer(question, "answer")
        assert is_valid
        assert error is None

        is_valid, error = QuestionValidator.validate_answer(question, "")
        assert not is_valid
        assert error == "Answer is required"

    def test_validate_email(self):
        """Test email validation."""
        question = Question(
            id="email",
            text="Email",
            type=QuestionType.EMAIL,
        )

        is_valid, _ = QuestionValidator.validate_answer(question, "test@example.com")
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "invalid-email")
        assert not is_valid
        assert "Invalid email format" in error

    def test_validate_ip(self):
        """Test IP address validation."""
        question = Question(
            id="ip",
            text="IP",
            type=QuestionType.IP,
        )

        is_valid, _ = QuestionValidator.validate_answer(question, "192.168.1.1")
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "invalid-ip")
        assert not is_valid
        assert "Invalid IP address format" in error

    def test_validate_domain(self):
        """Test domain validation."""
        question = Question(
            id="domain",
            text="Domain",
            type=QuestionType.DOMAIN,
        )

        is_valid, _ = QuestionValidator.validate_answer(question, "example.com")
        assert is_valid

        is_valid, _ = QuestionValidator.validate_answer(question, "sub.example.org")
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "invalid domain")
        assert not is_valid

    def test_validate_hash(self):
        """Test hash validation."""
        question = Question(
            id="hash",
            text="Hash",
            type=QuestionType.HASH,
        )

        md5 = "5d41402abc4b2a76b9719d911017c592"
        is_valid, _ = QuestionValidator.validate_answer(question, md5)
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "invalid")
        assert not is_valid
        assert "32, 40, or 64" in error

    def test_validate_choice(self):
        """Test choice validation."""
        question = Question(
            id="choice",
            text="Choose",
            type=QuestionType.CHOICE,
            choices=["A", "B", "C"],
        )

        is_valid, _ = QuestionValidator.validate_answer(question, "A")
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "D")
        assert not is_valid
        assert "must be one of" in error.lower()

    def test_validate_length(self):
        """Test min/max length validation."""
        question = Question(
            id="text",
            text="Text",
            type=QuestionType.TEXT,
            validation=AnswerValidation(min_length=3, max_length=10),
        )

        is_valid, _ = QuestionValidator.validate_answer(question, "valid")
        assert is_valid

        is_valid, error = QuestionValidator.validate_answer(question, "ab")
        assert not is_valid
        assert "Minimum length" in error

        is_valid, error = QuestionValidator.validate_answer(question, "this is too long")
        assert not is_valid
        assert "Maximum length" in error


class TestQuestionnaireWorkflow:
    """Tests for questionnaire workflow logic."""

    def test_linear_flow(self):
        """Test linear questionnaire flow."""
        questions = [
            Question(id="q1", text="Question 1", type=QuestionType.TEXT, next_question="q2"),
            Question(id="q2", text="Question 2", type=QuestionType.TEXT, next_question="q3"),
            Question(id="q3", text="Question 3", type=QuestionType.TEXT),
        ]
        questionnaire = Questionnaire(
            id="linear",
            name="Linear",
            questions=questions,
            start_question_id="q1",
        )

        workflow = QuestionnaireWorkflow(questionnaire)

        first = workflow.get_starting_question()
        assert first.id == "q1"

        answer1 = Answer(question_id="q1", value="answer1")
        next_q = workflow.get_next_question("q1", answer1)
        assert next_q.id == "q2"

    def test_branching_flow(self):
        """Test branching questionnaire flow."""
        questions = [
            Question(
                id="q1",
                text="Choose path",
                type=QuestionType.CHOICE,
                choices=["Path A", "Path B"],
                branching={"Path A": "q2a", "Path B": "q2b"},
            ),
            Question(id="q2a", text="Question 2A", type=QuestionType.TEXT),
            Question(id="q2b", text="Question 2B", type=QuestionType.TEXT),
        ]
        questionnaire = Questionnaire(
            id="branching",
            name="Branching",
            questions=questions,
            start_question_id="q1",
        )

        workflow = QuestionnaireWorkflow(questionnaire)

        # Path A
        answer_a = Answer(question_id="q1", value="Path A")
        next_q_a = workflow.get_next_question("q1", answer_a)
        assert next_q_a.id == "q2a"

        # Path B
        answer_b = Answer(question_id="q1", value="Path B")
        next_q_b = workflow.get_next_question("q1", answer_b)
        assert next_q_b.id == "q2b"

    def test_conditional_questions(self):
        """Test conditional question visibility."""
        questions = [
            Question(
                id="q1",
                text="Type?",
                type=QuestionType.CHOICE,
                choices=["IP", "Domain"],
            ),
            Question(
                id="q2",
                text="IP specific",
                type=QuestionType.TEXT,
                conditional={"q1": "IP"},
            ),
        ]
        questionnaire = Questionnaire(
            id="conditional",
            name="Conditional",
            questions=questions,
            start_question_id="q1",
        )

        workflow = QuestionnaireWorkflow(questionnaire)
        ip_question = questions[1]

        # Show if q1 is IP
        visible = workflow.is_question_visible(ip_question, {"q1": "IP"})
        assert visible

        # Hide if q1 is Domain
        visible = workflow.is_question_visible(ip_question, {"q1": "Domain"})
        assert not visible


class TestQueryGenerator:
    """Tests for query generation from answers."""

    def test_extract_indicators(self):
        """Test indicator extraction."""
        questions = [
            Question(id="ip", text="IP", type=QuestionType.IP),
            Question(id="domain", text="Domain", type=QuestionType.DOMAIN),
        ]

        answers = {"ip": "192.168.1.1", "domain": "example.com"}
        indicators = QueryGenerator.extract_indicators(answers, questions)

        assert len(indicators) == 2
        assert any(i["type"] == "ip" and i["value"] == "192.168.1.1" for i in indicators)
        assert any(i["type"] == "domain" and i["value"] == "example.com" for i in indicators)

    def test_generate_query_result(self):
        """Test query result generation."""
        questions = [
            Question(id="ip", text="IP", type=QuestionType.IP),
        ]

        answers = {"ip": "192.168.1.1"}
        result = QueryGenerator.generate_query_result(answers, questions)

        assert len(result.extracted_indicators) == 1
        assert result.extracted_indicators[0]["type"] == "ip"
        # Should include recommended APIs for IP
        assert "shodan" in result.recommended_apis or "abuseipdb" in result.recommended_apis


class TestQuestionnaireEngine:
    """Tests for questionnaire engine."""

    def test_engine_registration(self):
        """Test questionnaire registration."""
        template = get_questionnaire_template("threat_assessment_v1")
        engine = QuestionnaireEngine()

        engine.register_questionnaire(template)
        retrieved = engine.get_questionnaire(template.id)

        assert retrieved is not None
        assert retrieved.id == template.id

    def test_start_response(self):
        """Test starting a questionnaire response."""
        template = get_questionnaire_template("threat_assessment_v1")
        engine = QuestionnaireEngine()
        engine.register_questionnaire(template)

        response, first_question = engine.start_response(template.id)

        assert response is not None
        assert response.questionnaire_id == template.id
        assert not response.completed
        assert first_question is not None

    def test_submit_answer(self):
        """Test submitting answers."""
        template = get_questionnaire_template("threat_assessment_v1")
        engine = QuestionnaireEngine()
        engine.register_questionnaire(template)

        response, first_question = engine.start_response(template.id)

        success, error, next_q = engine.submit_answer(
            response.id,
            first_question.id,
            "IP Address",
        )

        assert success
        assert error is None
        assert next_q is not None

    def test_invalid_answer(self):
        """Test invalid answer rejection."""
        template = get_questionnaire_template("threat_assessment_v1")
        engine = QuestionnaireEngine()
        engine.register_questionnaire(template)

        response, first_question = engine.start_response(template.id)

        # Submit invalid answer (not in choices)
        success, error, next_q = engine.submit_answer(
            response.id,
            first_question.id,
            "Invalid Choice",
        )

        assert not success
        assert error is not None


class TestQuestionnaireLibrary:
    """Tests for built-in questionnaire library."""

    def test_threat_assessment_template(self):
        """Test threat assessment questionnaire template."""
        template = get_questionnaire_template("threat_assessment_v1")

        assert template.id == "threat_assessment_v1"
        assert len(template.questions) > 0
        assert template.start_question_id is not None

    def test_reconnaissance_template(self):
        """Test reconnaissance questionnaire template."""
        template = get_questionnaire_template("reconnaissance_v1")

        assert template.id == "reconnaissance_v1"
        assert template.category == "reconnaissance"
        assert len(template.questions) > 0

    def test_all_templates_loadable(self):
        """Test that all templates are loadable."""
        from src.osint_platform.questionnaire.library import QUESTIONNAIRE_LIBRARY

        for template_id in QUESTIONNAIRE_LIBRARY.keys():
            template = get_questionnaire_template(template_id)
            assert template is not None
            assert template.id == template_id
            assert len(template.questions) > 0

    def test_invalid_template(self):
        """Test error on invalid template."""
        with pytest.raises(ValueError):
            get_questionnaire_template("nonexistent_template")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
