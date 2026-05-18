"""
FastAPI routes for questionnaire-based investigations.

Endpoints for creating, answering, and completing questionnaires.
"""
import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from src.osint_platform.questionnaire.engine import get_questionnaire_engine
from src.osint_platform.questionnaire.library import get_questionnaire_template
from src.osint_platform.questionnaire.models import (
    Question, Questionnaire, QuestionnaireResponse, InvestigationContext,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/questionnaires", tags=["Questionnaires"])


class QuestionResponse(BaseModel):
    """API response for a question."""
    id: str
    text: str
    type: str
    description: Optional[str] = None
    choices: Optional[List[str]] = None
    help_text: Optional[str] = None
    default_value: Optional[Any] = None


class AnswerSubmissionRequest(BaseModel):
    """Request to submit an answer."""
    question_id: str = Field(..., description="ID of the question")
    value: Any = Field(..., description="Answer value")
    confidence: Optional[float] = Field(None, description="User confidence (0.0-1.0)")


class AnswerSubmissionResponse(BaseModel):
    """Response after submitting an answer."""
    success: bool
    error: Optional[str] = None
    next_question: Optional[QuestionResponse] = None
    completed: bool = False


class QuestionnaireStartResponse(BaseModel):
    """Response when starting a questionnaire."""
    response_id: str
    questionnaire_id: str
    first_question: Optional[QuestionResponse] = None


@router.get("/templates")
async def list_templates() -> Dict[str, List[str]]:
    """List available questionnaire templates."""
    from src.osint_platform.questionnaire.library import QUESTIONNAIRE_LIBRARY

    return {
        "templates": list(QUESTIONNAIRE_LIBRARY.keys()),
        "count": len(QUESTIONNAIRE_LIBRARY),
    }


@router.get("/templates/{template_id}")
async def get_template(template_id: str) -> Dict[str, Any]:
    """Get a questionnaire template."""
    try:
        template = get_questionnaire_template(template_id)
        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "category": template.category,
            "questions": [
                {
                    "id": q.id,
                    "text": q.text,
                    "type": q.type,
                    "choices": q.choices,
                    "help_text": q.help_text,
                }
                for q in template.questions
            ],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/start/{template_id}", response_model=QuestionnaireStartResponse)
async def start_questionnaire(template_id: str) -> QuestionnaireStartResponse:
    """
    Start a new questionnaire from a template.

    Returns response ID and first question.
    """
    try:
        engine = get_questionnaire_engine()
        template = get_questionnaire_template(template_id)

        # Register template
        engine.register_questionnaire(template)

        # Start response
        response, first_question = engine.start_response(template_id)

        first_q_response = None
        if first_question:
            first_q_response = QuestionResponse(
                id=first_question.id,
                text=first_question.text,
                type=first_question.type,
                description=first_question.description,
                choices=first_question.choices,
                help_text=first_question.help_text,
            )

        return QuestionnaireStartResponse(
            response_id=response.id,
            questionnaire_id=template_id,
            first_question=first_q_response,
        )

    except ValueError as e:
        logger.error(f"Questionnaire start error: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Questionnaire error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/responses/{response_id}/answer",
    response_model=AnswerSubmissionResponse
)
async def submit_answer(
    response_id: str,
    request: AnswerSubmissionRequest,
) -> AnswerSubmissionResponse:
    """
    Submit an answer to a question.

    Returns next question or completion status.
    """
    try:
        engine = get_questionnaire_engine()

        success, error, next_question = engine.submit_answer(
            response_id=response_id,
            question_id=request.question_id,
            answer_value=request.value,
        )

        if not success:
            return AnswerSubmissionResponse(
                success=False,
                error=error,
            )

        # Get response to check completion
        response = engine.get_response(response_id)

        next_q_response = None
        if next_question:
            next_q_response = QuestionResponse(
                id=next_question.id,
                text=next_question.text,
                type=next_question.type,
                description=next_question.description,
                choices=next_question.choices,
                help_text=next_question.help_text,
            )

        return AnswerSubmissionResponse(
            success=True,
            next_question=next_q_response,
            completed=response.completed if response else False,
        )

    except Exception as e:
        logger.error(f"Answer submission error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/responses/{response_id}")
async def get_response(response_id: str) -> Dict[str, Any]:
    """Get a questionnaire response."""
    try:
        engine = get_questionnaire_engine()
        response = engine.get_response(response_id)

        if not response:
            raise HTTPException(status_code=404, detail="Response not found")

        return {
            "id": response.id,
            "questionnaire_id": response.questionnaire_id,
            "completed": response.completed,
            "completion_time_seconds": response.completion_time_seconds,
            "answers_count": len(response.answers),
            "created_at": response.created_at.isoformat(),
            "completed_at": response.completed_at.isoformat() if response.completed_at else None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Response retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/responses/{response_id}/context")
async def get_investigation_context(response_id: str) -> Dict[str, Any]:
    """
    Get investigation context from completed questionnaire.

    Generates API query parameters and investigation metadata.
    """
    try:
        engine = get_questionnaire_engine()
        context = engine.get_investigation_context(response_id)

        if not context:
            raise HTTPException(
                status_code=422,
                detail="Questionnaire not completed or no indicators found"
            )

        return {
            "target_type": context.target_type,
            "target_value": context.target_value,
            "investigation_type": context.investigation_type,
            "scope": context.scope,
            "timeframe": context.timeframe,
            "severity": context.severity,
            "jurisdictions": context.jurisdictions,
            "custom_context": context.custom_context,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Context generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/responses/{response_id}/execute")
async def execute_investigation(response_id: str) -> Dict[str, Any]:
    """
    Execute investigation based on questionnaire responses.

    Integrates with APIManager to run queries on all indicators.
    """
    try:
        from src.osint_platform.api_integrations.manager import get_api_manager

        engine = get_questionnaire_engine()
        context = engine.get_investigation_context(response_id)

        if not context:
            raise HTTPException(
                status_code=422,
                detail="Questionnaire not completed or no indicators found"
            )

        # Get API manager
        api_manager = get_api_manager()
        if not api_manager._initialized:
            raise HTTPException(
                status_code=503,
                detail="API Manager not initialized"
            )

        # Execute query
        result = await api_manager.query(
            query=context.target_value,
            apis=None,  # Auto-select based on type
            use_cache=True,
        )

        return {
            "status": "success",
            "response_id": response_id,
            "target": f"{context.target_type}:{context.target_value}",
            "investigation_type": context.investigation_type,
            "execution_time_seconds": result["execution_time_seconds"],
            "total_results": result["correlation"]["total_results"],
            "total_sources": len(result["correlation"]["sources"]),
            "sources": result["correlation"]["sources"],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Investigation execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
