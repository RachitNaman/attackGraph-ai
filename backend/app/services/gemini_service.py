"""
services/gemini_service.py
===========================
Gemini LLM service — the ONLY file that calls Gemini for text generation.

WHERE GEMINI IS USED IN ATTACKGRAPH AI:
  1. Query Understanding     -> parse user intent into structured JSON
  2. Attack Path Explanation -> generate human-readable attack narrative
  3. Risk Assessment         -> evaluate and score attack scenarios
  4. Recommendations         -> generate prioritized remediation steps

WHERE GEMINI IS NOT USED:
  - Graph traversal          -> Neo4j handles this (structured queries)
  - Vector search            -> Qdrant handles this (embedding similarity)
  - Embedding generation     -> embeddings.py handles this (separate concern)
  - Path scoring             -> pure Python math (no LLM needed)

CHAINS vs AGENTS — EXPLAINED SIMPLY:

  CHAIN:
    A fixed sequence of steps. Input -> Step 1 -> Step 2 -> Step 3 -> Output.
    Like an assembly line. Every request follows the same path.
    Use when: the workflow is predictable and linear.
    Example: query -> embed -> search -> summarize

  AGENT:
    A dynamic decision-maker. The LLM decides which tools to call
    and in what order based on what it finds.
    Use when: the workflow depends on intermediate results.
    Example: "analyze this network" -> LLM decides whether to
             search CVEs, run graph traversal, or ask for clarification

  IN ATTACKGRAPH AI:
    LangChain handles CHAINS (prompt formatting, output parsing)
    LangGraph handles AGENTS (stateful multi-step reasoning)
    Gemini is the LLM BRAIN inside both

LANGCHAIN'S ROLE:
  - ChatPromptTemplate   -> structures system + user messages
  - JsonOutputParser     -> parses Gemini's JSON response reliably
  - LLMChain             -> connects prompt template to LLM in one call
  LangChain is the PLUMBING between prompts and Gemini.

LANGGRAPH'S ROLE:
  - StateGraph           -> defines the agent as a directed graph
  - Nodes                -> each step in the reasoning pipeline
  - Edges                -> connections between steps
  - Conditional edges    -> "if error, go to retry node"
  LangGraph is the WORKFLOW MANAGER for multi-step reasoning.
"""

import json
import logging
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.messages import SystemMessage, HumanMessage

from app.core.config import settings
from app.core.exceptions import AgentError

logger = logging.getLogger(__name__)


class GeminiService:
    """
    Wraps Gemini LLM for all text generation tasks.

    Uses LangChain's ChatGoogleGenerativeAI as the interface
    so we can use LangChain's prompt templates, output parsers,
    and chain composition cleanly.
    """

    def __init__(self) -> None:
        self._llm: ChatGoogleGenerativeAI | None = None
        self._llm_json: ChatGoogleGenerativeAI | None = None

    def _get_llm(self) -> ChatGoogleGenerativeAI:
        """
        Lazily initialize the LLM on first use.
        Lazy initialization means we don't fail at import time
        if the API key isn't set yet.
        """
        if not self._llm:
            if not settings.GEMINI_API_KEY:
                raise AgentError(
                    "GEMINI_API_KEY not set. Cannot initialize Gemini LLM."
                )
            self._llm = ChatGoogleGenerativeAI(
                model=settings.GEMINI_MODEL,
                google_api_key=settings.GEMINI_API_KEY,
                temperature=settings.GEMINI_TEMPERATURE,
                max_output_tokens=settings.GEMINI_MAX_TOKENS,
                convert_system_message_to_human=True,
            )
        return self._llm

    def _get_llm_for_json(self) -> ChatGoogleGenerativeAI:
        """
        LLM instance configured for JSON output.
        Lower temperature for more deterministic structured output.
        """
        if not self._llm_json:
            self._llm_json = ChatGoogleGenerativeAI(
                model=settings.GEMINI_MODEL,
                google_api_key=settings.GEMINI_API_KEY,
                temperature=0.0,         # Deterministic for JSON parsing
                max_output_tokens=settings.GEMINI_MAX_TOKENS,
                convert_system_message_to_human=True,
            )
        return self._llm_json

    async def generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """
        Generate a plain text response from Gemini.

        Uses LangChain's ChatPromptTemplate + StrOutputParser chain:
        prompt -> Gemini -> raw string output

        Args:
            system_prompt: Sets Gemini's role and behavior
            user_prompt: The actual question or task

        Returns:
            Gemini's text response as a string
        """
        try:
            llm = self._get_llm()

            # The prompts are already rendered strings. Send concrete messages
            # so literal JSON braces are not interpreted as template variables.
            response = await llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
            ])
            response = StrOutputParser().parse(response.content)
            logger.debug(f"Gemini text response: {len(response)} chars")
            return response

        except Exception as e:
            logger.error(f"Gemini text generation failed: {e}")
            raise AgentError(f"Gemini generation failed: {e}") from e

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict:
        """
        Generate a structured JSON response from Gemini.

        Uses LangChain's JsonOutputParser which:
        1. Tells Gemini to respond in JSON
        2. Automatically parses the response
        3. Handles markdown code blocks Gemini sometimes adds
        4. Raises a clear error if JSON is malformed

        Args:
            system_prompt: Sets Gemini's role
            user_prompt: Task that requires JSON output

        Returns:
            Parsed Python dict from Gemini's JSON response
        """
        try:
            llm = self._get_llm_for_json()

            # Add explicit JSON instruction to system prompt
            json_system = (
                system_prompt +
                "\n\nCRITICAL: Respond with valid JSON only. "
                "No markdown. No backticks. No explanation. Raw JSON only."
            )

            response = await llm.ainvoke([
                SystemMessage(content=json_system),
                HumanMessage(content=user_prompt),
            ])

            # JsonOutputParser handles parsing + markdown code fences
            parser = JsonOutputParser()
            result = parser.parse(response.content)
            logger.debug(f"Gemini JSON response: {type(result)}")
            return result

        except Exception as e:
            logger.error(f"Gemini JSON generation failed: {e}")
            # Try fallback: raw text with manual JSON extraction
            try:
                raw = await self.generate_text(system_prompt, user_prompt)
                return self._extract_json_from_text(raw)
            except Exception:
                raise AgentError(f"Gemini JSON generation failed: {e}") from e

    def _extract_json_from_text(self, text: str) -> dict:
        """
        Fallback JSON extraction from raw text.
        Handles cases where Gemini wraps JSON in markdown code blocks.
        """
        import re
        # Strip markdown code blocks
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = re.sub(r"```\s*$", "", text)
        text = text.strip()

        # Find JSON object boundaries
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])

        raise AgentError("Could not extract JSON from Gemini response")

    async def parse_query_intent(self, query: str) -> dict:
        """
        Use Gemini to parse a user's natural language query into
        structured intent for the graph traversal system.

        This is the entry point for the LangGraph agent pipeline.
        """
        from app.prompts.prompt_loader import prompt_loader

        system, user = prompt_loader.get_full_prompt(
            template="attack_path_explanation",
            section="query_understanding",
            query=query,
        )

        result = await self.generate_json(system, user)
        logger.info(f"Query intent parsed: {result.get('query_type')} "
                   f"(confidence: {result.get('confidence', 0)})")
        return result

    async def explain_attack_paths(
        self,
        context: str,
    ) -> dict:
        """
        Generate a comprehensive explanation of attack paths.

        This is the core AI feature — takes fused Graph RAG context
        and produces a human-readable security analysis.

        Args:
            context: Formatted context string from FusedContext.to_prompt_context()

        Returns:
            Dict with executive_summary, technical_narrative,
            risk_level, recommendations, etc.
        """
        from app.prompts.prompt_loader import prompt_loader

        system, user = prompt_loader.get_full_prompt(
            template="attack_path_explanation",
            section="path_analysis",
            context=context,
        )

        result = await self.generate_json(system, user)
        logger.info(
            f"Attack path explanation generated: "
            f"risk={result.get('risk_level')}, "
            f"recommendations={len(result.get('recommendations', []))}"
        )
        return result

    async def generate_report(
        self,
        query: str,
        context: str,
        risk_level: str,
        total_paths: int,
        highest_cvss: float,
        has_public_exploit: bool,
    ) -> dict:
        """Generate a full security report from analysis results."""
        from app.prompts.prompt_loader import prompt_loader

        system, user = prompt_loader.get_full_prompt(
            template="attack_path_explanation",
            section="report_generation",
            query=query,
            context=context,
            risk_level=risk_level,
            total_paths=total_paths,
            highest_cvss=highest_cvss,
            has_public_exploit=has_public_exploit,
        )

        return await self.generate_json(system, user)


# Singleton
gemini_service = GeminiService()
