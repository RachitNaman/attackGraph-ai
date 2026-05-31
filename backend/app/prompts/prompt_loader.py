"""
prompts/prompt_loader.py
=========================
Loads and renders YAML prompt templates.

WHY THIS EXISTS:
Instead of hardcoding prompts in Python files, we store them
in YAML. This file loads those YAML files and substitutes
variables using Python's str.format().

USAGE:
    loader = PromptLoader()
    prompt = loader.get_prompt(
        template="attack_path_explanation",
        section="path_analysis",
        context=fused_context_str,
    )
"""

import yaml
import logging
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class PromptLoader:
    """Loads YAML prompt templates and renders them with variables."""

    def __init__(self) -> None:
        self._cache: dict[str, dict] = {}

    def _load_template(self, template_name: str) -> dict:
        """Load a YAML template file. Cached after first load."""
        if template_name in self._cache:
            return self._cache[template_name]

        path = TEMPLATES_DIR / f"{template_name}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Prompt template not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self._cache[template_name] = data
        logger.debug(f"Loaded prompt template: {template_name}")
        return data

    def get_system_prompt(self, template: str, section: str) -> str:
        """Get the system prompt for a template section."""
        data = self._load_template(template)
        return data[section]["system"].strip()

    def get_user_prompt(self, template: str, section: str, **kwargs) -> str:
        """
        Get the user prompt for a template section with variables substituted.

        Args:
            template: YAML filename without extension
            section: Key inside the YAML (e.g. "path_analysis")
            **kwargs: Variables to substitute into the template
        """
        data = self._load_template(template)
        template_str = data[section]["user"].strip()

        try:
            return template_str.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing variable {e} for prompt {template}/{section}")

    def get_full_prompt(
        self,
        template: str,
        section: str,
        **kwargs,
    ) -> tuple[str, str]:
        """
        Returns (system_prompt, user_prompt) tuple.
        Convenience method for getting both at once.
        """
        return (
            self.get_system_prompt(template, section),
            self.get_user_prompt(template, section, **kwargs),
        )


# Singleton
prompt_loader = PromptLoader()
