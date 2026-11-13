"""
prompt-shield - Lightweight AI Security & LLM Prompt Linter
Detects prompt injections, secret leaks (API keys, PII), and token overflow risks.
"""

__version__ = "1.0.0"
__author__ = "Carlos"

from .scanner import scan_prompt, PromptScanResult
from .rules import RiskLevel

__all__ = [
    "scan_prompt",
    "PromptScanResult",
    "RiskLevel",
]
