"""
Security rules and regex patterns for Prompt Injection, Secrets, and PII detection.
"""

import re
from enum import Enum
from typing import List, Dict, Any


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Prompt Injection / Jailbreak Attack Signatures
INJECTION_PATTERNS = [
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands)\b", re.I), "Instruction Override Attack", RiskLevel.CRITICAL),
    (re.compile(r"\byou\s+are\s+now\s+(in\s+)?(DAN|developer\s+mode|unrestricted|jailbroken|godmode)\b", re.I), "Jailbreak Persona / DAN Attempt", RiskLevel.CRITICAL),
    (re.compile(r"\b(bypass|disable|remove)\s+(safety|content|ethical|moral)\s+(filters|guidelines|restrictions)\b", re.I), "Safety Filter Bypass Attempt", RiskLevel.HIGH),
    (re.compile(r"\b(repeat|print|reveal|output|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions|system\s+message)\b", re.I), "System Prompt Extraction Attack", RiskLevel.HIGH),
    (re.compile(r"<\s*(system|admin|developer|instruction)\s*>", re.I), "Fake XML/Role Tag Injection", RiskLevel.HIGH),
    (re.compile(r"\bdo\s+anything\s+now\b", re.I), "DAN Signature", RiskLevel.HIGH),
]

# Sensitive Secrets & API Key Signatures
SECRET_PATTERNS = [
    (re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"), "OpenAI / Anthropic API Key Leak", RiskLevel.CRITICAL),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID Leak", RiskLevel.CRITICAL),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"), "GitHub Personal Access Token Leak", RiskLevel.CRITICAL),
    (re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----"), "Private Key Header Leak", RiskLevel.CRITICAL),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"), "JWT Authentication Token Leak", RiskLevel.HIGH),
]

# Personally Identifiable Information (PII)
PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "Email Address", RiskLevel.MEDIUM),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "Credit Card Number Pattern", RiskLevel.HIGH),
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "Brazilian CPF Number", RiskLevel.HIGH),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "US Social Security Number", RiskLevel.HIGH),
]
