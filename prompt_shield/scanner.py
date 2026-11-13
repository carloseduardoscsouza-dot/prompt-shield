"""
Core scanning engine for prompts.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .rules import INJECTION_PATTERNS, SECRET_PATTERNS, PII_PATTERNS, RiskLevel


@dataclass
class Finding:
    category: str
    description: str
    risk: RiskLevel
    matched_text: str
    start: int
    end: int


@dataclass
class PromptScanResult:
    is_safe: bool
    risk_level: RiskLevel
    risk_score: int  # 0 to 100
    findings: List[Finding] = field(default_factory=list)
    sanitized_prompt: str = ""
    token_estimate: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "risk": f.risk.value,
                    "preview": f.matched_text[:20] + "..." if len(f.matched_text) > 20 else f.matched_text,
                }
                for f in self.findings
            ],
            "token_estimate": self.token_estimate,
            "sanitized_prompt": self.sanitized_prompt,
        }


def scan_prompt(prompt: str, mask_secrets: bool = True) -> PromptScanResult:
    """
    Scans a prompt string for injection attacks, leaked credentials, and PII.
    """
    findings: List[Finding] = []
    sanitized = prompt

    # 1. Scan for Injections
    for pattern, desc, risk in INJECTION_PATTERNS:
        for m in pattern.finditer(prompt):
            findings.append(Finding(
                category="PROMPT_INJECTION",
                description=desc,
                risk=risk,
                matched_text=m.group(0),
                start=m.start(),
                end=m.end(),
            ))

    # 2. Scan for Secrets & API Keys
    for pattern, desc, risk in SECRET_PATTERNS:
        for m in pattern.finditer(prompt):
            matched = m.group(0)
            findings.append(Finding(
                category="SECRET_LEAK",
                description=desc,
                risk=risk,
                matched_text=matched,
                start=m.start(),
                end=m.end(),
            ))
            if mask_secrets:
                sanitized = sanitized.replace(matched, "[REDACTED_SECRET]")

    # 3. Scan for PII
    for pattern, desc, risk in PII_PATTERNS:
        for m in pattern.finditer(prompt):
            matched = m.group(0)
            findings.append(Finding(
                category="PII_LEAK",
                description=desc,
                risk=risk,
                matched_text=matched,
                start=m.start(),
                end=m.end(),
            ))
            if mask_secrets:
                sanitized = sanitized.replace(matched, "[REDACTED_PII]")

    # 4. Token estimation
    token_est = max(1, int(len(prompt) / 3.8)) if prompt else 0

    # 5. Compute Risk Score
    score = 0
    for f in findings:
        if f.risk == RiskLevel.CRITICAL:
            score += 45
        elif f.risk == RiskLevel.HIGH:
            score += 25
        elif f.risk == RiskLevel.MEDIUM:
            score += 15
        elif f.risk == RiskLevel.LOW:
            score += 5

    score = min(100, score)

    if score >= 50:
        level = RiskLevel.CRITICAL
    elif score >= 30:
        level = RiskLevel.HIGH
    elif score >= 15:
        level = RiskLevel.MEDIUM
    elif score > 0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.SAFE

    is_safe = (level in [RiskLevel.SAFE, RiskLevel.LOW])

    return PromptScanResult(
        is_safe=is_safe,
        risk_level=level,
        risk_score=score,
        findings=findings,
        sanitized_prompt=sanitized,
        token_estimate=token_est,
    )
