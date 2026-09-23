"""
工具函数集
包含风险评分、证据链、输入清洗等功能
"""

from .risk_scorer import calculate_risk_score, make_decision
from .evidence_chain import build_evidence_chain
from .sanitizer import sanitize_email_body, validate_email_structure, extract_domains_from_email

__all__ = [
    "calculate_risk_score",
    "make_decision",
    "build_evidence_chain",
    "sanitize_email_body",
    "validate_email_structure",
    "extract_domains_from_email",
]
