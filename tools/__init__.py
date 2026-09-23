"""
钓鱼邮件检测工具集
包含所有外部工具的 Mock 实现
"""

from .whois_tool import WhoisQueryTool
from .url_checker import URLCheckerTool
from .spf_validator import SPFValidatorTool
from .attachment_scanner import AttachmentScannerTool
from .semantic_analyzer import SemanticAnalyzerTool

__all__ = [
    "WhoisQueryTool",
    "URLCheckerTool",
    "SPFValidatorTool",
    "AttachmentScannerTool",
    "SemanticAnalyzerTool",
]
