"""
SPF/DKIM 验证工具
检查邮件头的认证结果，判断发件人是否被伪造
"""

from langchain.tools import BaseTool
from typing import Optional, Type
from pydantic import BaseModel, Field
import json


class SPFValidatorInput(BaseModel):
    """SPF 验证输入"""
    email_headers: str = Field(description="邮件头 JSON 字符串，包含 from, spf_result, dkim_result 等字段")


class SPFValidatorTool(BaseTool):
    name: str = "spf_dkim_validator"
    description: str = """验证邮件的 SPF 和 DKIM 认证结果。
    SPF (Sender Policy Framework) 和 DKIM (DomainKeys Identified Mail) 用于防止邮件伪造。
    如果验证失败，说明发件人可能被伪造。
    输入：邮件头 JSON 字符串
    输出：验证结果和风险等级"""
    args_schema: Type[BaseModel] = SPFValidatorInput

    def _run(self, email_headers: str) -> dict:
        """执行 SPF/DKIM 验证"""
        try:
            # 解析邮件头
            headers = json.loads(email_headers) if isinstance(email_headers, str) else email_headers

            spf_result = headers.get("spf_result", "none").lower()
            dkim_result = headers.get("dkim_result", "none").lower()
            from_domain = headers.get("from", "").split("@")[-1]

            # 风险评估
            risk_score = 0
            reasons = []

            # SPF 检查
            if spf_result == "fail":
                risk_score += 30
                reasons.append("SPF 验证失败：发件人域名未授权该服务器发送邮件")
            elif spf_result == "softfail":
                risk_score += 15
                reasons.append("SPF 软失败：发件人域名可能未授权")
            elif spf_result == "none":
                risk_score += 10
                reasons.append("SPF 未配置：无法验证发件人")

            # DKIM 检查
            if dkim_result == "fail":
                risk_score += 25
                reasons.append("DKIM 验证失败：邮件签名无效")
            elif dkim_result == "none":
                risk_score += 10
                reasons.append("DKIM 未配置：无法验证邮件完整性")

            # 综合判定
            if spf_result == "fail" and dkim_result == "fail":
                risk_level = "critical"
                reasons.append("双重验证失败：高度怀疑邮件伪造")
            elif risk_score >= 30:
                risk_level = "high"
            elif risk_score >= 15:
                risk_level = "medium"
            else:
                risk_level = "low"

            return {
                "spf_result": spf_result,
                "dkim_result": dkim_result,
                "from_domain": from_domain,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reasons": reasons if reasons else ["SPF 和 DKIM 验证通过"]
            }

        except Exception as e:
            return {
                "error": f"解析邮件头失败: {str(e)}",
                "risk_level": "unknown"
            }

    async def _arun(self, email_headers: str) -> dict:
        """异步执行"""
        return self._run(email_headers)
