"""
Whois 域名查询工具 (Mock 实现)
返回域名注册信息，用于检测新注册的可疑域名
"""

from langchain.tools import BaseTool
from typing import Optional, Type
from pydantic import BaseModel, Field


class WhoisInput(BaseModel):
    """Whois 查询输入"""
    domain: str = Field(description="要查询的域名，例如 'example.com'")


class WhoisQueryTool(BaseTool):
    name: str = "whois_query"
    description: str = """查询域名注册信息，返回注册时间和注册商。
    用于检测新注册的可疑域名（如钓鱼网站通常使用新注册的域名）。
    输入：域名（例如 'micr0soft-security.com'）
    输出：JSON格式的注册信息"""
    args_schema: Type[BaseModel] = WhoisInput

    def _run(self, domain: str) -> dict:
        """执行 Whois 查询（Mock）"""
        # Mock 数据库：预设的可疑域名
        suspicious_domains = {
            "micr0soft-security.com": {
                "domain": domain,
                "registered_hours_ago": 12,
                "registrar": "Freenom (高危注册商)",
                "risk_level": "critical",
                "reason": "域名注册不足24小时，使用高危注册商"
            },
            "paypa1-verify.com": {
                "domain": domain,
                "registered_hours_ago": 3,
                "registrar": "NameCheap",
                "risk_level": "critical",
                "reason": "域名注册不足24小时"
            },
            "microsoft-security.com": {
                "domain": domain,
                "registered_hours_ago": 48,
                "registrar": "GoDaddy",
                "risk_level": "medium",
                "reason": "域名注册不足72小时"
            },
            "paypal-verify.com": {
                "domain": domain,
                "registered_hours_ago": 168,  # 7天
                "registrar": "NameCheap",
                "risk_level": "low",
                "reason": "域名注册时间较短但已超过1周"
            }
        }

        # 默认返回正常域名
        if domain in suspicious_domains:
            return suspicious_domains[domain]
        else:
            return {
                "domain": domain,
                "registered_hours_ago": 8760,  # 1年
                "registrar": "GoDaddy",
                "risk_level": "low",
                "reason": "域名注册时间正常"
            }

    async def _arun(self, domain: str) -> dict:
        """异步执行（暂时调用同步版本）"""
        return self._run(domain)
