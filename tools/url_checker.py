"""
URL 信誉检查工具 (Mock 实现)
检查邮件中的链接是否指向恶意网站
"""

from langchain.tools import BaseTool
from typing import Optional, Type
from pydantic import BaseModel, Field
import re


class URLCheckerInput(BaseModel):
    """URL 检查输入"""
    url: str = Field(description="要检查的 URL 链接")


class URLCheckerTool(BaseTool):
    name: str = "url_reputation_checker"
    description: str = """检查 URL 的信誉和安全性。
    功能包括：短链接展开、黑名单匹配、IP 地址检测、重定向分析。
    输入：URL 链接
    输出：URL 风险评估结果"""
    args_schema: Type[BaseModel] = URLCheckerInput

    def _run(self, url: str) -> dict:
        """执行 URL 检查（Mock）"""
        risk_score = 0
        reasons = []
        flags = []

        # 黑名单域名（常见钓鱼域名模式）
        blacklist_domains = [
            "micr0soft-security.com",
            "paypa1-verify.com",
            "apple-support-verify.com",
            "secure-login-update.com",
            "account-verification-required.com"
        ]

        # 可疑 TLD（顶级域名）
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]

        # 检查 1：黑名单匹配
        for domain in blacklist_domains:
            if domain in url:
                risk_score += 40
                reasons.append(f"URL 包含已知钓鱼域名：{domain}")
                flags.append("blacklist_match")
                break

        # 检查 2：IP 地址直接访问
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, url):
            risk_score += 35
            reasons.append("URL 直接使用 IP 地址（可疑行为）")
            flags.append("ip_address")

        # 检查 3：短链接
        short_link_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
        if any(domain in url for domain in short_link_domains):
            risk_score += 20
            reasons.append("使用短链接服务（可能隐藏真实目标）")
            flags.append("short_link")

            # Mock 短链接展开
            if "bit.ly/3xYz" in url:
                resolved_url = "http://192.168.1.100/login.php"
                risk_score += 25
                reasons.append(f"短链接展开后指向可疑 IP：{resolved_url}")
                flags.append("suspicious_redirect")

        # 检查 4：可疑 TLD
        for tld in suspicious_tlds:
            if url.endswith(tld) or tld in url:
                risk_score += 15
                reasons.append(f"使用高危顶级域名：{tld}")
                flags.append("suspicious_tld")
                break

        # 检查 5：域名混淆（数字替换字母）
        confusion_patterns = [
            (r'micr0soft', '0 替换 o'),
            (r'paypa1', '1 替换 l'),
            (r'g00gle', '0 替换 o'),
            (r'app1e', '1 替换 l')
        ]
        for pattern, desc in confusion_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                risk_score += 30
                reasons.append(f"检测到域名混淆：{desc}")
                flags.append("typosquatting")
                break

        # 检查 6：过长的 URL（可能隐藏参数）
        if len(url) > 150:
            risk_score += 10
            reasons.append("URL 异常过长（可能包含隐藏参数）")
            flags.append("long_url")

        # 检查 7：可疑的登录页面
        login_keywords = ["login", "verify", "account", "signin", "password", "secure"]
        if any(keyword in url.lower() for keyword in login_keywords):
            if risk_score > 0:  # 如果已经有其他风险信号
                risk_score += 15
                reasons.append("URL 指向登录页面且存在其他可疑特征")
                flags.append("suspicious_login_page")

        # 风险等级判定
        if risk_score >= 50:
            risk_level = "critical"
        elif risk_score >= 30:
            risk_level = "high"
        elif risk_score >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"
            if not reasons:
                reasons.append("URL 未发现明显可疑特征")

        return {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "flags": flags
        }

    async def _arun(self, url: str) -> dict:
        """异步执行"""
        return self._run(url)
