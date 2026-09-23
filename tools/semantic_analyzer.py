"""
语义分析工具
分析邮件正文的语言模式，检测钓鱼邮件的常见特征
"""

from langchain.tools import BaseTool
from typing import Optional, Type
from pydantic import BaseModel, Field
import re


class SemanticAnalyzerInput(BaseModel):
    """语义分析输入"""
    email_body: str = Field(description="邮件正文内容")
    email_subject: str = Field(default="", description="邮件主题")


class SemanticAnalyzerTool(BaseTool):
    name: str = "semantic_analyzer"
    description: str = """分析邮件正文和主题的语言模式。
    检测钓鱼邮件的常见特征：紧迫感、权威伪装、语法错误、可疑用词等。
    输入：邮件正文和主题
    输出：语义分析结果和风险评分"""
    args_schema: Type[BaseModel] = SemanticAnalyzerInput

    def _run(self, email_body: str, email_subject: str = "") -> dict:
        """执行语义分析"""
        risk_score = 0
        reasons = []
        detected_patterns = []

        combined_text = (email_subject + " " + email_body).lower()

        # 检查 1：紧迫感词汇
        urgency_keywords = [
            r"urgent", r"immediately", r"asap", r"right now", r"within.*hours?",
            r"紧急", r"立即", r"马上", r"尽快", r"今天内", r"小时内",
            r"expire", r"expiry", r"过期", r"失效",
            r"suspend", r"lock", r"freeze", r"暂停", r"冻结", r"锁定"
        ]
        urgency_count = sum(1 for pattern in urgency_keywords if re.search(pattern, combined_text, re.IGNORECASE))
        if urgency_count >= 2:
            risk_score += 25
            reasons.append(f"检测到 {urgency_count} 个紧迫感词汇（制造焦虑感）")
            detected_patterns.append("high_urgency")
        elif urgency_count == 1:
            risk_score += 10
            reasons.append("包含紧迫感词汇")
            detected_patterns.append("urgency")

        # 检查 2：权威伪装
        authority_keywords = [
            r"ceo", r"cfo", r"president", r"director", r"manager",
            r"总裁", r"CEO", r"总经理", r"董事",
            r"security team", r"it department", r"support team",
            r"安全团队", r"IT部门", r"技术支持",
            r"bank", r"paypal", r"amazon", r"microsoft", r"apple",
            r"银行", r"支付宝", r"微信支付"
        ]
        authority_count = sum(1 for pattern in authority_keywords if re.search(pattern, combined_text, re.IGNORECASE))
        if authority_count >= 1:
            risk_score += 15
            reasons.append("伪装权威身份（CEO、银行、IT部门等）")
            detected_patterns.append("authority_impersonation")

        # 检查 3：账户威胁
        account_threat_keywords = [
            r"account.*suspend", r"account.*lock", r"account.*close",
            r"账户.*暂停", r"账户.*冻结", r"账户.*关闭",
            r"verify.*account", r"confirm.*identity", r"update.*information",
            r"验证.*账户", r"确认.*身份", r"更新.*信息",
            r"unauthorized.*access", r"suspicious.*activity",
            r"未授权.*访问", r"可疑.*活动"
        ]
        threat_count = sum(1 for pattern in account_threat_keywords if re.search(pattern, combined_text, re.IGNORECASE))
        if threat_count >= 1:
            risk_score += 20
            reasons.append("使用账户威胁话术（诱导用户点击链接）")
            detected_patterns.append("account_threat")

        # 检查 4：金钱诱惑
        money_keywords = [
            r"refund", r"prize", r"winner", r"lottery", r"jackpot",
            r"退款", r"奖金", r"中奖", r"彩票",
            r"\$\d+", r"¥\d+", r"\d+\s*usd", r"\d+\s*元"
        ]
        money_count = sum(1 for pattern in money_keywords if re.search(pattern, combined_text, re.IGNORECASE))
        if money_count >= 1:
            risk_score += 15
            reasons.append("包含金钱诱惑内容")
            detected_patterns.append("money_lure")

        # 检查 5：要求点击链接
        click_keywords = [
            r"click here", r"click the link", r"visit.*link",
            r"点击这里", r"点击链接", r"访问.*链接",
            r"download.*attachment", r"open.*attachment",
            r"下载.*附件", r"打开.*附件"
        ]
        click_count = sum(1 for pattern in click_keywords if re.search(pattern, combined_text, re.IGNORECASE))
        if click_count >= 1:
            risk_score += 15
            reasons.append("明确要求用户点击链接或附件")
            detected_patterns.append("explicit_action_request")

        # 检查 6：通用称呼（而非个性化）
        generic_greetings = [
            r"dear\s+(user|customer|member|client)",
            r"尊敬的.*(用户|客户|会员)",
            r"hello\s+(user|customer)",
            r"您好.*用户"
        ]
        if any(re.search(pattern, combined_text, re.IGNORECASE) for pattern in generic_greetings):
            risk_score += 10
            reasons.append("使用通用称呼（非个性化，疑似群发）")
            detected_patterns.append("generic_greeting")

        # 检查 7：拼写/语法错误模式（常见打字错误）
        typo_patterns = [
            r"recieve", r"seperete", r"occured", r"priviledge",  # 常见拼写错误
            r"\s{2,}",  # 多余空格
            r"[.]{2,}",  # 多个句号
        ]
        typo_count = sum(1 for pattern in typo_patterns if re.search(pattern, combined_text))
        if typo_count >= 2:
            risk_score += 10
            reasons.append("检测到拼写或格式错误")
            detected_patterns.append("typos")

        # 检查 8：可疑域名提及（但不在发件人字段）
        suspicious_domain_mentions = [
            r"paypa1", r"micr0soft", r"g00gle", r"app1e",
            r"verify.*password", r"reset.*password",
            r"验证.*密码", r"重置.*密码"
        ]
        if any(re.search(pattern, combined_text, re.IGNORECASE) for pattern in suspicious_domain_mentions):
            risk_score += 15
            reasons.append("正文提及可疑域名或密码操作")
            detected_patterns.append("suspicious_content")

        # 检查 9：Prompt Injection 尝试检测
        injection_patterns = [
            r"ignore.*previous", r"忽略.*之前",
            r"you are now", r"你现在是",
            r"new.*task", r"新.*任务",
            r"forget.*instruction", r"忘记.*指令",
            r"disregard", r"不要理会"
        ]
        injection_count = sum(1 for pattern in injection_patterns if re.search(pattern, combined_text, re.IGNORECASE))
        if injection_count >= 1:
            risk_score += 30
            reasons.append("⚠️ 检测到 Prompt Injection 攻击尝试")
            detected_patterns.append("prompt_injection_attempt")

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
                reasons.append("语义分析未发现明显可疑特征")

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "detected_patterns": detected_patterns,
            "urgency_level": "high" if urgency_count >= 2 else "low",
            "has_authority_impersonation": authority_count > 0,
            "has_prompt_injection": injection_count > 0
        }

    async def _arun(self, email_body: str, email_subject: str = "") -> dict:
        """异步执行"""
        return self._run(email_body, email_subject)
