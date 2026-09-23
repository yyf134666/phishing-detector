"""
输入清洗工具
防御 Prompt Injection 攻击，清洗邮件正文中的危险指令
"""

import re
from typing import Tuple


def sanitize_email_body(text: str) -> Tuple[str, bool, list]:
    """
    清洗邮件正文，移除可能干扰 LLM 的元指令

    Args:
        text: 原始邮件正文

    Returns:
        (cleaned_text, has_suspicious_content, detected_patterns):
        清洗后的文本、是否包含可疑内容、检测到的攻击模式
    """
    original_text = text
    has_suspicious = False
    detected_patterns = []

    # 危险模式列表
    dangerous_patterns = [
        # 英文指令注入
        (r"ignore\s+(previous|all|the)\s+(instruction|prompt|rule)", "ignore_instruction"),
        (r"disregard\s+(previous|all|the)\s+(instruction|prompt)", "disregard_instruction"),
        (r"forget\s+(previous|all|the)\s+(instruction|prompt|rule)", "forget_instruction"),
        (r"you\s+are\s+now\s+(a|an)", "role_hijacking"),
        (r"new\s+(task|instruction|mission)", "new_task"),
        (r"system\s*:\s*", "system_prompt_injection"),
        (r"assistant\s*:\s*", "assistant_impersonation"),

        # 中文指令注入
        (r"忽略.{0,5}(之前|所有|全部|以前).{0,5}(指令|提示|规则)", "ignore_instruction_cn"),
        (r"不要理会.{0,5}(之前|所有)", "disregard_instruction_cn"),
        (r"忘记.{0,5}(之前|所有).{0,5}指令", "forget_instruction_cn"),
        (r"你现在是.{0,10}(助手|机器人|AI)", "role_hijacking_cn"),
        (r"新的.{0,5}(任务|指令|使命)", "new_task_cn"),
        (r"系统.{0,3}[:：]", "system_prompt_injection_cn"),

        # 角色伪装
        (r"act\s+as\s+(a|an)", "act_as"),
        (r"pretend\s+to\s+be", "pretend_to_be"),
        (r"扮演", "act_as_cn"),
        (r"假装", "pretend_cn"),

        # 输出控制
        (r"output\s+(only|just)", "output_control"),
        (r"respond\s+with\s+(only|just)", "response_control"),
        (r"只(输出|回复|返回)", "output_control_cn"),
        (r"仅(输出|回复|返回)", "response_control_cn"),

        # 规则修改
        (r"change\s+(the\s+)?rule", "change_rule"),
        (r"modify\s+(the\s+)?instruction", "modify_instruction"),
        (r"修改.{0,5}(规则|指令)", "change_rule_cn"),
        (r"更改.{0,5}(规则|指令)", "modify_instruction_cn"),
    ]

    # 检测并标记可疑内容
    for pattern, tag in dangerous_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            has_suspicious = True
            detected_patterns.append(tag)
            # 将匹配内容替换为标记
            matched_text = match.group(0)
            text = text.replace(matched_text, f"[已过滤:{tag}]")

    # 移除多余的过滤标记（只保留一个）
    text = re.sub(r'(\[已过滤:[^\]]+\])+', '[可疑内容已过滤]', text)

    # 清理多余空白
    text = re.sub(r'\s{2,}', ' ', text)
    text = text.strip()

    return text, has_suspicious, list(set(detected_patterns))


def sanitize_email_subject(subject: str) -> str:
    """
    清洗邮件主题（相对简单，主要去除特殊字符）

    Args:
        subject: 原始邮件主题

    Returns:
        清洗后的主题
    """
    # 移除控制字符
    subject = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', subject)

    # 移除多余空白
    subject = re.sub(r'\s{2,}', ' ', subject)

    return subject.strip()


def validate_email_structure(email_data: dict) -> Tuple[bool, str]:
    """
    验证邮件数据结构的完整性

    Args:
        email_data: 邮件数据字典

    Returns:
        (is_valid, error_message): 是否有效和错误信息
    """
    required_fields = ["headers", "body_text"]

    # 检查必需字段
    for field in required_fields:
        if field not in email_data:
            return False, f"缺少必需字段: {field}"

    # 检查 headers 子字段
    headers = email_data.get("headers", {})
    required_headers = ["from", "to", "subject"]

    for header in required_headers:
        if header not in headers:
            return False, f"缺少必需的邮件头字段: {header}"

    # 检查字段类型
    if not isinstance(email_data.get("body_text"), str):
        return False, "body_text 必须是字符串"

    if not isinstance(headers, dict):
        return False, "headers 必须是字典"

    return True, ""


def extract_domains_from_email(from_address: str, urls: list) -> list:
    """
    从邮件中提取所有域名用于检查

    Args:
        from_address: 发件人地址
        urls: URL 列表

    Returns:
        域名列表
    """
    domains = []

    # 提取发件人域名
    if "@" in from_address:
        sender_domain = from_address.split("@")[-1].strip().lower()
        domains.append(sender_domain)

    # 提取 URL 中的域名
    url_pattern = r'https?://([^/\s:]+)'
    for url_obj in urls:
        url = url_obj.get("original", "") if isinstance(url_obj, dict) else url_obj
        matches = re.findall(url_pattern, url)
        domains.extend([m.lower() for m in matches])

    return list(set(domains))  # 去重
