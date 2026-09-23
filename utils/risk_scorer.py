"""
风险评分算法
基于各个工具的检测结果，计算综合风险分数并做出最终决策
"""

from typing import Dict, List, Tuple


# 证据权重配置（总和为 1.0）
EVIDENCE_WEIGHTS = {
    "domain_age": 0.30,        # 域名年龄（硬事实）
    "spf_dkim": 0.25,          # SPF/DKIM 验证（硬事实）
    "url_reputation": 0.25,    # URL 信誉（硬事实）
    "attachment": 0.15,        # 附件扫描（硬事实）
    "semantic": 0.05           # 语义分析（软判断）
}


def calculate_risk_score(tool_results: Dict) -> Tuple[int, List[Dict]]:
    """
    基于工具返回结果计算综合风险分数

    Args:
        tool_results: 各个工具的返回结果字典

    Returns:
        (risk_score, evidence_chain): 风险分数 (0-100) 和证据链
    """
    total_score = 0
    evidence_chain = []

    # 1. 域名年龄检查
    if "whois" in tool_results:
        whois_data = tool_results["whois"]
        domain_risk = 0

        if "registered_hours_ago" in whois_data:
            hours = whois_data["registered_hours_ago"]
            if hours < 24:
                domain_risk = 100
            elif hours < 72:
                domain_risk = 70
            elif hours < 168:  # 1周
                domain_risk = 40
            elif hours < 720:  # 1个月
                domain_risk = 20
            else:
                domain_risk = 0

        weighted_score = domain_risk * EVIDENCE_WEIGHTS["domain_age"]
        total_score += weighted_score

        evidence_chain.append({
            "source": "Whois 域名查询",
            "risk_contribution": round(weighted_score),
            "weight": EVIDENCE_WEIGHTS["domain_age"],
            "raw_risk": domain_risk,
            "detail": whois_data.get("reason", "域名信息检查"),
            "evidence": whois_data
        })

    # 2. SPF/DKIM 验证
    if "spf_dkim" in tool_results:
        spf_data = tool_results["spf_dkim"]
        spf_risk = spf_data.get("risk_score", 0)

        # 归一化到 0-100
        normalized_risk = min(spf_risk * 1.5, 100)  # SPF 风险分数较低，放大

        weighted_score = normalized_risk * EVIDENCE_WEIGHTS["spf_dkim"]
        total_score += weighted_score

        evidence_chain.append({
            "source": "SPF/DKIM 验证",
            "risk_contribution": round(weighted_score),
            "weight": EVIDENCE_WEIGHTS["spf_dkim"],
            "raw_risk": round(normalized_risk),
            "detail": "; ".join(spf_data.get("reasons", [])),
            "evidence": spf_data
        })

    # 3. URL 信誉检查
    if "url_check" in tool_results:
        url_data = tool_results["url_check"]

        if isinstance(url_data, list):
            # 多个 URL，取最高风险
            if url_data:  # 确保列表不为空
                max_url_risk = max([u.get("risk_score", 0) for u in url_data], default=0)
                url_risk = max_url_risk
                url_reasons = []
                for u in url_data:
                    if u.get("risk_score", 0) > 0:
                        url_reasons.extend(u.get("reasons", []))
            else:
                url_risk = 0
                url_reasons = ["邮件无链接"]
        else:
            url_risk = url_data.get("risk_score", 0)
            url_reasons = url_data.get("reasons", [])

        weighted_score = url_risk * EVIDENCE_WEIGHTS["url_reputation"]
        total_score += weighted_score

        evidence_chain.append({
            "source": "URL 信誉检查",
            "risk_contribution": round(weighted_score),
            "weight": EVIDENCE_WEIGHTS["url_reputation"],
            "raw_risk": url_risk,
            "detail": "; ".join(url_reasons[:3]) if url_reasons else "URL 检查",
            "evidence": url_data
        })

    # 4. 附件扫描
    if "attachment" in tool_results:
        att_data = tool_results["attachment"]
        att_risk = att_data.get("risk_score", 0)

        weighted_score = att_risk * EVIDENCE_WEIGHTS["attachment"]
        total_score += weighted_score

        evidence_chain.append({
            "source": "附件扫描",
            "risk_contribution": round(weighted_score),
            "weight": EVIDENCE_WEIGHTS["attachment"],
            "raw_risk": att_risk,
            "detail": att_data.get("reasons", ["附件检查"])[0] if att_data.get("reasons") else "无附件",
            "evidence": att_data
        })

    # 5. 语义分析
    if "semantic" in tool_results:
        sem_data = tool_results["semantic"]
        sem_risk = sem_data.get("risk_score", 0)

        weighted_score = sem_risk * EVIDENCE_WEIGHTS["semantic"]
        total_score += weighted_score

        evidence_chain.append({
            "source": "语义分析",
            "risk_contribution": round(weighted_score),
            "weight": EVIDENCE_WEIGHTS["semantic"],
            "raw_risk": sem_risk,
            "detail": "; ".join(sem_data.get("reasons", [])[:2]),
            "evidence": sem_data
        })

    # 确保分数在 0-100 范围内
    final_score = min(round(total_score), 100)

    # 按贡献度排序证据链
    evidence_chain.sort(key=lambda x: x["risk_contribution"], reverse=True)

    return final_score, evidence_chain


def make_decision(risk_score: int, tool_results: Dict) -> Tuple[str, str]:
    """
    基于风险分数做出最终决策

    Args:
        risk_score: 综合风险分数 (0-100)
        tool_results: 工具检测结果（用于规则覆盖）

    Returns:
        (decision, reason): 决策 (Block/Quarantine/Allow) 和原因
    """
    decision = ""
    reason = ""

    # 强制规则 1：域名注册 < 48 小时 → 至少 Quarantine
    whois_data = tool_results.get("whois", {})
    if whois_data.get("registered_hours_ago", 999) < 48:
        if risk_score < 31:
            return "Quarantine", "规则覆盖：域名注册不足 48 小时，即使其他指标正常也需人工审核"

    # 强制规则 2：SPF + DKIM 双失败 → Block
    spf_data = tool_results.get("spf_dkim", {})
    if (spf_data.get("spf_result") == "fail" and
        spf_data.get("dkim_result") == "fail"):
        return "Block", "规则覆盖：SPF 和 DKIM 双重验证失败，高度怀疑邮件伪造"

    # 强制规则 3：检测到 Prompt Injection → Block
    semantic_data = tool_results.get("semantic", {})
    if semantic_data.get("has_prompt_injection"):
        return "Block", "规则覆盖：检测到 Prompt Injection 攻击尝试"

    # 强制规则 4：附件包含已知恶意哈希 → Block
    att_data = tool_results.get("attachment", {})
    if att_data.get("risk_level") == "critical":
        for detail in att_data.get("attachment_details", []):
            if "恶意软件" in str(detail.get("reasons", [])):
                return "Block", "规则覆盖：附件匹配已知恶意软件哈希"

    # 常规决策阈值
    if risk_score >= 70:
        decision = "Block"
        reason = "风险分数过高，建议直接拦截"
    elif risk_score >= 30:
        decision = "Quarantine"
        reason = "风险分数中等，建议隔离待人工审核"
    else:
        decision = "Allow"
        reason = "风险分数较低，可以放行"

    return decision, reason


def override_decision_if_needed(llm_decision: str, rule_decision: str,
                               rule_reason: str) -> Tuple[str, str, bool]:
    """
    如果规则决策与 LLM 决策不同，判断是否需要覆盖

    Args:
        llm_decision: LLM 的决策
        rule_decision: 规则引擎的决策
        rule_reason: 规则原因

    Returns:
        (final_decision, final_reason, was_overridden)
    """
    decision_priority = {"Block": 3, "Quarantine": 2, "Allow": 1}

    # 取更严格的决策
    if decision_priority.get(rule_decision, 0) > decision_priority.get(llm_decision, 0):
        return rule_decision, f"规则覆盖 LLM 决策: {rule_reason}", True
    else:
        return llm_decision, "LLM 决策与规则一致", False
