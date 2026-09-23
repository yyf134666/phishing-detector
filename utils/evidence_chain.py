"""
证据链构建工具
将各个工具的检测结果整合成一条可追溯的证据链
"""

from typing import Dict, List


def build_evidence_chain(tool_results: Dict) -> List[Dict]:
    """
    构建证据链，用于可解释性展示

    Args:
        tool_results: 各个工具的返回结果

    Returns:
        证据链列表，按风险贡献度排序
    """
    evidence_chain = []

    # 1. Whois 证据
    if "whois" in tool_results:
        whois_data = tool_results["whois"]
        evidence_chain.append({
            "type": "domain_check",
            "source": "Whois 域名查询",
            "finding": whois_data.get("reason", "域名检查完成"),
            "risk_level": whois_data.get("risk_level", "low"),
            "details": {
                "domain": whois_data.get("domain"),
                "registered_hours_ago": whois_data.get("registered_hours_ago"),
                "registrar": whois_data.get("registrar")
            }
        })

    # 2. SPF/DKIM 证据
    if "spf_dkim" in tool_results:
        spf_data = tool_results["spf_dkim"]
        evidence_chain.append({
            "type": "email_authentication",
            "source": "SPF/DKIM 验证",
            "finding": "; ".join(spf_data.get("reasons", [])),
            "risk_level": spf_data.get("risk_level", "low"),
            "details": {
                "spf_result": spf_data.get("spf_result"),
                "dkim_result": spf_data.get("dkim_result"),
                "from_domain": spf_data.get("from_domain")
            }
        })

    # 3. URL 证据
    if "url_check" in tool_results:
        url_data = tool_results["url_check"]

        if isinstance(url_data, list):
            # 多个 URL
            for url_result in url_data:
                if url_result.get("risk_score", 0) > 0:
                    evidence_chain.append({
                        "type": "url_check",
                        "source": "URL 信誉检查",
                        "finding": "; ".join(url_result.get("reasons", [])),
                        "risk_level": url_result.get("risk_level", "low"),
                        "details": {
                            "url": url_result.get("url"),
                            "flags": url_result.get("flags", [])
                        }
                    })
        else:
            # 单个 URL
            evidence_chain.append({
                "type": "url_check",
                "source": "URL 信誉检查",
                "finding": "; ".join(url_data.get("reasons", [])),
                "risk_level": url_data.get("risk_level", "low"),
                "details": {
                    "url": url_data.get("url"),
                    "flags": url_data.get("flags", [])
                }
            })

    # 4. 附件证据
    if "attachment" in tool_results:
        att_data = tool_results["attachment"]
        if att_data.get("has_attachments"):
            evidence_chain.append({
                "type": "attachment_scan",
                "source": "附件扫描",
                "finding": f"检测到 {att_data.get('attachment_count', 0)} 个附件",
                "risk_level": att_data.get("risk_level", "low"),
                "details": {
                    "attachment_count": att_data.get("attachment_count"),
                    "attachment_details": att_data.get("attachment_details", [])
                }
            })

    # 5. 语义分析证据
    if "semantic" in tool_results:
        sem_data = tool_results["semantic"]
        evidence_chain.append({
            "type": "semantic_analysis",
            "source": "语义分析",
            "finding": "; ".join(sem_data.get("reasons", [])),
            "risk_level": sem_data.get("risk_level", "low"),
            "details": {
                "detected_patterns": sem_data.get("detected_patterns", []),
                "urgency_level": sem_data.get("urgency_level"),
                "has_authority_impersonation": sem_data.get("has_authority_impersonation"),
                "has_prompt_injection": sem_data.get("has_prompt_injection")
            }
        })

    return evidence_chain


def format_evidence_for_display(evidence_chain: List[Dict]) -> str:
    """
    将证据链格式化为易读的文本

    Args:
        evidence_chain: 证据链列表

    Returns:
        格式化后的文本
    """
    if not evidence_chain:
        return "未发现明显可疑证据"

    output = []
    for i, evidence in enumerate(evidence_chain, 1):
        risk_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "unknown": "⚪"
        }
        emoji = risk_emoji.get(evidence.get("risk_level", "low"), "⚪")

        output.append(f"{i}. {emoji} [{evidence['source']}] {evidence['finding']}")

    return "\n".join(output)


def get_top_risks(evidence_chain: List[Dict], top_n: int = 3) -> List[Dict]:
    """
    获取风险最高的前 N 条证据

    Args:
        evidence_chain: 证据链列表
        top_n: 返回前 N 条

    Returns:
        排序后的证据列表
    """
    risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

    sorted_evidence = sorted(
        evidence_chain,
        key=lambda x: risk_priority.get(x.get("risk_level", "low"), 0),
        reverse=True
    )

    return sorted_evidence[:top_n]
