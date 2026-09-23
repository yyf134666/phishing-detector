"""
LangGraph 节点定义
包含 Agent 的各个处理节点
"""

from typing import TypedDict, List, Dict, Annotated
import operator
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import json
import os

from tools import (
    WhoisQueryTool,
    URLCheckerTool,
    SPFValidatorTool,
    AttachmentScannerTool,
    SemanticAnalyzerTool
)
from utils import sanitize_email_body, validate_email_structure, extract_domains_from_email
from agent.prompts import SYSTEM_PROMPT, build_reasoning_prompt


class AgentState(TypedDict):
    """Agent 状态"""
    email_data: dict                    # 原始邮件数据
    sanitized_body: str                 # 清洗后的邮件正文
    has_injection_attempt: bool         # 是否检测到注入攻击
    injection_patterns: List[str]       # 检测到的注入模式
    domains_to_check: List[str]         # 需要检查的域名列表
    tool_results: Dict                  # 工具检测结果
    llm_analysis: Dict                  # LLM 分析结果
    risk_score: int                     # 风险评分 (0-100)
    evidence_chain: List[Dict]          # 证据链
    final_decision: str                 # 最终决策 (Block/Quarantine/Allow)
    decision_reason: str                # 决策理由
    error: str                          # 错误信息


def parse_email_node(state: AgentState) -> AgentState:
    """
    节点 1: 解析邮件并清洗输入
    """
    email_data = state["email_data"]

    # 验证邮件结构
    is_valid, error_msg = validate_email_structure(email_data)
    if not is_valid:
        state["error"] = f"邮件数据格式错误: {error_msg}"
        return state

    # 清洗邮件正文（防御 Prompt Injection）
    body_text = email_data.get("body_text", "")
    sanitized, has_suspicious, patterns = sanitize_email_body(body_text)

    state["sanitized_body"] = sanitized
    state["has_injection_attempt"] = has_suspicious
    state["injection_patterns"] = patterns

    # 提取需要检查的域名
    from_address = email_data.get("headers", {}).get("from", "")
    urls = email_data.get("links", [])
    domains = extract_domains_from_email(from_address, urls)

    state["domains_to_check"] = domains

    print(f"✅ 邮件解析完成")
    if has_suspicious:
        print(f"⚠️  检测到可疑内容，已过滤: {patterns}")

    return state


def execute_tools_node(state: AgentState) -> AgentState:
    """
    节点 2: 执行所有检测工具
    """
    email_data = state["email_data"]
    tool_results = {}

    print("\n🔍 开始执行检测工具...")

    # 1. Whois 查询（检查发件人域名）
    try:
        whois_tool = WhoisQueryTool()
        from_domain = email_data.get("headers", {}).get("from", "").split("@")[-1]
        if from_domain:
            whois_result = whois_tool._run(from_domain)
            tool_results["whois"] = whois_result
            print(f"  ✓ Whois 查询完成: {from_domain} - {whois_result.get('risk_level', 'unknown')}")
    except Exception as e:
        print(f"  ✗ Whois 查询失败: {e}")
        tool_results["whois"] = {"error": str(e)}

    # 2. SPF/DKIM 验证
    try:
        spf_tool = SPFValidatorTool()
        headers_json = json.dumps(email_data.get("headers", {}))
        spf_result = spf_tool._run(headers_json)
        tool_results["spf_dkim"] = spf_result
        print(f"  ✓ SPF/DKIM 验证完成: {spf_result.get('risk_level', 'unknown')}")
    except Exception as e:
        print(f"  ✗ SPF/DKIM 验证失败: {e}")
        tool_results["spf_dkim"] = {"error": str(e)}

    # 3. URL 检查
    try:
        url_tool = URLCheckerTool()
        links = email_data.get("links", [])

        if links:
            url_results = []
            for link in links:
                url = link.get("original", link) if isinstance(link, dict) else link
                url_result = url_tool._run(url)
                url_results.append(url_result)
                print(f"  ✓ URL 检查完成: {url[:50]}... - {url_result.get('risk_level', 'unknown')}")

            # 始终返回列表，保持一致性
            tool_results["url_check"] = url_results
        else:
            tool_results["url_check"] = {"risk_score": 0, "risk_level": "low", "reasons": ["邮件无链接"]}
            print(f"  - 跳过 URL 检查: 邮件无链接")
    except Exception as e:
        print(f"  ✗ URL 检查失败: {e}")
        tool_results["url_check"] = {"error": str(e)}

    # 4. 附件扫描
    try:
        attachment_tool = AttachmentScannerTool()
        attachments = email_data.get("attachments", [])

        if attachments:
            attachments_json = json.dumps(attachments)
            attachment_result = attachment_tool._run(attachments_json)
            tool_results["attachment"] = attachment_result
            print(f"  ✓ 附件扫描完成: {attachment_result.get('risk_level', 'unknown')}")
        else:
            tool_results["attachment"] = {"has_attachments": False, "risk_score": 0, "risk_level": "low"}
            print(f"  - 跳过附件扫描: 邮件无附件")
    except Exception as e:
        print(f"  ✗ 附件扫描失败: {e}")
        tool_results["attachment"] = {"error": str(e)}

    # 5. 语义分析
    try:
        semantic_tool = SemanticAnalyzerTool()
        subject = email_data.get("headers", {}).get("subject", "")
        body = state["sanitized_body"]  # 使用清洗后的正文

        semantic_result = semantic_tool._run(email_body=body, email_subject=subject)
        tool_results["semantic"] = semantic_result
        print(f"  ✓ 语义分析完成: {semantic_result.get('risk_level', 'unknown')}")
    except Exception as e:
        print(f"  ✗ 语义分析失败: {e}")
        tool_results["semantic"] = {"error": str(e)}

    state["tool_results"] = tool_results
    print("✅ 所有工具执行完成\n")

    return state


def llm_reasoning_node(state: AgentState) -> AgentState:
    """
    节点 3: LLM 推理分析
    """
    print("🤖 LLM 开始推理...")

    # 构建推理 Prompt
    prompt = build_reasoning_prompt(state["email_data"], state["tool_results"])

    # 调用 LLM
    try:
        api_key = os.getenv("DEEPSEEK_API_KEY")
        base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")

        if not api_key:
            raise ValueError("未设置 DEEPSEEK_API_KEY 环境变量")

        llm = ChatOpenAI(
            model="deepseek-chat",
            api_key=api_key,
            base_url=base_url,
            temperature=0.1,  # 低温度，更确定性的输出
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ]

        response = llm.invoke(messages)
        response_text = response.content

        # 解析 JSON 响应
        # 尝试提取 JSON（可能被包裹在 markdown 代码块中）
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        llm_analysis = json.loads(response_text)

        state["llm_analysis"] = llm_analysis
        print(f"✅ LLM 推理完成")
        print(f"   判断: {'是钓鱼邮件' if llm_analysis.get('is_phishing') else '非钓鱼邮件'}")
        print(f"   置信度: {llm_analysis.get('confidence', 0):.2%}")

    except json.JSONDecodeError as e:
        print(f"⚠️  LLM 返回格式错误，使用默认分析")
        state["llm_analysis"] = {
            "is_phishing": True,
            "confidence": 0.5,
            "reasoning": f"LLM 返回解析失败: {e}，基于工具结果做保守判断",
            "key_evidence": ["工具检测结果"],
            "recommendation": "Quarantine"
        }
    except Exception as e:
        print(f"❌ LLM 调用失败: {e}")
        state["error"] = f"LLM 调用失败: {str(e)}"
        # 设置默认分析
        state["llm_analysis"] = {
            "is_phishing": True,
            "confidence": 0.5,
            "reasoning": "LLM 不可用，基于工具结果做保守判断",
            "key_evidence": ["工具检测结果"],
            "recommendation": "Quarantine"
        }

    return state


def make_decision_node(state: AgentState) -> AgentState:
    """
    节点 4: 综合决策
    """
    from utils import calculate_risk_score, make_decision
    from utils.risk_scorer import override_decision_if_needed

    print("\n⚖️  综合决策中...")

    # 计算风险评分和证据链
    risk_score, evidence_chain = calculate_risk_score(state["tool_results"])
    state["risk_score"] = risk_score
    state["evidence_chain"] = evidence_chain

    # 基于规则的决策
    rule_decision, rule_reason = make_decision(risk_score, state["tool_results"])

    # LLM 的建议决策
    llm_recommendation = state["llm_analysis"].get("recommendation", "Quarantine")

    # 决策覆盖逻辑：取更严格的决策
    final_decision, final_reason, was_overridden = override_decision_if_needed(
        llm_recommendation, rule_decision, rule_reason
    )

    state["final_decision"] = final_decision
    state["decision_reason"] = final_reason

    print(f"✅ 决策完成")
    print(f"   风险评分: {risk_score}/100")
    print(f"   最终决策: {final_decision}")
    if was_overridden:
        print(f"   ⚠️  {final_reason}")

    return state
