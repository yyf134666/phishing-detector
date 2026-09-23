"""
LangGraph 状态机定义
构建完整的 Agent 工作流
"""

from langgraph.graph import StateGraph, END
from agent.nodes import (
    AgentState,
    parse_email_node,
    execute_tools_node,
    llm_reasoning_node,
    make_decision_node
)


def create_agent_graph():
    """
    创建 LangGraph 状态机

    工作流:
    1. parse_email: 解析邮件并清洗输入
    2. execute_tools: 并行执行所有检测工具
    3. llm_reasoning: LLM 基于证据进行推理
    4. make_decision: 综合决策并输出结果
    """
    # 创建状态图
    workflow = StateGraph(AgentState)

    # 添加节点
    workflow.add_node("parse_email", parse_email_node)
    workflow.add_node("execute_tools", execute_tools_node)
    workflow.add_node("llm_reasoning", llm_reasoning_node)
    workflow.add_node("make_decision", make_decision_node)

    # 定义边（节点之间的转换）
    workflow.set_entry_point("parse_email")

    # parse_email -> execute_tools（如果没有错误）
    workflow.add_conditional_edges(
        "parse_email",
        lambda state: "error" if state.get("error") else "continue",
        {
            "error": END,
            "continue": "execute_tools"
        }
    )

    # execute_tools -> llm_reasoning
    workflow.add_edge("execute_tools", "llm_reasoning")

    # llm_reasoning -> make_decision
    workflow.add_edge("llm_reasoning", "make_decision")

    # make_decision -> END
    workflow.add_edge("make_decision", END)

    # 编译图
    app = workflow.compile()

    return app


def run_detection(email_data: dict) -> dict:
    """
    运行钓鱼邮件检测

    Args:
        email_data: 邮件数据字典

    Returns:
        检测结果字典
    """
    # 创建 Agent 图
    app = create_agent_graph()

    # 初始化状态
    initial_state = {
        "email_data": email_data,
        "sanitized_body": "",
        "has_injection_attempt": False,
        "injection_patterns": [],
        "domains_to_check": [],
        "tool_results": {},
        "llm_analysis": {},
        "risk_score": 0,
        "evidence_chain": [],
        "final_decision": "",
        "decision_reason": "",
        "error": ""
    }

    # 运行工作流
    print("=" * 60)
    print("🚀 钓鱼邮件检测 Agent 启动")
    print("=" * 60)

    final_state = app.invoke(initial_state)

    # 检查是否有错误
    if final_state.get("error"):
        return {
            "success": False,
            "error": final_state["error"]
        }

    # 构建返回结果
    result = {
        "success": True,
        "email_id": email_data.get("id", "unknown"),
        "risk_score": final_state["risk_score"],
        "decision": final_state["final_decision"],
        "decision_reason": final_state["decision_reason"],
        "is_phishing": final_state["llm_analysis"].get("is_phishing", False),
        "confidence": final_state["llm_analysis"].get("confidence", 0.0),
        "llm_reasoning": final_state["llm_analysis"].get("reasoning", ""),
        "key_evidence": final_state["llm_analysis"].get("key_evidence", []),
        "evidence_chain": final_state["evidence_chain"],
        "tool_results": final_state["tool_results"],
        "security_flags": {
            "has_prompt_injection": final_state["has_injection_attempt"],
            "injection_patterns": final_state["injection_patterns"]
        }
    }

    return result
