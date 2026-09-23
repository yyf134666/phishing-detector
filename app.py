"""
Gradio Web UI for Phishing Email Detector
提供可视化的邮件检测界面和测试管理
"""

import gradio as gr
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from agent.graph import run_detection

# 加载环境变量
load_dotenv()


def load_test_cases():
    """加载所有测试用例"""
    test_file = os.path.join(os.path.dirname(__file__), "data", "test_emails.json")
    with open(test_file, "r", encoding="utf-8") as f:
        emails = json.load(f)
    return {email["id"]: email for email in emails}


TEST_CASES = load_test_cases()


def format_result_html(result: dict, email_data: dict) -> str:
    """将检测结果格式化为HTML"""
    if not result.get("success"):
        return f"""
        <div style="padding: 20px; background: #fee; border-left: 4px solid #f00; border-radius: 5px;">
            <h3>❌ 检测失败</h3>
            <p>{result.get('error', '未知错误')}</p>
        </div>
        """

    # 决策颜色
    decision_colors = {
        "Block": "#dc3545",
        "Quarantine": "#ffc107",
        "Allow": "#28a745"
    }
    decision_emojis = {
        "Block": "🔴",
        "Quarantine": "🟡",
        "Allow": "🟢"
    }

    decision = result["decision"]
    color = decision_colors.get(decision, "#6c757d")
    emoji = decision_emojis.get(decision, "⚪")

    # 风险进度条
    risk_score = result["risk_score"]
    risk_bar_width = risk_score
    risk_bar_color = "#dc3545" if risk_score >= 70 else "#ffc107" if risk_score >= 40 else "#28a745"

    html = f"""
    <div style="font-family: Arial, sans-serif;">
        <!-- 头部信息 -->
        <div style="padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; margin-bottom: 20px;">
            <h2 style="margin: 0;">📧 检测报告</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">邮件ID: {result["email_id"]}</p>
        </div>

        <!-- 邮件基本信息 -->
        <div style="padding: 15px; background: #f8f9fa; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin-top: 0;">📨 邮件信息</h3>
            <p><strong>发件人:</strong> {email_data['headers']['from']}</p>
            <p><strong>收件人:</strong> {email_data['headers']['to']}</p>
            <p><strong>主题:</strong> {email_data['headers']['subject']}</p>
        </div>

        <!-- 风险评分 -->
        <div style="padding: 15px; background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin-top: 0;">🎯 风险评分</h3>
            <div style="display: flex; align-items: center; gap: 15px;">
                <div style="font-size: 48px; font-weight: bold; color: {risk_bar_color};">{risk_score}</div>
                <div style="flex: 1;">
                    <div style="background: #e9ecef; border-radius: 10px; height: 30px; overflow: hidden;">
                        <div style="width: {risk_bar_width}%; height: 100%; background: {risk_bar_color}; transition: width 0.3s;"></div>
                    </div>
                    <p style="margin: 5px 0 0 0; color: #6c757d; font-size: 14px;">风险等级: {"高危" if risk_score >= 70 else "中等" if risk_score >= 40 else "低风险"}</p>
                </div>
            </div>
        </div>

        <!-- 最终决策 -->
        <div style="padding: 20px; background: {color}; color: white; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin-top: 0;">{emoji} 最终决策: {decision}</h3>
            <p style="margin: 0;">{result["decision_reason"]}</p>
        </div>

        <!-- LLM 分析 -->
        <div style="padding: 15px; background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin-top: 0;">🤖 AI 分析</h3>
            <p><strong>判定:</strong> {"🚨 钓鱼邮件" if result["is_phishing"] else "✅ 正常邮件"}</p>
            <p><strong>置信度:</strong> {result["confidence"]:.1%}</p>
            <div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <strong>推理过程:</strong>
                <p style="margin-top: 10px; line-height: 1.6;">{result["llm_reasoning"][:500]}{"..." if len(result["llm_reasoning"]) > 500 else ""}</p>
            </div>
        </div>

        <!-- 关键证据 -->
        <div style="padding: 15px; background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin-top: 0;">🔍 关键证据</h3>
            <ol style="line-height: 1.8;">
    """

    for evidence in result["key_evidence"][:5]:
        html += f"<li>{evidence}</li>"

    html += """
            </ol>
        </div>

        <!-- 安全标记 -->
    """

    if result["security_flags"]["has_prompt_injection"]:
        patterns = ", ".join(result["security_flags"]["injection_patterns"][:3])
        html += f"""
        <div style="padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 8px;">
            <h4 style="margin-top: 0;">⚠️ 安全警告</h4>
            <p>检测到 <strong>Prompt Injection</strong> 攻击尝试！</p>
            <p style="margin: 0; font-size: 14px; color: #856404;">攻击模式: {patterns}</p>
        </div>
        """

    html += """
    </div>
    """

    return html


def detect_email_from_json(json_input: str):
    """从JSON输入检测邮件"""
    try:
        email_data = json.loads(json_input)
        result = run_detection(email_data)
        html_output = format_result_html(result, email_data)
        return html_output, json.dumps(result, indent=2, ensure_ascii=False)
    except json.JSONDecodeError as e:
        return f"<div style='color: red;'>JSON 格式错误: {str(e)}</div>", ""
    except Exception as e:
        return f"<div style='color: red;'>检测失败: {str(e)}</div>", ""


def detect_email_from_form(from_addr, to_addr, subject, body, spf, dkim, links_text):
    """从表单检测邮件"""
    try:
        # 解析链接
        links = []
        if links_text.strip():
            for line in links_text.strip().split("\n"):
                if line.strip():
                    links.append({"original": line.strip()})

        email_data = {
            "id": f"manual_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "headers": {
                "from": from_addr,
                "to": to_addr,
                "subject": subject,
                "spf_result": spf,
                "dkim_result": dkim
            },
            "body_text": body,
            "links": links,
            "attachments": []
        }

        result = run_detection(email_data)
        html_output = format_result_html(result, email_data)
        return html_output, json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"<div style='color: red;'>检测失败: {str(e)}</div>", ""


def run_selected_tests(selected_tests):
    """运行选中的测试用例"""
    if not selected_tests:
        return "<div style='color: orange;'>请至少选择一个测试用例</div>", ""

    results = []
    summary_html = "<div style='font-family: Arial, sans-serif;'>"
    summary_html += "<h2>📊 批量测试报告</h2>"

    for test_id in selected_tests:
        email = TEST_CASES[test_id]
        result = run_detection(email)
        results.append({
            "id": test_id,
            "name": email.get("name", test_id),
            "decision": result.get("decision", "ERROR"),
            "risk_score": result.get("risk_score", 0),
            "success": result.get("success", False)
        })

    # 汇总统计
    success_count = sum(1 for r in results if r["success"])
    block_count = sum(1 for r in results if r["decision"] == "Block")
    quarantine_count = sum(1 for r in results if r["decision"] == "Quarantine")
    allow_count = sum(1 for r in results if r["decision"] == "Allow")

    summary_html += f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0;">
        <div style="padding: 15px; background: #e7f3ff; border-radius: 8px; text-align: center;">
            <div style="font-size: 32px; font-weight: bold; color: #0066cc;">{success_count}/{len(results)}</div>
            <div>成功检测</div>
        </div>
        <div style="padding: 15px; background: #ffe7e7; border-radius: 8px; text-align: center;">
            <div style="font-size: 32px; font-weight: bold; color: #dc3545;">🔴 {block_count}</div>
            <div>拦截</div>
        </div>
        <div style="padding: 15px; background: #fff9e7; border-radius: 8px; text-align: center;">
            <div style="font-size: 32px; font-weight: bold; color: #ffc107;">🟡 {quarantine_count}</div>
            <div>隔离</div>
        </div>
        <div style="padding: 15px; background: #e7ffe7; border-radius: 8px; text-align: center;">
            <div style="font-size: 32px; font-weight: bold; color: #28a745;">🟢 {allow_count}</div>
            <div>放行</div>
        </div>
    </div>
    """

    # 详细结果表格
    summary_html += """
    <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
        <thead style="background: #f8f9fa;">
            <tr>
                <th style="padding: 12px; text-align: left; border: 1px solid #dee2e6;">测试ID</th>
                <th style="padding: 12px; text-align: left; border: 1px solid #dee2e6;">名称</th>
                <th style="padding: 12px; text-align: center; border: 1px solid #dee2e6;">决策</th>
                <th style="padding: 12px; text-align: center; border: 1px solid #dee2e6;">风险分数</th>
                <th style="padding: 12px; text-align: center; border: 1px solid #dee2e6;">状态</th>
            </tr>
        </thead>
        <tbody>
    """

    for r in results:
        status_icon = "✅" if r["success"] else "❌"
        decision_color = {"Block": "#dc3545", "Quarantine": "#ffc107", "Allow": "#28a745"}.get(r["decision"], "#6c757d")

        summary_html += f"""
        <tr>
            <td style="padding: 10px; border: 1px solid #dee2e6;">{r["id"]}</td>
            <td style="padding: 10px; border: 1px solid #dee2e6;">{r["name"][:50]}</td>
            <td style="padding: 10px; border: 1px solid #dee2e6; text-align: center; color: {decision_color}; font-weight: bold;">{r["decision"]}</td>
            <td style="padding: 10px; border: 1px solid #dee2e6; text-align: center;">{r["risk_score"]}/100</td>
            <td style="padding: 10px; border: 1px solid #dee2e6; text-align: center;">{status_icon}</td>
        </tr>
        """

    summary_html += """
        </tbody>
    </table>
    </div>
    """

    return summary_html, json.dumps(results, indent=2, ensure_ascii=False)


# 创建 Gradio 界面
def create_ui():
    """创建 Gradio UI"""
    with gr.Blocks(title="钓鱼邮件检测 AI 智能体", theme=gr.themes.Soft()) as app:
        gr.Markdown("""
        # 🛡️ 钓鱼邮件检测 AI 智能体
        **基于 LangGraph + DeepSeek-V4.1 | 支持多模态分析、推理链展示、Prompt Injection 防御**
        """)

        with gr.Tabs():
            # Tab 1: 手动输入检测
            with gr.Tab("📝 手动输入"):
                gr.Markdown("### 填写邮件信息进行检测")

                with gr.Row():
                    with gr.Column():
                        from_input = gr.Textbox(label="发件人", placeholder="sender@example.com")
                        to_input = gr.Textbox(label="收件人", placeholder="recipient@company.com")
                        subject_input = gr.Textbox(label="主题", placeholder="邮件主题")

                    with gr.Column():
                        spf_input = gr.Dropdown(choices=["pass", "fail", "softfail", "none"], label="SPF 结果", value="pass")
                        dkim_input = gr.Dropdown(choices=["pass", "fail", "none"], label="DKIM 结果", value="pass")

                body_input = gr.Textbox(label="邮件正文", placeholder="邮件内容...", lines=5)
                links_input = gr.Textbox(label="链接（每行一个）", placeholder="https://example.com\nhttp://phishing.com", lines=3)

                detect_form_btn = gr.Button("🔍 检测邮件", variant="primary")

                with gr.Row():
                    form_result_html = gr.HTML(label="检测结果")

                with gr.Accordion("查看原始 JSON 结果", open=False):
                    form_result_json = gr.Code(language="json", label="JSON 输出")

                detect_form_btn.click(
                    detect_email_from_form,
                    inputs=[from_input, to_input, subject_input, body_input, spf_input, dkim_input, links_input],
                    outputs=[form_result_html, form_result_json]
                )

            # Tab 2: JSON 输入检测
            with gr.Tab("📋 JSON 输入"):
                gr.Markdown("### 使用 JSON 格式输入邮件数据")

                json_input = gr.Code(
                    language="json",
                    label="邮件 JSON 数据",
                    value=json.dumps({
                        "id": "example_001",
                        "headers": {
                            "from": "sender@example.com",
                            "to": "recipient@company.com",
                            "subject": "Test Email",
                            "spf_result": "pass",
                            "dkim_result": "pass"
                        },
                        "body_text": "This is a test email.",
                        "links": [{"original": "https://example.com"}],
                        "attachments": []
                    }, indent=2),
                    lines=15
                )

                detect_json_btn = gr.Button("🔍 检测邮件", variant="primary")

                with gr.Row():
                    json_result_html = gr.HTML(label="检测结果")

                with gr.Accordion("查看原始 JSON 结果", open=False):
                    json_result_json = gr.Code(language="json", label="JSON 输出")

                detect_json_btn.click(
                    detect_email_from_json,
                    inputs=[json_input],
                    outputs=[json_result_html, json_result_json]
                )

            # Tab 3: 测试用例管理
            with gr.Tab("🧪 测试用例"):
                gr.Markdown("### 选择并运行预定义的测试用例")

                test_choices = [f"{test_id}: {email.get('name', test_id)}" for test_id, email in TEST_CASES.items()]
                test_checkbox = gr.CheckboxGroup(
                    choices=test_choices,
                    label="选择测试用例",
                    value=[]
                )

                gr.Markdown("**快速选择:**")
                with gr.Row():
                    select_complex_btn = gr.Button("选择复杂用例")
                    select_common_btn = gr.Button("选择常见用例")
                    select_all_btn = gr.Button("全选")
                    clear_btn = gr.Button("清空")

                run_tests_btn = gr.Button("▶️ 运行选中的测试", variant="primary")

                with gr.Row():
                    test_result_html = gr.HTML(label="测试结果")

                with gr.Accordion("查看原始 JSON 结果", open=False):
                    test_result_json = gr.Code(language="json", label="JSON 输出")

                def select_complex():
                    return [c for c in test_choices if "复杂用例" in c]

                def select_common():
                    return [c for c in test_choices if "常见用例" in c]

                def select_all():
                    return test_choices

                def clear_selection():
                    return []

                select_complex_btn.click(select_complex, outputs=[test_checkbox])
                select_common_btn.click(select_common, outputs=[test_checkbox])
                select_all_btn.click(select_all, outputs=[test_checkbox])
                clear_btn.click(clear_selection, outputs=[test_checkbox])

                def run_tests_wrapper(selected):
                    # 提取 test_id
                    test_ids = [s.split(":")[0] for s in selected]
                    return run_selected_tests(test_ids)

                run_tests_btn.click(
                    run_tests_wrapper,
                    inputs=[test_checkbox],
                    outputs=[test_result_html, test_result_json]
                )

            # Tab 4: 系统信息
            with gr.Tab("ℹ️ 系统信息"):
                gr.Markdown("""
                ### 系统配置

                **模型**: DeepSeek-V4.1-Flash
                **框架**: LangGraph + LangChain
                **工具数量**: 5 个检测工具（Whois, SPF/DKIM, URL, 附件, 语义）

                ### 功能特性

                - ✅ 多模态分析（文本、域名、URL、附件、邮件头）
                - ✅ Prompt Injection 防御
                - ✅ 完整推理链展示
                - ✅ 规则 + LLM 混合决策
                - ✅ 可解释的证据链

                ### 风险等级

                - **0-30分**: 🟢 低风险 → 放行 (Allow)
                - **30-70分**: 🟡 中等风险 → 隔离 (Quarantine)
                - **70-100分**: 🔴 高风险 → 拦截 (Block)

                ### 测试用例

                总计 **16** 个测试用例，包括：
                - 3 个复杂场景（多层重定向、BEC、混合攻击）
                - 3 个常见场景（标准钓鱼、正常邮件）
                - 10 个基础场景

                ### 使用说明

                1. **手动输入**: 适合测试自定义邮件
                2. **JSON 输入**: 适合批量导入或 API 集成
                3. **测试用例**: 快速验证系统能力

                ### API Key 配置

                请确保在 `.env` 文件中设置了 `DEEPSEEK_API_KEY`。

                ---
                **版本**: v1.0.0 | **开发**: TDD + SDD
                """)

        gr.Markdown("""
        ---
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
            🛡️ Phishing Email Detector | Powered by LangGraph + DeepSeek-V4.1
        </div>
        """)

    return app


if __name__ == "__main__":
    # 检查 API Key
    if not os.getenv("DEEPSEEK_API_KEY"):
        print("⚠️  警告: 未设置 DEEPSEEK_API_KEY 环境变量")
        print("请在 .env 文件中添加: DEEPSEEK_API_KEY=your_key_here")

    app = create_ui()
    app.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True
    )
