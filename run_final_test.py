"""
最终测试脚本
运行 3 个复杂用例 + 3 个常见用例
"""

import os
import json
import time
from dotenv import load_dotenv
from agent.graph import run_detection


def print_banner():
    """打印横幅"""
    print("\n" + "=" * 80)
    print("  🛡️  钓鱼邮件检测 AI 智能体 - 最终测试")
    print("  测试用例: 3 个复杂场景 + 3 个常见场景")
    print("=" * 80 + "\n")


def print_result(email_data: dict, result: dict, test_num: int, total: int):
    """格式化打印检测结果"""
    print("\n" + "=" * 80)
    print(f"📊 测试 [{test_num}/{total}] - {email_data.get('name')}")
    print("=" * 80)

    if not result.get("success"):
        print(f"❌ 检测失败: {result.get('error')}")
        return

    # 基本信息
    print(f"\n📧 邮件ID: {result['email_id']}")
    print(f"📨 发件人: {email_data['headers']['from']}")
    print(f"📬 主题: {email_data['headers']['subject']}")

    # 风险评分
    risk_score = result['risk_score']
    risk_bar = "█" * (risk_score // 5) + "░" * (20 - risk_score // 5)
    print(f"\n🎯 风险评分: {risk_score}/100 [{risk_bar}]")

    # 决策
    decision_emoji = {
        "Block": "🔴 拦截 (Block)",
        "Quarantine": "🟡 隔离 (Quarantine)",
        "Allow": "🟢 放行 (Allow)"
    }
    print(f"⚖️  最终决策: {decision_emoji.get(result['decision'], result['decision'])}")
    print(f"📝 决策理由: {result['decision_reason']}")

    # LLM 分析
    print(f"\n🤖 LLM 分析:")
    print(f"   • 判定: {'🚨 钓鱼邮件' if result['is_phishing'] else '✅ 正常邮件'}")
    print(f"   • 置信度: {result['confidence']:.1%}")

    # 推理过程（简化显示）
    reasoning = result['llm_reasoning']
    if len(reasoning) > 300:
        reasoning = reasoning[:300] + "..."
    print(f"   • 推理摘要: {reasoning}")

    # 关键证据（最多显示3条）
    print(f"\n🔍 关键证据:")
    for i, evidence in enumerate(result['key_evidence'][:3], 1):
        print(f"   {i}. {evidence}")
    if len(result['key_evidence']) > 3:
        print(f"   ... (还有 {len(result['key_evidence']) - 3} 条证据)")

    # 安全标记
    if result['security_flags']['has_prompt_injection']:
        print(f"\n⚠️  安全警告: 检测到 Prompt Injection 攻击!")
        print(f"   攻击模式: {', '.join(result['security_flags']['injection_patterns'][:3])}")

    print("\n" + "=" * 80)


def run_final_test():
    """运行最终测试"""
    # 加载环境变量
    load_dotenv()

    # 检查 API Key
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("❌ 错误: 未设置 DEEPSEEK_API_KEY")
        return

    print_banner()
    print(f"🔑 API Key: {api_key[:20]}...")
    print(f"🌐 API Base: {os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')}")
    print("\n⏳ 开始测试，请稍候...\n")

    # 加载测试邮件
    test_file = os.path.join(os.path.dirname(__file__), "data", "test_emails.json")
    with open(test_file, "r", encoding="utf-8") as f:
        all_emails = json.load(f)

    # 筛选出目标测试用例
    target_ids = [
        "email_complex_001",  # 多层重定向 + IDN
        "email_complex_002",  # BEC攻击
        "email_complex_003",  # 混合攻击 + Prompt Injection
        "email_common_001",   # 标准钓鱼
        "email_common_002",   # 正常会议邀请
        "email_common_003",   # 正常营销邮件
    ]

    test_emails = [email for email in all_emails if email['id'] in target_ids]

    # 按照 target_ids 的顺序排序
    test_emails.sort(key=lambda x: target_ids.index(x['id']))

    if len(test_emails) != 6:
        print(f"⚠️  警告: 找到 {len(test_emails)} 个测试用例，预期 6 个")

    # 运行测试
    results = []
    start_time = time.time()

    for i, email in enumerate(test_emails, 1):
        print(f"\n{'='*80}")
        print(f"🔬 正在测试 [{i}/6]: {email.get('name')}")
        print(f"{'='*80}")

        try:
            result = run_detection(email)
            print_result(email, result, i, 6)

            results.append({
                "id": email.get("id"),
                "name": email.get("name"),
                "decision": result.get("decision"),
                "risk_score": result.get("risk_score"),
                "is_phishing": result.get("is_phishing"),
                "confidence": result.get("confidence"),
                "success": result.get("success")
            })

        except Exception as e:
            print(f"\n❌ 测试失败: {str(e)}")
            results.append({
                "id": email.get("id"),
                "name": email.get("name"),
                "success": False,
                "error": str(e)
            })

        # 间隔，避免 API 限流
        if i < len(test_emails):
            print("\n⏳ 等待 3 秒...")
            time.sleep(3)

    # 打印汇总
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 80)
    print("📈 测试汇总报告")
    print("=" * 80)

    print(f"\n⏱️  总耗时: {elapsed_time:.1f} 秒")
    print(f"✅ 成功: {sum(1 for r in results if r.get('success'))} / {len(results)}")

    print("\n📊 详细结果:")
    print(f"{'ID':<20} {'名称':<40} {'决策':<12} {'风险':<8} {'状态':<8}")
    print("-" * 80)

    for r in results:
        status = "✅" if r.get("success") else "❌"
        decision = r.get("decision", "N/A")
        risk = f"{r.get('risk_score', 0)}/100" if r.get("success") else "ERROR"
        name = r.get("name", "Unknown")[:38]

        print(f"{r['id']:<20} {name:<40} {decision:<12} {risk:<8} {status}")

    # 分类统计
    print(f"\n📋 分类统计:")
    blocked = sum(1 for r in results if r.get('decision') == 'Block')
    quarantined = sum(1 for r in results if r.get('decision') == 'Quarantine')
    allowed = sum(1 for r in results if r.get('decision') == 'Allow')

    print(f"   🔴 拦截 (Block): {blocked}")
    print(f"   🟡 隔离 (Quarantine): {quarantined}")
    print(f"   🟢 放行 (Allow): {allowed}")

    # 预期结果对比
    print(f"\n🎯 预期结果对比:")
    expected_phishing = ["email_complex_001", "email_complex_002", "email_complex_003", "email_common_001"]
    expected_normal = ["email_common_002", "email_common_003"]

    correct_phishing = sum(1 for r in results if r['id'] in expected_phishing and r.get('decision') in ['Block', 'Quarantine'])
    correct_normal = sum(1 for r in results if r['id'] in expected_normal and r.get('decision') == 'Allow')

    print(f"   钓鱼检出: {correct_phishing}/{len(expected_phishing)} (应拦截/隔离)")
    print(f"   正常放行: {correct_normal}/{len(expected_normal)} (应放行)")
    print(f"   总准确率: {(correct_phishing + correct_normal) / 6 * 100:.1f}%")

    print("\n" + "=" * 80)
    print("✅ 测试完成!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_final_test()
