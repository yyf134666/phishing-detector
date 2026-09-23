"""
主程序入口
运行钓鱼邮件检测系统
"""

import os
import json
from dotenv import load_dotenv
from agent.graph import run_detection


def print_banner():
    """打印横幅"""
    print("\n" + "=" * 70)
    print("  🛡️  钓鱼邮件检测 AI 智能体 v1.0")
    print("  基于 LangGraph + DeepSeek-V4.1")
    print("=" * 70 + "\n")


def print_result(result: dict):
    """格式化打印检测结果"""
    print("\n" + "=" * 70)
    print("📊 检测报告")
    print("=" * 70)

    if not result.get("success"):
        print(f"❌ 检测失败: {result.get('error')}")
        return

    # 基本信息
    print(f"\n📧 邮件ID: {result['email_id']}")
    print(f"🎯 风险评分: {result['risk_score']}/100")

    # 决策
    decision_emoji = {
        "Block": "🔴 拦截",
        "Quarantine": "🟡 隔离",
        "Allow": "🟢 放行"
    }
    print(f"⚖️  最终决策: {decision_emoji.get(result['decision'], result['decision'])}")
    print(f"📝 决策理由: {result['decision_reason']}")

    # LLM 分析
    print(f"\n🤖 LLM 判断:")
    print(f"   是否钓鱼: {'是' if result['is_phishing'] else '否'}")
    print(f"   置信度: {result['confidence']:.1%}")
    print(f"   推理过程:\n   {result['llm_reasoning']}")

    # 关键证据
    print(f"\n🔍 关键证据:")
    for i, evidence in enumerate(result['key_evidence'], 1):
        print(f"   {i}. {evidence}")

    # 证据链（详细）
    print(f"\n📋 完整证据链:")
    for evidence in result['evidence_chain'][:5]:  # 只显示前5条
        print(f"   • [{evidence['source']}] "
              f"风险贡献: {evidence['risk_contribution']}分 "
              f"(权重: {evidence['weight']:.1%})")
        print(f"     {evidence['detail']}")

    # 安全标记
    if result['security_flags']['has_prompt_injection']:
        print(f"\n⚠️  安全警告: 检测到 Prompt Injection 攻击尝试!")
        print(f"   攻击模式: {result['security_flags']['injection_patterns']}")

    print("\n" + "=" * 70 + "\n")


def load_test_emails():
    """加载测试邮件"""
    test_file = os.path.join(os.path.dirname(__file__), "data", "test_emails.json")
    with open(test_file, "r", encoding="utf-8") as f:
        return json.load(f)


def run_single_test(email_data: dict):
    """运行单个测试"""
    print(f"\n{'='*70}")
    print(f"测试邮件: {email_data.get('name', email_data.get('id'))}")
    print(f"{'='*70}")

    result = run_detection(email_data)
    print_result(result)

    return result


def run_batch_test():
    """批量测试所有邮件"""
    print_banner()
    print("🧪 批量测试模式\n")

    test_emails = load_test_emails()
    results = []

    for email in test_emails:
        result = run_single_test(email)
        results.append({
            "email_id": email.get("id"),
            "name": email.get("name"),
            "expected": "phishing" if "钓鱼" in email.get("name", "") or "Prompt" in email.get("name", "") else "normal",
            "decision": result.get("decision"),
            "risk_score": result.get("risk_score"),
            "success": result.get("success")
        })

        # 暂停以便查看
        input("\n按 Enter 继续下一个测试...")

    # 打印汇总
    print("\n" + "=" * 70)
    print("📈 测试汇总")
    print("=" * 70)

    for r in results:
        status = "✅" if r["success"] else "❌"
        print(f"{status} {r['email_id']}: {r['name']}")
        print(f"   决策: {r['decision']}, 风险分数: {r['risk_score']}")

    print("\n" + "=" * 70)


def run_interactive():
    """交互式测试"""
    print_banner()
    print("🎮 交互式测试模式\n")
    print("请输入邮件 JSON 数据（输入 'test' 加载测试邮件）:")

    while True:
        user_input = input("\n> ").strip()

        if user_input.lower() == "exit":
            print("👋 再见!")
            break

        if user_input.lower() == "test":
            test_emails = load_test_emails()
            print(f"\n加载了 {len(test_emails)} 封测试邮件")
            for i, email in enumerate(test_emails, 1):
                print(f"  {i}. {email.get('name')} ({email.get('id')})")

            choice = input("\n选择邮件编号（或输入 'all' 测试全部）: ").strip()

            if choice.lower() == "all":
                run_batch_test()
                break
            else:
                try:
                    idx = int(choice) - 1
                    email_data = test_emails[idx]
                    run_single_test(email_data)
                except (ValueError, IndexError):
                    print("❌ 无效的选择")
        else:
            try:
                email_data = json.loads(user_input)
                run_single_test(email_data)
            except json.JSONDecodeError:
                print("❌ 无效的 JSON 格式")


def main():
    """主函数"""
    # 加载环境变量
    load_dotenv()

    # 检查 API Key
    if not os.getenv("DEEPSEEK_API_KEY"):
        print("❌ 错误: 未设置 DEEPSEEK_API_KEY 环境变量")
        print("\n请创建 .env 文件并添加:")
        print("DEEPSEEK_API_KEY=your_api_key_here")
        print("DEEPSEEK_BASE_URL=https://api.deepseek.com/v1")
        return

    # 选择运行模式
    print_banner()
    print("请选择运行模式:")
    print("  1. 批量测试（运行所有测试用例）")
    print("  2. 交互式测试（手动输入或选择邮件）")
    print("  3. 快速演示（测试前3个用例）")

    choice = input("\n请选择 (1/2/3): ").strip()

    if choice == "1":
        run_batch_test()
    elif choice == "2":
        run_interactive()
    elif choice == "3":
        test_emails = load_test_emails()
        for email in test_emails[:3]:
            run_single_test(email)
            input("\n按 Enter 继续...")
    else:
        print("❌ 无效的选择")


if __name__ == "__main__":
    main()
