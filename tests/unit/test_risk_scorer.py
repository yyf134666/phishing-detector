"""
单元测试：风险评分算法
"""
import pytest
from utils.risk_scorer import calculate_risk_score, make_decision, override_decision_if_needed


class TestCalculateRiskScore:
    """风险评分测试"""

    def test_high_risk_domain_contributes_score(self):
        """测试高风险域名应贡献分数"""
        tool_results = {
            "whois": {
                "registered_hours_ago": 12,
                "risk_level": "critical",
                "risk_score": 100,
                "reason": "域名注册不足24小时"
            }
        }
        score, evidence = calculate_risk_score(tool_results)

        assert score >= 30  # 域名权重30%
        assert len(evidence) > 0
        assert evidence[0]["source"] == "Whois 域名查询"

    def test_spf_dkim_failure_contributes_score(self):
        """测试SPF/DKIM失败应贡献分数"""
        tool_results = {
            "spf_dkim": {
                "spf_result": "fail",
                "dkim_result": "fail",
                "risk_score": 40,
                "risk_level": "high",
                "reasons": ["SPF验证失败", "DKIM验证失败"]
            }
        }
        score, evidence = calculate_risk_score(tool_results)

        assert score > 0
        assert any(e["source"] == "SPF/DKIM 验证" for e in evidence)

    def test_multiple_urls_take_max_risk(self):
        """测试多个URL应取最高风险"""
        tool_results = {
            "url_check": [
                {"risk_score": 20, "risk_level": "medium", "reasons": ["短链接"]},
                {"risk_score": 50, "risk_level": "high", "reasons": ["黑名单域名"]},
                {"risk_score": 10, "risk_level": "low", "reasons": ["无异常"]}
            ]
        }
        score, evidence = calculate_risk_score(tool_results)

        # 应该取最高的50分
        assert score >= 12  # 50 * 0.25 = 12.5

    def test_empty_tool_results_zero_score(self):
        """测试空结果应返回0分"""
        tool_results = {}
        score, evidence = calculate_risk_score(tool_results)

        assert score == 0
        assert len(evidence) == 0

    def test_evidence_chain_sorted_by_contribution(self):
        """测试证据链应按贡献度排序"""
        tool_results = {
            "whois": {
                "registered_hours_ago": 12,
                "risk_score": 100,
                "risk_level": "critical",
                "reason": "新域名"
            },
            "spf_dkim": {
                "risk_score": 20,
                "risk_level": "medium",
                "reasons": ["SPF软失败"]
            }
        }
        score, evidence = calculate_risk_score(tool_results)

        # 第一个应该是贡献最大的
        assert evidence[0]["risk_contribution"] >= evidence[-1]["risk_contribution"]


class TestMakeDecision:
    """决策测试"""

    def test_high_risk_score_blocks(self):
        """测试高风险分数应拦截"""
        decision, reason = make_decision(80, {})

        assert decision == "Block"

    def test_medium_risk_score_quarantines(self):
        """测试中等风险分数应隔离"""
        decision, reason = make_decision(50, {})

        assert decision == "Quarantine"

    def test_low_risk_score_allows(self):
        """测试低风险分数应放行"""
        decision, reason = make_decision(20, {})

        assert decision == "Allow"

    def test_new_domain_forces_quarantine(self):
        """测试新域名应强制隔离"""
        tool_results = {
            "whois": {"registered_hours_ago": 24}
        }
        decision, reason = make_decision(25, tool_results)

        assert decision == "Quarantine"
        assert "域名" in reason

    def test_spf_dkim_double_failure_blocks(self):
        """测试SPF+DKIM双失败应拦截"""
        tool_results = {
            "spf_dkim": {
                "spf_result": "fail",
                "dkim_result": "fail"
            }
        }
        decision, reason = make_decision(20, tool_results)

        assert decision == "Block"
        assert "SPF" in reason and "DKIM" in reason

    def test_prompt_injection_blocks(self):
        """测试Prompt Injection应拦截"""
        tool_results = {
            "semantic": {
                "has_prompt_injection": True
            }
        }
        decision, reason = make_decision(10, tool_results)

        assert decision == "Block"
        assert "Prompt Injection" in reason


class TestOverrideDecisionIfNeeded:
    """决策覆盖测试"""

    def test_stricter_rule_overrides_llm(self):
        """测试更严格的规则应覆盖LLM"""
        final, reason, overridden = override_decision_if_needed(
            "Allow", "Block", "规则要求拦截"
        )

        assert final == "Block"
        assert overridden is True

    def test_same_decision_no_override(self):
        """测试相同决策不覆盖"""
        final, reason, overridden = override_decision_if_needed(
            "Block", "Block", "一致"
        )

        assert final == "Block"
        assert overridden is False

    def test_less_strict_rule_no_override(self):
        """测试不够严格的规则不覆盖"""
        final, reason, overridden = override_decision_if_needed(
            "Block", "Allow", "规则说放行"
        )

        assert final == "Block"
        assert overridden is False


@pytest.mark.unit
class TestRiskScorerEdgeCases:
    """风险评分边界测试"""

    def test_score_capped_at_100(self):
        """测试分数上限为100"""
        tool_results = {
            "whois": {"registered_hours_ago": 1, "risk_score": 100, "risk_level": "critical", "reason": "test"},
            "spf_dkim": {"risk_score": 100, "risk_level": "critical", "reasons": ["test"]},
            "url_check": [{"risk_score": 100, "risk_level": "critical", "reasons": ["test"]}],
            "attachment": {"risk_score": 100, "risk_level": "critical", "reasons": ["test"]},
            "semantic": {"risk_score": 100, "risk_level": "critical", "reasons": ["test"]}
        }
        score, evidence = calculate_risk_score(tool_results)

        assert score <= 100

    def test_handle_missing_risk_scores(self):
        """测试处理缺失的风险分数"""
        tool_results = {
            "whois": {"risk_level": "high"}  # 缺少 risk_score
        }
        score, evidence = calculate_risk_score(tool_results)

        # 应不崩溃
        assert isinstance(score, int)
        assert score >= 0
