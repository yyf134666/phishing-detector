"""
集成测试：完整的邮件检测流程
"""
import pytest
import os
from agent.graph import run_detection


@pytest.mark.integration
class TestEmailDetectionFlow:
    """邮件检测流程集成测试"""

    def test_detect_phishing_email_end_to_end(self, sample_phishing_email):
        """测试端到端钓鱼邮件检测"""
        result = run_detection(sample_phishing_email)

        assert result["success"] is True
        assert result["is_phishing"] is True
        assert result["decision"] in ["Block", "Quarantine"]
        assert result["risk_score"] > 0
        assert len(result["key_evidence"]) > 0

    def test_detect_legitimate_email_end_to_end(self, sample_legitimate_email):
        """测试端到端正常邮件检测"""
        result = run_detection(sample_legitimate_email)

        assert result["success"] is True
        assert result["is_phishing"] is False
        assert result["decision"] == "Allow"
        assert result["risk_score"] < 30

    def test_detect_prompt_injection_end_to_end(self, sample_prompt_injection_email):
        """测试端到端Prompt Injection检测"""
        result = run_detection(sample_prompt_injection_email)

        assert result["success"] is True
        assert result["security_flags"]["has_prompt_injection"] is True
        assert result["decision"] == "Block"

    @pytest.mark.skipif(not os.getenv("DEEPSEEK_API_KEY"), reason="需要API Key")
    def test_llm_integration(self, sample_phishing_email):
        """测试LLM集成"""
        result = run_detection(sample_phishing_email)

        assert result["success"] is True
        assert "llm_reasoning" in result
        assert len(result["llm_reasoning"]) > 0
        assert 0.0 <= result["confidence"] <= 1.0

    def test_evidence_chain_completeness(self, sample_phishing_email):
        """测试证据链完整性"""
        result = run_detection(sample_phishing_email)

        assert "evidence_chain" in result
        assert len(result["evidence_chain"]) > 0

        for evidence in result["evidence_chain"]:
            assert "source" in evidence
            assert "risk_contribution" in evidence
            assert "weight" in evidence
            assert "detail" in evidence


@pytest.mark.integration
class TestToolIntegration:
    """工具集成测试"""

    def test_all_tools_execute_successfully(self, sample_phishing_email):
        """测试所有工具都能成功执行"""
        result = run_detection(sample_phishing_email)

        assert "tool_results" in result
        tool_results = result["tool_results"]

        # 检查所有工具都有结果
        expected_tools = ["whois", "spf_dkim", "url_check", "attachment", "semantic"]
        for tool in expected_tools:
            assert tool in tool_results

    def test_tool_error_handling(self):
        """测试工具错误处理"""
        # 使用不完整的邮件数据
        incomplete_email = {
            "id": "test_incomplete",
            "headers": {
                "from": "test@example.com"
                # 缺少必需字段
            }
        }
        result = run_detection(incomplete_email)

        # 应该返回错误而不是崩溃
        assert result["success"] is False
        assert "error" in result


@pytest.mark.integration
@pytest.mark.slow
class TestBatchDetection:
    """批量检测测试"""

    def test_batch_detection_consistency(self):
        """测试批量检测的一致性"""
        from tests.conftest import load_test_emails

        test_emails = load_test_emails()[:3]  # 测试前3个
        results = []

        for email in test_emails:
            result = run_detection(email)
            results.append(result)

        # 检查所有结果都成功
        assert all(r["success"] for r in results)

    def test_detection_performance(self, sample_phishing_email):
        """测试检测性能"""
        import time

        start_time = time.time()
        result = run_detection(sample_phishing_email)
        elapsed_time = time.time() - start_time

        assert result["success"] is True
        # 单个检测应在30秒内完成（包括LLM调用）
        assert elapsed_time < 30


@pytest.mark.integration
class TestDecisionLogic:
    """决策逻辑集成测试"""

    def test_high_risk_always_blocks_or_quarantines(self):
        """测试高风险邮件应该被拦截或隔离"""
        high_risk_email = {
            "id": "high_risk_test",
            "headers": {
                "from": "hacker@evil.tk",
                "to": "victim@company.com",
                "subject": "Urgent: Click Now!",
                "spf_result": "fail",
                "dkim_result": "fail"
            },
            "body_text": "Your account will be deleted in 1 hour. Click here immediately: http://192.168.1.1/phishing",
            "links": [{"original": "http://192.168.1.1/phishing"}],
            "attachments": [{"filename": "malware.exe", "hash": "evil123"}]
        }

        result = run_detection(high_risk_email)

        assert result["decision"] in ["Block", "Quarantine"]
        assert result["risk_score"] >= 30

    def test_low_risk_allows(self):
        """测试低风险邮件应该被放行"""
        low_risk_email = {
            "id": "low_risk_test",
            "headers": {
                "from": "notifications@github.com",
                "to": "dev@company.com",
                "subject": "Weekly Digest",
                "spf_result": "pass",
                "dkim_result": "pass"
            },
            "body_text": "Here is your weekly summary of repository activity.",
            "links": [{"original": "https://github.com"}],
            "attachments": []
        }

        result = run_detection(low_risk_email)

        assert result["decision"] == "Allow"
        assert result["risk_score"] < 30


@pytest.mark.integration
class TestErrorRecovery:
    """错误恢复测试"""

    def test_missing_email_fields(self):
        """测试缺失字段的处理"""
        incomplete_email = {
            "id": "incomplete",
            "headers": {}
        }

        result = run_detection(incomplete_email)

        assert result["success"] is False

    def test_invalid_email_format(self):
        """测试无效格式的处理"""
        invalid_email = {
            "headers": {
                "from": "invalid",
                "to": "invalid",
                "subject": "test"
            },
            "body_text": 12345  # 应该是字符串
        }

        result = run_detection(invalid_email)

        assert result["success"] is False
