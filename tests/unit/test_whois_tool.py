"""
单元测试：Whois 查询工具
"""
import pytest
from tools.whois_tool import WhoisQueryTool


class TestWhoisQueryTool:
    """Whois 查询工具单元测试"""

    def test_new_domain_critical_risk(self):
        """测试新注册域名（<24小时）应返回严重风险"""
        tool = WhoisQueryTool()
        result = tool._run("brand-new-phishing.com")

        assert result["risk_level"] == "critical"
        assert result["risk_score"] == 100
        assert "24小时" in result["reason"]

    def test_recent_domain_high_risk(self):
        """测试近期注册域名（24-72小时）应返回高风险"""
        tool = WhoisQueryTool()
        result = tool._run("recent-domain.com")

        assert result["risk_level"] == "high"
        assert result["risk_score"] == 70

    def test_established_domain_low_risk(self):
        """测试老域名应返回低风险"""
        tool = WhoisQueryTool()
        result = tool._run("google.com")

        assert result["risk_level"] == "low"
        assert result["risk_score"] == 0

    def test_suspicious_registrar(self):
        """测试可疑注册商应增加风险"""
        tool = WhoisQueryTool()
        result = tool._run("suspicious-site.tk")

        assert result["risk_score"] > 0
        assert "注册商" in result["reason"] or "TLD" in result["reason"]

    def test_empty_domain(self):
        """测试空域名应返回错误"""
        tool = WhoisQueryTool()
        result = tool._run("")

        assert "error" in result or result["risk_level"] == "unknown"


@pytest.mark.unit
class TestWhoisQueryToolEdgeCases:
    """Whois 工具边界测试"""

    def test_international_domain(self):
        """测试国际域名"""
        tool = WhoisQueryTool()
        result = tool._run("中文域名.com")

        assert "risk_level" in result
        assert "risk_score" in result

    def test_subdomain(self):
        """测试子域名"""
        tool = WhoisQueryTool()
        result = tool._run("sub.example.com")

        assert "risk_level" in result
        assert isinstance(result["risk_score"], int)

    def test_domain_with_port(self):
        """测试带端口的域名"""
        tool = WhoisQueryTool()
        result = tool._run("example.com:8080")

        assert "risk_level" in result
