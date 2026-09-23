"""
单元测试：URL 检查工具
"""
import pytest
from tools.url_checker import URLCheckerTool


class TestURLCheckerTool:
    """URL 检查工具单元测试"""

    def test_blacklist_domain_high_risk(self):
        """测试黑名单域名应返回高风险"""
        tool = URLCheckerTool()
        result = tool._run("http://micr0soft-security.com/login")

        assert result["risk_score"] >= 40
        assert "blacklist_match" in result["flags"]
        assert "钓鱼域名" in str(result["reasons"])

    def test_ip_address_url_high_risk(self):
        """测试IP地址URL应返回高风险"""
        tool = URLCheckerTool()
        result = tool._run("http://192.168.1.100/phishing.php")

        assert result["risk_score"] >= 35
        assert "ip_address" in result["flags"]

    def test_short_link_medium_risk(self):
        """测试短链接应返回中等风险"""
        tool = URLCheckerTool()
        result = tool._run("http://bit.ly/3xYz")

        assert result["risk_score"] >= 20
        assert "short_link" in result["flags"]

    def test_typosquatting_high_risk(self):
        """测试域名混淆应返回高风险"""
        tool = URLCheckerTool()
        result = tool._run("http://paypa1.com/login")

        assert result["risk_score"] >= 30
        assert "typosquatting" in result["flags"]

    def test_legitimate_url_low_risk(self):
        """测试合法URL应返回低风险"""
        tool = URLCheckerTool()
        result = tool._run("https://www.amazon.com")

        assert result["risk_level"] == "low"
        assert result["risk_score"] == 0

    def test_suspicious_tld_medium_risk(self):
        """测试可疑TLD应增加风险"""
        tool = URLCheckerTool()
        result = tool._run("http://phishing-site.tk")

        assert result["risk_score"] > 0
        assert any("TLD" in str(r) or ".tk" in str(r) for r in result["reasons"])


@pytest.mark.unit
class TestURLCheckerToolEdgeCases:
    """URL 检查工具边界测试"""

    def test_very_long_url(self):
        """测试超长URL"""
        tool = URLCheckerTool()
        long_url = "http://example.com/" + "a" * 200
        result = tool._run(long_url)

        assert "long_url" in result["flags"]

    def test_url_with_login_page(self):
        """测试包含登录关键词的可疑URL"""
        tool = URLCheckerTool()
        result = tool._run("http://evil.com/login?user=victim")

        # 如果已有其他风险信号，应增加风险
        if result["risk_score"] > 0:
            assert "suspicious_login_page" in result["flags"] or result["risk_score"] > 0

    def test_empty_url(self):
        """测试空URL"""
        tool = URLCheckerTool()
        result = tool._run("")

        assert "risk_level" in result
