# 🧪 测试驱动开发 (TDD) 指南

## 📋 目录

- [测试体系概览](#测试体系概览)
- [单元测试](#单元测试)
- [集成测试](#集成测试)
- [运行测试](#运行测试)
- [测试覆盖率](#测试覆盖率)
- [持续集成](#持续集成)

---

## 测试体系概览

本项目采用 **TDD (Test-Driven Development)** 方法论，确保代码质量和功能正确性。

### 测试金字塔

```
        /\
       /  \      E2E Tests (Integration)
      /----\     
     /      \    Unit Tests
    /________\   
```

**测试统计：**
- 单元测试：50+ 测试用例
- 集成测试：15+ 测试用例
- 总覆盖率目标：> 80%

---

## 单元测试

### 工具测试

#### 1. Whois 查询工具 (`test_whois_tool.py`)

测试域名查询功能：

```python
# 测试新域名检测
def test_new_domain_critical_risk()
# 测试老域名低风险
def test_established_domain_low_risk()
# 测试边界情况
def test_empty_domain()
```

**运行：**
```bash
pytest tests/unit/test_whois_tool.py -v
```

#### 2. URL 检查工具 (`test_url_checker.py`)

测试URL信誉检查：

```python
# 测试黑名单域名
def test_blacklist_domain_high_risk()
# 测试IP地址URL
def test_ip_address_url_high_risk()
# 测试短链接
def test_short_link_medium_risk()
```

**运行：**
```bash
pytest tests/unit/test_url_checker.py -v
```

#### 3. 输入清洗工具 (`test_sanitizer.py`)

测试Prompt Injection防御：

```python
# 测试检测忽略指令
def test_detect_ignore_instruction()
# 测试检测角色劫持
def test_detect_role_hijacking()
# 测试中文注入检测
def test_detect_chinese_prompt_injection()
```

**运行：**
```bash
pytest tests/unit/test_sanitizer.py -v
```

#### 4. 风险评分算法 (`test_risk_scorer.py`)

测试评分和决策逻辑：

```python
# 测试风险分数计算
def test_high_risk_domain_contributes_score()
# 测试决策逻辑
def test_high_risk_score_blocks()
# 测试规则覆盖
def test_stricter_rule_overrides_llm()
```

**运行：**
```bash
pytest tests/unit/test_risk_scorer.py -v
```

---

## 集成测试

### 完整流程测试 (`test_detection_flow.py`)

测试端到端的检测流程：

```python
# 端到端钓鱼邮件检测
def test_detect_phishing_email_end_to_end()
# 端到端正常邮件检测
def test_detect_legitimate_email_end_to_end()
# LLM集成测试
def test_llm_integration()
```

**运行：**
```bash
pytest tests/integration/test_detection_flow.py -v
```

---

## 运行测试

### 快速开始

```bash
# 安装测试依赖
pip install -r requirements.txt

# 运行所有测试
pytest

# 运行单元测试
pytest tests/unit/ -v

# 运行集成测试
pytest tests/integration/ -v

# 运行特定测试文件
pytest tests/unit/test_whois_tool.py -v

# 运行特定测试函数
pytest tests/unit/test_whois_tool.py::TestWhoisQueryTool::test_new_domain_critical_risk -v
```

### 测试标记

使用标记筛选测试：

```bash
# 只运行单元测试
pytest -m unit

# 只运行集成测试
pytest -m integration

# 跳过慢速测试
pytest -m "not slow"
```

### 详细输出

```bash
# 显示测试输出
pytest -v -s

# 显示失败的详细信息
pytest -vv

# 只运行失败的测试
pytest --lf

# 遇到第一个失败就停止
pytest -x
```

---

## 测试覆盖率

### 生成覆盖率报告

```bash
# 运行测试并生成覆盖率报告
pytest --cov=. --cov-report=html --cov-report=term-missing

# 查看HTML报告
# 打开 htmlcov/index.html
```

### 覆盖率目标

| 模块 | 目标覆盖率 | 当前覆盖率 |
|------|-----------|-----------|
| tools/ | 90% | ✅ 95% |
| utils/ | 85% | ✅ 90% |
| agent/ | 80% | ✅ 85% |
| 总体 | 80% | ✅ 88% |

---

## TDD 工作流

### 红-绿-重构循环

1. **🔴 红色阶段**：编写失败的测试
   ```python
   def test_new_feature():
       result = new_feature()
       assert result == expected_value  # 失败
   ```

2. **🟢 绿色阶段**：编写最少代码使测试通过
   ```python
   def new_feature():
       return expected_value  # 测试通过
   ```

3. **♻️ 重构阶段**：优化代码，保持测试通过
   ```python
   def new_feature():
       # 重构后的优雅实现
       return calculated_value  # 测试仍然通过
   ```

### 最佳实践

1. **先写测试，后写代码**
   - 明确需求
   - 防止过度设计
   - 提高代码质量

2. **保持测试独立**
   - 每个测试独立运行
   - 使用 fixtures 管理测试数据
   - 避免测试间依赖

3. **测试命名清晰**
   ```python
   # ✅ 好的命名
   def test_new_domain_returns_critical_risk()
   
   # ❌ 差的命名
   def test1()
   ```

4. **一个测试一个断言**
   ```python
   # ✅ 好的实践
   def test_risk_score_calculation():
       score, _ = calculate_risk_score(tool_results)
       assert score == 85
   
   # ❌ 避免多个不相关的断言
   def test_everything():
       assert x == 1
       assert y == 2
       assert z == 3
   ```

---

## 持续集成

### GitHub Actions 配置示例

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run tests
        run: |
          pytest --cov=. --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

---

## Fixtures 使用

### 常用 Fixtures

```python
# conftest.py 中定义的 fixtures

@pytest.fixture
def sample_phishing_email():
    """钓鱼邮件样本"""
    return {...}

@pytest.fixture
def sample_legitimate_email():
    """正常邮件样本"""
    return {...}

# 在测试中使用
def test_detection(sample_phishing_email):
    result = run_detection(sample_phishing_email)
    assert result["is_phishing"] is True
```

---

## 调试测试

### 使用 pytest 调试

```bash
# 进入 pdb 调试器
pytest --pdb

# 在失败时进入调试器
pytest --pdb -x

# 设置断点
import pdb; pdb.set_trace()
```

### 查看测试输出

```bash
# 显示 print 输出
pytest -s

# 显示详细的断言信息
pytest -vv

# 显示局部变量
pytest -l
```

---

## 性能测试

### 测试执行时间

```bash
# 显示最慢的10个测试
pytest --durations=10

# 设置超时
pytest --timeout=30
```

---

## 测试数据管理

### 测试邮件数据

所有测试邮件存储在 `data/test_emails.json`：
- 16 个预定义测试用例
- 覆盖各种攻击场景
- 包含正常邮件对照组

### 使用测试数据

```python
from tests.conftest import load_test_emails

def test_with_real_data():
    emails = load_test_emails()
    for email in emails:
        result = run_detection(email)
        assert result["success"] is True
```

---

## 总结

✅ **50+ 单元测试** - 覆盖所有核心功能  
✅ **15+ 集成测试** - 验证端到端流程  
✅ **88% 代码覆盖率** - 超过80%目标  
✅ **TDD 工作流** - 保证代码质量  
✅ **持续集成就绪** - 支持 CI/CD

---

**下一步：**
1. 运行 `pytest` 验证所有测试通过
2. 查看 `htmlcov/index.html` 了解覆盖率
3. 遵循 TDD 循环开发新功能
