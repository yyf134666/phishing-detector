# 钓鱼邮件检测 AI 智能体

## 项目简介

基于 LangGraph + DeepSeek-V4.1 的智能钓鱼邮件检测系统，具备多模态分析、推理链展示和对抗防御能力。

## 功能特性

- ✅ **多模态分析**：文本、域名、URL、附件全方位检测
- ✅ **推理链展示**：每个判定都有完整的 Chain of Thought
- ✅ **对抗防御**：防御 Prompt Injection 攻击
- ✅ **风险评分**：0-100 分量化风险等级
- ✅ **Mock 工具**：安全的模拟外部 API 调用

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 API Key

创建 `.env` 文件：

```bash
DEEPSEEK_API_KEY=your_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
```

### 3. 运行检测

```bash
python main.py
```

## 项目结构

```
phishing_detector/
├── agent/
│   ├── graph.py          # LangGraph 状态机
│   ├── nodes.py          # 处理节点
│   └── prompts.py        # Prompt 模板
├── tools/
│   ├── whois_tool.py     # 域名查询
│   ├── url_checker.py    # URL 检查
│   ├── spf_validator.py  # SPF/DKIM 验证
│   ├── attachment_scanner.py  # 附件扫描
│   └── semantic_analyzer.py   # 语义分析
├── utils/
│   ├── risk_scorer.py    # 风险评分
│   ├── evidence_chain.py # 证据链
│   └── sanitizer.py      # 输入清洗
├── data/
│   ├── test_emails.json  # 测试用例
│   └── blacklist.json    # 黑名单
├── main.py
└── requirements.txt
```

## 测试用例

系统包含 10+ 测试用例，覆盖：
- 正常邮件
- 典型钓鱼（域名仿冒、SPF 失败）
- 对抗样本（Prompt Injection）
- 边界情况（新域名但合法）

## 技术栈

- **LLM**: DeepSeek-V4.1-Flash
- **框架**: LangChain + LangGraph
- **语言**: Python 3.10+

## 设计文档

详见 [设计文档-钓鱼邮件检测AI智能体.md](../设计文档-钓鱼邮件检测AI智能体.md)
