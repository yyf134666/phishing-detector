"""
附件扫描工具 (Mock 实现)
检查邮件附件的安全性
"""

from langchain.tools import BaseTool
from typing import Optional, Type
from pydantic import BaseModel, Field
import json


class AttachmentScannerInput(BaseModel):
    """附件扫描输入"""
    attachments: str = Field(description="附件列表的 JSON 字符串，包含 filename 和 hash 字段")


class AttachmentScannerTool(BaseTool):
    name: str = "attachment_scanner"
    description: str = """扫描邮件附件的安全性。
    检查文件哈希值是否匹配已知恶意软件，检测可疑文件类型和双扩展名。
    输入：附件列表 JSON 字符串
    输出：附件风险评估结果"""
    args_schema: Type[BaseModel] = AttachmentScannerInput

    def _run(self, attachments: str) -> dict:
        """执行附件扫描（Mock）"""
        try:
            # 解析附件列表
            attachment_list = json.loads(attachments) if isinstance(attachments, str) else attachments

            if not attachment_list or len(attachment_list) == 0:
                return {
                    "has_attachments": False,
                    "risk_score": 0,
                    "risk_level": "low",
                    "reasons": ["邮件无附件"]
                }

            total_risk_score = 0
            all_reasons = []
            attachment_results = []

            # 已知恶意文件哈希（Mock 数据 - 使用 EICAR 测试文件哈希）
            malicious_hashes = {
                "a1b2c3": "已知恶意软件哈希",
                "44d88612fea8a8f36de82e1278abb02f": "EICAR 测试病毒",
                "malicious123": "已知勒索软件",
                "phishing456": "钓鱼工具包"
            }

            # 危险文件扩展名
            dangerous_extensions = [
                ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
                ".vbs", ".js", ".jar", ".msi", ".dll", ".ps1"
            ]

            # 可疑文件扩展名
            suspicious_extensions = [
                ".zip", ".rar", ".7z", ".iso", ".dmg"
            ]

            for attachment in attachment_list:
                filename = attachment.get("filename", "")
                file_hash = attachment.get("hash", "")
                risk_score = 0
                reasons = []

                # 检查 1：恶意哈希匹配
                if file_hash in malicious_hashes:
                    risk_score += 50
                    reasons.append(f"文件哈希匹配已知恶意软件：{malicious_hashes[file_hash]}")

                # 检查 2：危险文件类型
                for ext in dangerous_extensions:
                    if filename.lower().endswith(ext):
                        risk_score += 35
                        reasons.append(f"危险文件类型：{ext}")
                        break

                # 检查 3：双扩展名（如 invoice.pdf.exe）
                if filename.count('.') >= 2:
                    risk_score += 25
                    reasons.append("检测到双扩展名（常见的文件伪装手法）")

                # 检查 4：可疑压缩文件
                for ext in suspicious_extensions:
                    if filename.lower().endswith(ext):
                        risk_score += 15
                        reasons.append(f"压缩文件需要额外注意：{ext}")
                        break

                # 检查 5：Office 宏文件
                if filename.lower().endswith(('.docm', '.xlsm', '.pptm')):
                    risk_score += 20
                    reasons.append("Office 宏文件（可能包含恶意宏代码）")

                # 检查 6：可疑文件名
                suspicious_keywords = ["invoice", "payment", "urgent", "receipt", "order", "statement"]
                if any(keyword in filename.lower() for keyword in suspicious_keywords):
                    if risk_score > 0:  # 如果已经有其他风险信号
                        risk_score += 10
                        reasons.append("文件名使用常见钓鱼诱饵词汇")

                if not reasons:
                    reasons.append("附件未发现明显可疑特征")

                attachment_results.append({
                    "filename": filename,
                    "hash": file_hash,
                    "risk_score": risk_score,
                    "reasons": reasons
                })

                total_risk_score += risk_score

            # 计算平均风险分数
            avg_risk_score = total_risk_score // len(attachment_list) if attachment_list else 0

            # 风险等级判定
            if avg_risk_score >= 40:
                risk_level = "critical"
            elif avg_risk_score >= 25:
                risk_level = "high"
            elif avg_risk_score >= 10:
                risk_level = "medium"
            else:
                risk_level = "low"

            return {
                "has_attachments": True,
                "attachment_count": len(attachment_list),
                "risk_score": avg_risk_score,
                "risk_level": risk_level,
                "attachment_details": attachment_results,
                "reasons": [f"检测到 {len(attachment_list)} 个附件"] + all_reasons
            }

        except Exception as e:
            return {
                "error": f"解析附件失败: {str(e)}",
                "risk_level": "unknown"
            }

    async def _arun(self, attachments: str) -> dict:
        """异步执行"""
        return self._run(attachments)
