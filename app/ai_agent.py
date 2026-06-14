"""
WiFiWarden AI 智能体
"""

import json
import requests
from datetime import datetime


class AIAgent:
    """AI 安全分析智能体"""

    def __init__(self, api_key, base_url, model):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self):
        """构建系统提示词"""
        return """你是一个专业的无线网络安全分析专家，名为 WiFiWardern。

你的职责是分析来自物联网设备的感知数据，判断是否存在安全威胁，并生成防御策略。

## 风险等级定义
- 0级 (正常): 设备正常接入，无异常行为
- 1级 (观察): 检测到轻微异常，如陌生设备首次接入
- 2级 (警示): 多个感知源发现可疑行为，如端口扫描行为
- 3级 (威胁): 确认恶意行为，如弱口令尝试、Deauth攻击
- 4级 (严重): 主动攻击行为，如暴力破解、大规模扫描

## 防御策略
- 0级: 记录日志
- 1级: 提升监控频率
- 2级: 蜂鸣器短鸣告警，上报云端
- 3级: 蜂鸣器持续告警，加入黑名单
- 4级: 触发蜜罐诱捕，记录攻击者行为

## 输出格式要求
你必须返回JSON格式的分析结果：
{
    "risk_level": 0-4的风险等级,
    "risk_reason": "风险判断依据",
    "recommended_action": "建议的防御动作",
    "threat_type": "检测到的威胁类型(如无可填null)",
    "confidence": 0.0-1.0的置信度
}

请基于以下感知数据进行智能分析："""

    def analyze(self,感知数据: dict) -> dict:
        """
        分析感知数据并返回决策结果

        Args:
            感知数据: 包含以下键的字典
                - mac: 设备MAC地址
                - ip: 设备IP地址
                - device_type: 设备类型
                - wifi_probes: WiFi探针数据列表
                - port_scan: 端口扫描结果
                - weak_password_attempts: 弱口令尝试记录
                - deauth_attacks: Deauth攻击记录
                - csi_anomaly: CSI异常检测结果
                - recent_alerts: 最近告警记录

        Returns:
            包含分析结果的字典
        """
        # 构建分析提示
        prompt = self.system_prompt + "\n\n感知数据:\n"
        prompt += json.dumps(感知数据, ensure_ascii=False, indent=2)

        try:
            # 调用大模型API
            response = self._call_api(prompt)

            # 解析响应
            result = self._parse_response(response)

            # 添加时间戳
            result['analyzed_at'] = datetime.now().isoformat()
            result['model_used'] = self.model

            return result

        except Exception as e:
            # 如果API调用失败，返回默认结果
            return {
                'risk_level': 1,
                'risk_reason': f'AI分析服务异常: {str(e)}，自动降级为观察模式',
                'recommended_action': '记录日志，提升监控',
                'threat_type': None,
                'confidence': 0.0,
                'analyzed_at': datetime.now().isoformat(),
                'error': str(e)
            }

    def _call_api(self, prompt: str) -> str:
        """调用大模型API"""
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,  # 较低温度保证稳定性
            "max_tokens": 500
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()

        return response.json()['choices'][0]['message']['content']

    def _parse_response(self, response: str) -> dict:
        """解析大模型响应"""
        # 尝试提取JSON
        try:
            # 尝试直接解析
            return json.loads(response)
        except json.JSONDecodeError:
            # 尝试从文本中提取JSON
            import re
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except:
                    pass

            # 如果解析失败，返回错误信息
            return {
                'risk_level': 1,
                'risk_reason': 'AI响应解析失败',
                'recommended_action': '记录日志',
                'threat_type': None,
                'confidence': 0.0,
                'raw_response': response
            }


