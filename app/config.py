"""
WiFiWarden 配置（FastAPI 版）
"""

import os


class Config:
    """基础配置 — 全部从环境变量读取，docker-compose 注入"""

    # MQTT Broker
    MQTT_BROKER   = os.environ.get("MQTT_BROKER",   "mosquitto")
    MQTT_PORT     = int(os.environ.get("MQTT_PORT",  "1883"))
    MQTT_USERNAME = os.environ.get("MQTT_USERNAME",  "wifiwarden")
    MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD",  "")

    # AI 智能体 (DeepSeek 官方 API)
    AI_API_KEY  = os.environ.get("AI_API_KEY",  "")
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.deepseek.com/v1")
    AI_MODEL    = os.environ.get("AI_MODEL",    "deepseek-chat")

    # 蜜罐
    HONEYPOT_TELNET_PORT = 2323
    HONEYPOT_HTTP_PORT   = 8080
