"""
WiFiWarden MQTT 客户端
兼容 paho-mqtt 1.x 和 2.x
"""
import json
import threading
from datetime import datetime
import paho.mqtt.client as mqtt


# 检测 paho-mqtt 版本，2.x 需要 CallbackAPIVersion
def _create_mqtt_client(client_id="wifiwarden-cloud"):
    """创建兼容 1.x 和 2.x 的 MQTT Client"""
    if hasattr(mqtt, 'CallbackAPIVersion'):
        # paho-mqtt 2.x
        return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    else:
        # paho-mqtt 1.x
        return mqtt.Client(client_id=client_id)


class MQTTClient:
    TOPIC_SENSE    = "wifiwarden/sense/{mac}"
    TOPIC_COMMAND  = "wifiwarden/command/{mac}"
    TOPIC_STATUS   = "wifiwarden/status"
    TOPIC_HONEYPOT = "wifiwarden/honeypot"

    def __init__(self, broker: str, port: int, username: str, password: str,
                 on_message_callback=None):
        self.broker = broker
        self.port = port
        self._on_msg_cb = on_message_callback
        self._connected = threading.Event()

        self.client = _create_mqtt_client()
        self.client.username_pw_set(username, password)
        self.client.on_connect    = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message    = self._on_message
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)

    def connect(self) -> bool:
        try:
            self.client.connect(self.broker, self.port, keepalive=60)
            self.client.loop_start()
            connected = self._connected.wait(timeout=10)
            if not connected:
                print("[MQTT] 连接超时（10秒内未收到 CONNACK）")
            return connected
        except Exception as e:
            print(f"[MQTT] 连接异常: {e}", exc_info=True)
            return False

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()
        self._connected.clear()

    def is_connected(self) -> bool:
        return self._connected.is_set()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("[MQTT] 已连接到 Broker")
            self._connected.set()
            result, mid = client.subscribe([
                (self.TOPIC_SENSE.replace("{mac}", "+"), 1),
            ])
            print(f"[MQTT] 已订阅 wifiwarden/sense/+ (result={result})")
        else:
            print(f"[MQTT] 连接被拒绝 rc={rc} (1=协议错误 2=ID拒绝 3=服务不可用 4=凭证错误 5=未授权)")

    def _on_disconnect(self, client, userdata, rc):
        if rc == 0:
            print("[MQTT] 正常断开")
        else:
            print(f"[MQTT] 意外断开 rc={rc}，将自动重连")
        self._connected.clear()

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(f"[MQTT] 收到: topic={msg.topic}, keys={list(payload.keys()) if isinstance(payload, dict) else type(payload)}")
            if self._on_msg_cb:
                self._on_msg_cb(msg.topic, payload)
        except json.JSONDecodeError as e:
            print(f"[MQTT] JSON解析错误: {e}, raw={msg.payload[:200]}")
        except Exception as e:
            print(f"[MQTT] 消息处理异常: {e}", exc_info=True)

    def _publish(self, topic: str, payload, qos=1):
        if not self._connected.is_set():
            print(f"[MQTT] ⚠ 未连接，无法发布到 {topic}")
            return
        data = json.dumps(payload, ensure_ascii=False)
        result = self.client.publish(topic, data, qos=qos)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"[MQTT] 发布失败: topic={topic}, rc={result.rc}")

    def publish_command(self, mac: str, command: dict):
        topic = self.TOPIC_COMMAND.replace("{mac}", mac)
        self._publish(topic, {"command": command, "timestamp": datetime.now().isoformat()})

    def publish_broadcast_command(self, command: dict):
        if not self._connected.is_set():
            print(f"[MQTT] ⚠ 未连接，无法广播: {command}")
            return
        payload = {"command": command, "timestamp": datetime.now().isoformat()}
        self._publish("wifiwarden/command/broadcast", payload)

    def send_alert(self, mac: str, alert_type: str, risk_level: int, message: str):
        self.publish_command(mac, {"action": "alert", "params": {
            "alert_type": alert_type, "risk_level": risk_level, "message": message
        }})

    def send_blacklist(self, mac: str, target_mac: str):
        self.publish_command(mac, {"action": "blacklist", "params": {"target_mac": target_mac}})

    def send_honeypot_on(self, mac: str, ssid: str = "WifiWarden_Honey"):
        self.publish_command(mac, {"action": "honeypot_on", "params": {"ssid": ssid}})

    def send_honeypot_off(self, mac: str):
        self.publish_command(mac, {"action": "honeypot_off", "params": {}})
