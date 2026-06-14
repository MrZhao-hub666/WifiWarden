"""
WiFiWarden MQTT 客户端
"""
import json
import threading
from datetime import datetime
import paho.mqtt.client as mqtt


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

        self.client = mqtt.Client()
        self.client.username_pw_set(username, password)
        self.client.on_connect    = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message    = self._on_message
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)

    def connect(self) -> bool:
        try:
            self.client.connect(self.broker, self.port, keepalive=60)
            self.client.loop_start()
            return self._connected.wait(timeout=10)
        except Exception as e:
            print(f"[MQTT] 连接失败: {e}")
            return False

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()
        self._connected.clear()

    def is_connected(self) -> bool:
        return self._connected.is_set()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("[MQTT] 已连接")
            self._connected.set()
            client.subscribe([
                (self.TOPIC_SENSE.replace("{mac}", "+"), 1),
                (self.TOPIC_STATUS, 1),
                (self.TOPIC_HONEYPOT, 1),
            ])
        else:
            print(f"[MQTT] 连接失败 rc={rc}")

    def _on_disconnect(self, client, userdata, rc):
        print(f"[MQTT] 断开 rc={rc}")
        self._connected.clear()

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            if self._on_msg_cb:
                self._on_msg_cb(msg.topic, payload)
        except Exception as e:
            print(f"[MQTT] 解析错误: {e}")

    def _publish(self, topic: str, payload, qos=1):
        data = json.dumps(payload, ensure_ascii=False)
        self.client.publish(topic, data, qos=qos)

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
