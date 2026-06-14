"""
WiFiWarden 状态管理 — 内存 + JSON持久化
"""
import json
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"


class AppState:
    def __init__(self):
        self.blacklist: set = set()
        self.honeypot_logs: list = []
        self.alerts: list = []
        self._load_blacklist()

    # -- 黑名单 --
    def _load_blacklist(self):
        if BLACKLIST_FILE.exists():
            try:
                self.blacklist = set(json.loads(BLACKLIST_FILE.read_text()).get("macs", []))
            except Exception:
                self.blacklist = set()

    def _save_blacklist(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        BLACKLIST_FILE.write_text(json.dumps({"macs": list(self.blacklist)}))

    def is_blacklisted(self, mac: str) -> bool:
        return mac in self.blacklist

    def blacklist_device(self, mac: str):
        self.blacklist.add(mac)
        self._save_blacklist()

    def unblacklist_device(self, mac: str):
        self.blacklist.discard(mac)
        self._save_blacklist()

    def get_blacklist(self) -> list:
        return list(self.blacklist)

    # -- 蜜罐日志 --
    def add_honeypot_log(self, hp_type: str, attacker_ip: str, attacker_mac: str, raw_data: str):
        self.honeypot_logs.insert(0, {
            "honeypot_type": hp_type, "attacker_ip": attacker_ip,
            "attacker_mac": attacker_mac, "input_data": raw_data[:200],
            "timestamp": datetime.now().isoformat()
        })
        self.honeypot_logs = self.honeypot_logs[:200]

    def get_honeypot_logs(self) -> list:
        return self.honeypot_logs[:50]

    # -- 告警 --
    def add_alert(self, device_mac: str, alert_type: str, risk_level: int,
                  description: str, action_taken: str = None):
        self.alerts.insert(0, {
            "device_mac": device_mac, "alert_type": alert_type,
            "risk_level": risk_level, "description": description,
            "action_taken": action_taken, "timestamp": datetime.now().isoformat()
        })
        self.alerts = self.alerts[:100]

    def get_recent_alerts(self, limit: int = 50) -> list:
        return self.alerts[:limit]

    def get_statistics(self) -> dict:
        return {"total_devices": 0, "risk_level": 0,
                "total_alerts": len(self.alerts), "deauth_window": 0,
                "deauth_threshold": 3, "total_honeypot_hits": len(self.honeypot_logs)}


state = AppState()
