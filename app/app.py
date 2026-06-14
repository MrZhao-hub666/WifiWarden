"""
WiFiWarden 云端控制台 — FastAPI + WebSocket + MQTT
"""
import asyncio
import json
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from config import Config
from state import state
from mqtt_client import MQTTClient
from honeypot import HoneypotManager
from ai_agent import AIAgent

# --------------- 全局状态 ---------------
honeypot: Optional[HoneypotManager] = None
ai_agent: Optional[AIAgent] = None
ws_clients: list[WebSocket] = []
ws_lock = threading.Lock()


# --------------- WebSocket ---------------
async def broadcast(data: dict):
    dead = []
    with ws_lock:
        clients = list(ws_clients)
    for ws in clients:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    if dead:
        with ws_lock:
            for ws in dead:
                if ws in ws_clients:
                    ws_clients.remove(ws)


def on_mqtt_message(topic: str, payload: dict):
    """MQTT消息 → 处理 + WebSocket广播到前端"""
    try:
        if "sense" in topic:
            _handle_sense_data(topic, payload)
        elif "honeypot" in topic:
            _handle_honeypot_data(topic, payload)

        asyncio.run_coroutine_threadsafe(
            broadcast({"type": "mqtt_message", "topic": topic, "payload": payload,
                        "timestamp": datetime.now().isoformat()}), loop
        )
    except Exception as e:
        print(f"[MQTT] 消息处理错误: {e}")


def _handle_sense_data(topic: str, payload: dict):
    mac = payload.get("mac", "unknown")

    deauth = payload.get("deauth", {})
    if deauth and deauth.get("in_window", 0) >= 3:
        state.add_alert(mac, "deauth", 4, f"Deauth攻击窗口内{deauth.get('in_window', 0)}次")

    hosts = payload.get("hosts", [])
    open_ports_found = any(len(h.get("open_ports", [])) > 0 for h in hosts)
    weak_found = any(h.get("weak_http") or h.get("weak_telnet") or h.get("weak_ftp") for h in hosts)
    deauth_active = payload.get("deauth", {}).get("in_window", 0) >= 3

    if weak_found:
        state.add_alert(mac, "weak_password", 3, "检测到弱口令设备")
    if open_ports_found and not weak_found:
        state.add_alert(mac, "port_risk", 2, f"发现{sum(len(h.get('open_ports',[])) for h in hosts)}个高危端口")

    should_ai = (open_ports_found or weak_found or deauth_active) and bool(hosts)
    if ai_agent and Config.AI_API_KEY and should_ai:
        try:
            ai_input = {"mac": mac, "ip": payload.get("ip"), "hosts": hosts,
                        "deauth": payload.get("deauth", {})}
            analysis = ai_agent.analyze(ai_input)
            _execute_defense(mac, analysis.get("risk_level", 0), analysis)
            asyncio.run_coroutine_threadsafe(
                broadcast({"type": "ai_analysis", "mac": mac, "analysis": analysis}), loop
            )
        except Exception as e:
            print(f"[AI] 分析失败: {e}")


def _handle_honeypot_data(topic: str, payload: dict):
    state.add_honeypot_log(
        payload.get("type", "unknown"),
        payload.get("attacker_ip", ""),
        payload.get("attacker_mac", ""),
        json.dumps(payload, ensure_ascii=False)
    )
    asyncio.run_coroutine_threadsafe(
        broadcast({"type": "honeypot_alert", "payload": payload, "timestamp": datetime.now().isoformat()}), loop
    )


def _execute_defense(mac: str, risk: int, analysis: dict):
    action = analysis.get("recommended_action", "")
    threat = analysis.get("threat_type") or "suspicious_activity"
    if risk >= 2:
        state.add_alert(mac, threat, risk, analysis.get("risk_reason", ""), action)
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.send_alert(mac, threat, risk, analysis.get("risk_reason", ""))
    if risk >= 3:
        state.blacklist_device(mac)
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.send_blacklist(mac, mac)
    if risk >= 4:
        if honeypot and not honeypot.running:
            honeypot.start(on_capture_callback=on_mqtt_message)
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.send_honeypot_on(mac, "WifiWarden_Honey")
            mqtt_client.publish_broadcast_command({"action": "honeypot_on", "params": {"ssid": "WifiWarden_Honey"}})


# --------------- FastAPI 生命周期 ---------------
loop: asyncio.AbstractEventLoop = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop, honeypot, ai_agent, mqtt_client
    loop = asyncio.get_running_loop()

    if Config.AI_API_KEY:
        ai_agent = AIAgent(Config.AI_API_KEY, Config.AI_BASE_URL, Config.AI_MODEL)
        print(f"[AI] 模型: {Config.AI_MODEL}")

    mqtt_client = MQTTClient(
        Config.MQTT_BROKER, Config.MQTT_PORT,
        Config.MQTT_USERNAME, Config.MQTT_PASSWORD,
        on_mqtt_message
    )
    ok = mqtt_client.connect()
    print(f"[MQTT] 连接{'成功' if ok else '失败'} -> {Config.MQTT_BROKER}")

    honeypot = HoneypotManager(Config.HONEYPOT_TELNET_PORT, Config.HONEYPOT_HTTP_PORT)
    print(f"[Honeypot] Telnet:{Config.HONEYPOT_TELNET_PORT} HTTP:{Config.HONEYPOT_HTTP_PORT}")

    yield
    if mqtt_client:
        mqtt_client.disconnect()
    if honeypot and honeypot.running:
        honeypot.stop()


# --------------- App ---------------
app = FastAPI(title="WiFiWarden API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# --------------- WebSocket ---------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    with ws_lock:
        ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        with ws_lock:
            if ws in ws_clients:
                ws_clients.remove(ws)


# ==================== REST API ====================

@app.get("/")
async def index():
    return FileResponse("templates/index.html")

@app.post("/api/devices/{mac}/blacklist")
async def blacklist_device(mac: str):
    state.blacklist_device(mac)
    if mqtt_client and mqtt_client.is_connected():
        # 通过broadcast发送黑名单命令，扫描板收到后转发KICK给AP板
        mqtt_client.publish_broadcast_command({"action": "blacklist", "params": {"target_mac": mac}})
    return {"code": 0, "message": "Device blacklisted"}

@app.delete("/api/devices/{mac}/blacklist")
async def unblacklist_device(mac: str):
    state.unblacklist_device(mac)
    if mqtt_client and mqtt_client.is_connected():
        # 通知扫描板转发UNBLK给AP板，允许设备重新连接
        mqtt_client.publish_broadcast_command({"action": "unblacklist", "params": {"target_mac": mac}})
    return {"code": 0, "message": "Device removed from blacklist"}

@app.get("/api/blacklist")
async def get_blacklist():
    return {"code": 0, "data": state.get_blacklist()}

@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50)):
    return {"code": 0, "data": state.get_recent_alerts(limit)}

@app.get("/api/honeypot/logs")
async def honeypot_logs():
    return {"code": 0, "data": state.get_honeypot_logs()}

@app.get("/api/honeypot/status")
async def honeypot_status():
    return {"code": 0, "data": {"running": honeypot.running if honeypot else False,
                                 "telnet_port": Config.HONEYPOT_TELNET_PORT,
                                 "http_port": Config.HONEYPOT_HTTP_PORT}}

@app.post("/api/honeypot/start")
async def start_honeypot():
    try:
        if honeypot and not honeypot.running:
            honeypot.start(on_capture_callback=on_mqtt_message)
    except Exception as e:
        raise HTTPException(500, f"蜜罐启动失败: {e}")
    if mqtt_client and mqtt_client.is_connected():
        mqtt_client.publish_broadcast_command({"action": "honeypot_on", "params": {"ssid": "WifiWarden_Honey"}})
        return {"code": 0, "message": "Honeypot started"}
    return {"code": 1, "message": "蜜罐已启动但MQTT未连接，端侧未收到指令"}

@app.post("/api/honeypot/stop")
async def stop_honeypot():
    try:
        if honeypot and honeypot.running:
            honeypot.stop()
    except Exception as e:
        raise HTTPException(500, f"蜜罐停止失败: {e}")
    if mqtt_client and mqtt_client.is_connected():
        mqtt_client.publish_broadcast_command({"action": "honeypot_off", "params": {}})
        return {"code": 0, "message": "Honeypot stopped"}
    return {"code": 1, "message": "蜜罐已停止但MQTT未连接，端侧未收到指令"}

@app.post("/api/scan/broadcast")
async def trigger_scan_all(deep: bool = Query(False)):
    if not mqtt_client or not mqtt_client.is_connected():
        raise HTTPException(400, "MQTT not connected")
    action = "deep_scan" if deep else "scan"
    mqtt_client.publish_broadcast_command({"action": action, "params": {}})
    asyncio.run_coroutine_threadsafe(
        broadcast({"type": "scan_triggered", "mac": "broadcast", "deep": deep,
                    "timestamp": datetime.now().isoformat()}), loop
    )
    return {"code": 0, "message": f"{'深度扫描' if deep else '普通扫描'}命令已下发"}

@app.post("/api/scan/{mac}")
async def trigger_scan(mac: str, deep: bool = Query(False)):
    return await trigger_scan_all(deep)

@app.get("/api/statistics")
async def statistics():
    return {"code": 0, "data": state.get_statistics()}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
