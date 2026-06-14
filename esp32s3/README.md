# WiFiWarden ESP32-S3 端侧代码

多模态WiFi安全感知系统固件。

## 系统架构

```
┌──────────────────┐     UART      ┌──────────────────┐     MQTT/cJSON      ┌─────────────┐
│    AP板 (ESP32)   │◄───────────►│  扫描板 (ESP32)   │◄──────────────────►│  云端 AI    │
│  WifiWarden热点   │  DEV/WIFI/   │  帧嗅探+端口扫描    │  sense/command     │  DeepSeek   │
│  + NAT上网       │  HOST/KICK   │  +弱口令检测+防御    │                      │  + Web控制台 │
│  连接上游WiFi    │  UNBLK       │  连接AP板的WiFi     │                      │             │
└──────────────────┘              └──────────────────┘                      └─────────────┘
```

## 文件夹说明

| 文件夹 | 说明 |
|--------|------|
| `wifiwarden/` | 扫描板固件 — 802.11帧嗅探、端口扫描、弱口令检测、ST7789屏幕，通过MQTT与云端通信 |
| `wifiwarden_ap/` | AP板固件 — 发射WifiWarden热点、DHCP/NAT、通过UART与扫描板通信 |

## 编译前准备

### 1. 安装 ESP-IDF

推荐使用 ESP-IDF v5.3.x，安装说明：
https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/index.html

### 2. 获取 cJSON 组件

```bash
cd esp32s3/wifiwarden/components/cjson/
curl -O https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.h
curl -O https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.c
```

### 3. 配置

编译前需修改以下配置（通过 `idf.py menuconfig` 或在 `sdkconfig.defaults` 中直接修改）：

**扫描板** (`wifiwarden/sdkconfig.defaults`)：
- `CONFIG_SCANNER_AP_PASSWORD` — AP板WiFi密码
- `CONFIG_MQTT_BROKER_URI` — MQTT服务器地址
- `CONFIG_MQTT_USERNAME` / `CONFIG_MQTT_PASSWORD` — MQTT凭据

**AP板** (`wifiwarden_ap/Kconfig.projbuild` 中修改，或 `sdkconfig.defaults`)：
- `CONFIG_AP_PASSWORD` — WifiWarden热点密码
- `CONFIG_WIFI_SSID` / `CONFIG_WIFI_PASSWORD` — 上游WiFi信息

## 编译与烧录

```powershell
# 扫描板
cd esp32s3/wifiwarden
idf.py set-target esp32s3
idf.py build
idf.py -p COM3 flash monitor

# AP板
cd esp32s3/wifiwarden_ap
idf.py set-target esp32s3
idf.py build
idf.py -p COM4 flash monitor
```

⚠️ 注意：COM端口号请根据实际情况修改。

## 功能清单

| 功能 | 状态 |
|------|------|
| 802.11帧嗅探（Probe/Beacon/Deauth） | ✅ |
| Deauth攻击检测（5秒窗口，可配阈值） | ✅ |
| 高危端口扫描（11个端口，TCP Connect） | ✅ |
| 弱口令检测（HTTP Basic Auth + Telnet + FTP，200+组密码） | ✅ |
| Web后台路径枚举（30+路径） | ✅ |
| 设备指纹识别（MAC OUI，100+厂商） | ✅ |
| MAC黑名单（踢除后自动拉黑，重连立即踢除） | ✅ |
| 黑名单移除（UNBLK命令，解除拉黑允许重连） | ✅ |
| 自动踢除（风险≥4触发UART KICK + 加入黑名单） | ✅ |
| MQTT云端上报（cJSON序列化） | ✅ |
| MQTT命令接收（scan/deep_scan/honeypot/blacklist/unblacklist） | ✅ |
| 蜜罐状态云端同步（屏幕Honeypot: ON/OFF） | ✅ |
| ST7789屏幕显示（AP状态/扫描结果/蜜罐/告警） | ✅ |
| 蜂鸣器+LED声光告警 | ✅ |

## UART通信协议（AP板 ↔ 扫描板）

| 方向 | 消息 | 说明 |
|------|------|------|
| AP→扫描 | `DEV:<n>` | AP板连接设备总数（含扫描板自身） |
| AP→扫描 | `HOST:<ip>,<mac>,<hostname>` | 已连接设备的IP/MAC/主机名 |
| AP→扫描 | `WIFI:<SSID>,<RSSI>` | AP板上游WiFi信息 |
| 扫描→AP | `KICK:<MAC>` | 扫描板要求AP板断开指定设备并加入黑名单 |
| 扫描→AP | `UNBLK:<MAC>` | 扫描板要求AP板从黑名单移除设备 |

## MQTT主题

| 主题 | 方向 | 说明 |
|------|------|------|
| `wifiwarden/sense/{mac}` | 扫描板→云端 | 感知数据上报（JSON格式） |
| `wifiwarden/command/{mac}` | 云端→扫描板 | 控制命令（设备专属） |
| `wifiwarden/command/broadcast` | 云端→扫描板 | 控制命令（广播所有设备） |
| `wifiwarden/status` | 扫描板→云端 | 设备状态 |
