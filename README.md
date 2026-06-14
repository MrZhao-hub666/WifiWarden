# WiFiWarden — 无线局域网多源感知与自适应防御系统

基于 ESP32-S3 双板架构的物联网安全防护系统。实时监控、AI 决策、蜜罐诱捕、自适应防御。

![WiFiWarden 云端控制台首页](docs/homepage.png)

---

## 系统拓扑

```
ESP32-S3(AP板) ──UART── ESP32-S3(扫描板) ──MQTT── Mosquitto ── FastAPI ── Nginx ── 浏览器
     │                        │
  WifiWarden热点         ST7789屏幕/蜂鸣器/LED
  DHCP/NAT               802.11嗅探/端口扫描
```

---

## 项目结构

```
大作业/
├── README.md
├── PROGRESS.md               # 开发进度
├── WIRING.md                 # 硬件接线说明
├── .env.example              # 环境变量示例
├── docker-compose.yml        # Docker 编排
├── deploy.sh                 # 一键部署脚本
│
├── app/                      # 云端 Web (FastAPI)
│   ├── app.py                # 主入口 API + WebSocket
│   ├── state.py              # 状态管理（内存 + JSON）
│   ├── config.py             # 配置（环境变量）
│   ├── mqtt_client.py        # MQTT 客户端
│   ├── ai_agent.py           # AI 智能体（DeepSeek）
│   ├── honeypot.py           # 蜜罐服务（Telnet + HTTP）
│   ├── requirements.txt      # Python 依赖
│   ├── Dockerfile            # Docker 构建
│   └── templates/
│       └── index.html        # Web 前端单页应用
│
├── nginx/
│   ├── default.conf          # Nginx HTTPS 反向代理
│   └── certs/
│       └── README.md         # SSL 证书配置说明
│
├── mosquitto/
│   └── config/
│       ├── mosquitto.conf    # MQTT Broker 配置
│       └── acl.conf          # 访问控制列表
│
└── esp32s3/
    ├── README.md             # ESP32 端侧代码说明
    ├── wifiwarden/           # 扫描板固件
    │   ├── main/
    │   │   ├── main.c                # 主程序（99KB）
    │   │   ├── Kconfig.projbuild     # 菜单配置
    │   │   ├── mac_oui.h             # MAC OUI 厂商识别
    │   │   └── weak_passwords.h      # 弱密码字典（200+组）
    │   ├── components/
    │   │   ├── st7789/               # ST7789 屏幕驱动
    │   │   └── cjson/                # JSON 解析库
    │   ├── sdkconfig.defaults        # 默认编译配置
    │   └── CMakeLists.txt
    └── wifiwarden_ap/        # AP 板固件
        ├── main/
        │   ├── main.c                # 主程序（25KB）
        │   └── Kconfig.projbuild     # 菜单配置
        └── CMakeLists.txt
```

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 云端后端 | FastAPI + WebSocket |
| 前端 | ECharts + 原生 JS（单页应用） |
| MQTT | Mosquitto（1883/8883） |
| 反向代理 | Nginx（HTTPS + HTTP/2） |
| AI 智能体 | DeepSeek 官方 API |
| 数据持久化 | JSON 文件（黑名单等） |
| 端侧 | ESP32-S3 × 2（双板 UART 通信） |
| 蜜罐 | Python Telnet + HTTP 服务 |

---

## 功能特性

### 扫描板（ESP32-S3）
- 🔍 802.11 帧嗅探（Probe Request / Beacon / Deauth）
- 🚨 Deauth 攻击实时检测（5 秒滑动窗口，阈值可配）
- 🔌 高危端口扫描（TCP Connect 扫描 11 个端口）
- 🔑 弱口令检测（HTTP Basic Auth + Telnet + FTP，200+ 组密码）
- 🗂️ Web 管理后台路径枚举（30+ 常见路径）
- 🏷️ 设备指纹识别（MAC OUI，100+ 厂商）
- 📊 ST7789 屏幕实时显示状态
- 🔊 蜂鸣器 + LED 声光告警
- ☁️ MQTT 双向通信（实时上报感知数据，接收云端命令）

### AP 板（ESP32-S3）
- 📡 发射 WifiWarden 热点（供设备连入）
- 🌐 NAT/NAPT 网络地址转换（客户端可上网）
- 🔗 UART 桥接扫描板（HOST/KICK/UNBLK 命令）
- 🛡️ MAC 黑名单强制断开（拉黑设备每次连接即踢除）
- 📋 DHCP 服务器（192.168.4.x 网段）

### 云端控制台
- 🖥️ 设备列表实时监控（WebSocket 推送）
- 📈 安全趋势曲线（Deauth / 弱口令 / 端口风险）
- 🍯 蜜罐管理（Telnet + HTTP 双蜜罐，一键启停）
- 🤖 AI 自动分析（检测到威胁自动调用 DeepSeek）
- 🚫 黑名单管理（拉黑/解除，全链路同步到 AP 板）
- 🔔 告警记录与日志
- 🔄 扫描管理（普通/深度扫描）

---

## ⚠️ 部署前必须修改

### 1. 创建 .env 文件

```bash
cp .env.example .env
# 编辑 .env，填入真实配置
```

### 2. 修改域名

全局搜索替换 `YOUR_DOMAIN.com` → 你的域名。

### 3. SSL 证书

参考 `nginx/certs/README.md` 配置 SSL 证书。

### 4. MQTT 用户密码

- `.env` 文件中设置 `MQTT_USERNAME` 和 `MQTT_PASSWORD`
- ESP32 的 `sdkconfig.defaults` 中同步修改

### 5. ESP32 WiFi 密码

- 扫描板 `esp32s3/wifiwarden/sdkconfig.defaults`: `CONFIG_SCANNER_AP_PASSWORD`
- AP 板 `esp32s3/wifiwarden_ap/main/Kconfig.projbuild`: `CONFIG_AP_PASSWORD`
- AP 板上游 WiFi: `CONFIG_WIFI_SSID` / `CONFIG_WIFI_PASSWORD`

### 6. AI API Key（可选，不填不影响系统运行）

`.env` 文件中设置 `AI_API_KEY=sk-xxx`（DeepSeek API Key）

### 7. 获取 cJSON 组件

参考 `esp32s3/wifiwarden/components/cjson/CJSON_README.md`

---

## 快速部署（服务器）

```bash
# 1. 上传项目到服务器
scp -r app/ nginx/ mosquitto/ docker-compose.yml deploy.sh .env root@服务器IP:/opt/wifiwarden/

# 2. 编辑 .env 和证书
# 参考上文「部署前必须修改」

# 3. 部署
cd /opt/wifiwarden
chmod +x deploy.sh && ./deploy.sh
```

防火墙开放: **TCP 443**（HTTPS）和 **TCP 1883**（MQTT）

---

## ESP32 烧录

```powershell
# 扫描板
cd esp32s3/wifiwarden
idf.py build
idf.py -p COM3 flash monitor

# AP板
cd esp32s3/wifiwarden_ap
idf.py build
idf.py -p COM4 flash monitor
```

> ⚠️ 烧录前确认 `sdkconfig.defaults` 中的密码和 MQTT Broker 地址已修改。首次编译可能需 `idf.py set-target esp32s3`。

---

## 上电顺序

1. **AP 板先上电** → 绿灯常亮（连上上游 WiFi）
2. **扫描板上电** → 屏幕显示 `AP:[OK]` + 设备列表
3. 手机/设备连接 `WifiWarden` 热点
4. 浏览器打开 `https://你的域名`

---

## 风险等级

| 等级 | 触发条件 | 系统动作 |
|------|----------|----------|
| 0 正常 | 无异常 | 记录日志 |
| 1 观察 | 少量开放端口 | 提升监控频率 |
| 2 警示 | 高危端口开放 | 蜂鸣器短鸣，LED 快闪 |
| 3 威胁 | 弱口令被发现 | 蜂鸣器告警 + 自动拉黑 |
| 4 严重 | Deauth 攻击活跃 | 蜂鸣器长鸣 + 自动开启蜜罐 |

---

## MQTT 主题

| 主题 | 方向 | 说明 |
|------|------|------|
| `wifiwarden/sense/{mac}` | 扫描板 → 云端 | 感知数据上报 |
| `wifiwarden/command/{mac}` | 云端 → 扫描板 | 设备专属命令 |
| `wifiwarden/command/broadcast` | 云端 → 扫描板 | 广播命令（所有设备） |
| `wifiwarden/status` | 扫描板 → 云端 | 设备在线状态 |
| `wifiwarden/honeypot` | 蜜罐 → 云端 | 蜜罐捕获日志 |

---

## License

MIT
