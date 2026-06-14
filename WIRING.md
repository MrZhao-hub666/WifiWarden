# WiFiWarden 硬件接线说明

## 扫描板（wifiwarden）— ESP32-S3 + ST7789 屏幕

| GPIO   | 功能              | 连接目标                |
| ------ | --------------- | ------------------- |
| 1 (TX) | UART发命令 → AP板RX | 接AP板 GPIO3          |
| 3 (RX) | UART收数据 ← AP板TX | 接AP板 GPIO1          |
| 2      | 屏幕背光 BLK        | ST7789 背光           |
| 6      | 蜂鸣器             | 有源蜂鸣器 (+) 串100Ω     |
| 7      | 状态LED           | LED (+) 串220Ω → GND |
| 8      | 屏幕 DC           | ST7789 DC           |
| 9      | 屏幕 RST          | ST7789 RST          |
| 10     | 屏幕 SCK          | ST7789 SCL          |
| 11     | 屏幕 MOSI         | ST7789 SDA          |
| 15     | 屏幕 CS           | ST7789 CS           |
| GND    | 公共地             | 屏幕GND + AP板GND      |

## AP板（wifiwarden_ap）— ESP32-S3

| GPIO   | 功能                | 连接目标                |
| ------ | ----------------- | ------------------- |
| 1 (TX) | UART发数据 → 扫描板RX   | 接扫描板 GPIO3          |
| 3 (RX) | UART收命令 ← 扫描板TX   | 接扫描板 GPIO1          |
| 7      | 红色LED（上游WiFi断开闪烁） | LED (+) 串220Ω → GND |
| 8      | 绿色LED（上游WiFi已连常亮） | LED (+) 串220Ω → GND |
| GND    | 公共地               | 扫描板GND（必须共地）        |

## UART 交叉接线

```
AP板 TX (GPIO1) ────→ 扫描板 RX (GPIO3)
AP板 RX (GPIO3) ←──── 扫描板 TX (GPIO1)
AP板 GND       ────   扫描板 GND         ← 必须共地！
```

## 上电顺序

1. **先给AP板上电** → 等绿灯常亮（连上上游WiFi）
2. **再给扫描板上电** → 等屏幕显示 `AP:[OK]` + `MQTT:已连接`
3. 手机连接 `WifiWarden` 热点（密码见配置文件）
4. 浏览器访问 `https://你的域名` 查看控制面板
