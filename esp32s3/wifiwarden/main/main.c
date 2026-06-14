/**
 * WiFiWarden ESP32-S3 扫描板主程序
 * 无线局域网多源感知与自适应防御系统 - 端侧代码
 *
 * P0功能：
 * 1. STA模式连接AP板WiFi (WifiWarden)，获取192.168.4.x IP
 * 2. 混杂模式嗅探802.11帧：Deauth攻击检测、Probe Request捕获、Beacon监控
 * 3. 高危端口扫描：TCP Connect扫描同网段设备的敏感端口
 * 4. 风险等级计算与告警触发
 *
 * 硬件：
 * - ESP32-S3 + ST7789V 2.0" 240x320 SPI TFT
 * - LED (GPIO7) / 蜂鸣器 (GPIO6)
 * - UART1 (GPIO1 TX / GPIO3 RX) 连接AP板
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/uart.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_netif_net_stack.h"

#include "st7789.h"
#include "weak_passwords.h"
#include "mac_oui.h"
#include "mqtt_client.h"
#include "cJSON.h"

static const char *TAG = "WiFiWarden";

// ==================== 硬件引脚定义 ====================
#define LED_GPIO       GPIO_NUM_7
#define BEEPER_GPIO    GPIO_NUM_6

// ST7789 SPI 引脚
#define TFT_MOSI_GPIO  GPIO_NUM_11
#define TFT_SCK_GPIO   GPIO_NUM_10
#define TFT_CS_GPIO    GPIO_NUM_15
#define TFT_DC_GPIO    GPIO_NUM_8
#define TFT_RST_GPIO   GPIO_NUM_9
#define TFT_BLK_GPIO   GPIO_NUM_2

// ==================== UART配置 ====================
// ESP32-S3 使用 GPIO1(TX) 和 GPIO3(RX) 作为UART1
#define UART_NUM        UART_NUM_1
#define UART_TX_PIN     GPIO_NUM_1
#define UART_RX_PIN     GPIO_NUM_3
#define UART_BAUD_RATE  115200
#define UART_BUF_SIZE   256

// ==================== 网络配置 ====================
// 扫描板以STA模式连接AP板的WiFi热点，从而进入AP板的内网
#define SCANNER_AP_SSID     CONFIG_SCANNER_AP_SSID
#define SCANNER_AP_PASSWORD CONFIG_SCANNER_AP_PASSWORD

// ==================== 端口扫描配置 ====================
#define PORT_SCAN_INTERVAL_SEC  CONFIG_PORT_SCAN_INTERVAL  // 端口扫描间隔（秒）
#define TCP_CONNECT_TIMEOUT_MS  500   // TCP端口扫描连接超时（毫秒）
#define TCP_PROBE_TIMEOUT_MS    100   // 主机发现探测超时（毫秒，100ms足够局域网判断）
#define MAX_SCANNED_HOSTS       20    // 最多记录的扫描主机数
#define TARGET_SUBNET_PREFIX    "192.168.4"  // AP板默认子网前缀

// 高危端口列表：这些端口的开放通常意味着安全风险
// 不同的端口对应不同的威胁等级，扫描结果将用于风险计算
static const uint16_t HIGH_RISK_PORTS[] = {
    21,    // FTP - 明文传输，易被嗅探
    22,    // SSH - 可能被暴力破解
    23,    // Telnet - 明文传输，极高危（IoT设备常见）
    80,    // HTTP - IoT设备管理页面，常有默认密码
    443,   // HTTPS - 相对安全但可能暴露服务
    445,   // SMB - WannaCry蠕虫传播通道
    3389,  // RDP - 远程桌面，暴力破解高频目标
    5555,  // ADB - Android调试端口，可远程控制手机
    8080,  // HTTP代理/IoT管理面板
    8443,  // HTTPS备用端口
    5900,  // VNC - 远程桌面，常被暴力破解
};
#define HIGH_RISK_PORT_COUNT (sizeof(HIGH_RISK_PORTS) / sizeof(HIGH_RISK_PORTS[0]))

// 常见Web管理后台路径（用于深度扫描隐藏后台发现）
static const char *ADMIN_PATHS[] = {
    "/admin", "/admin/", "/login", "/login/",
    "/manager", "/manager/", "/management", "/management/",
    "/system", "/system/", "/setup", "/setup/",
    "/config", "/config/", "/configuration", "/configuration/",
    "/status", "/status/", "/index", "/index.html",
    "/cgi-bin/login", "/cgi-bin", "/user",
    "/user/login", "/web", "/main.html",
    "/admin/login.html", "/admin/index.html",
    "/goform/login", "/logon", "/Logon",
    NULL  // 结束标记
};

// ==================== Deauth检测配置 ====================
// Deauth攻击原理：攻击者发送伪造的Deauthentication帧，强制断开合法设备的WiFi连接
// 检测方法：在短时间窗口内统计Deauth帧数量，超过阈值则判定为攻击
#define DEAUTH_THRESHOLD     CONFIG_DEAUTH_THRESHOLD  // 触发告警的Deauth帧最小数量
#define DEAUTH_WINDOW_SEC    5     // Deauth检测时间窗口（秒）
#define DEAUTH_ALERT_TIMEOUT_MS   30000  // 无新Deauth帧30秒后自动清除告警

// ESP-IDF标准WiFi SSID最大长度为32字节+1字节null终止符
#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN 33
#endif

// ==================== 802.11帧类型定义 ====================
// 802.11帧Frame Control字段结构: [Protocol(2bit) | Type(2bit) | Subtype(4bit)]
#define WIFI_FRAME_TYPE_MGMT    0x00  // 管理帧（Beacon/Probe/Deauth等）
#define WIFI_FRAME_TYPE_CTRL    0x01  // 控制帧（RTS/CTS/ACK等）
#define WIFI_FRAME_TYPE_DATA    0x02  // 数据帧（承载上层协议数据）

// 管理帧子类型（我们只关心这几种）
#define WIFI_FRAME_SUBTYPE_PROBE_REQ   0x04  // Probe Request - 设备主动探测WiFi
#define WIFI_FRAME_SUBTYPE_BEACON      0x08  // Beacon - AP定期广播声明存在
#define WIFI_FRAME_SUBTYPE_DEAUTH      0x0C  // Deauthentication - 断开认证连接

// ==================== 数据结构 ====================
#define MAX_DEVICES (50)
#define WIFI_CHANNEL_MAX (13)

// WiFi扫描发现的设备（来自混杂模式捕获的帧）
typedef struct {
    uint8_t mac[6];
    char mac_str[18];
    int8_t rssi;
    char ssid[MAX_SSID_LEN];
    uint32_t last_seen;
    uint8_t risk_level;
    bool blacklisted;
} device_entry_t;

// 端口扫描发现的主机
typedef struct {
    char ip_str[16];           // IP地址字符串，如"192.168.4.3"
    uint8_t mac[6];            // MAC地址（通过ARP表获取）
    char mac_str[18];          // MAC地址字符串
    char vendor[20];           // 设备厂商（通过MAC OUI识别）
    char hostname[32];         // DHCP主机名（来自AP板）
    uint16_t open_ports[16];   // 开放的端口列表
    uint8_t open_port_count;   // 开放端口数量
    uint8_t risk_level;        // 该主机的风险等级(0-4)
    uint32_t last_scanned;     // 最后扫描时间
    bool is_alive;             // 主机是否在线
    // 弱口令检测结果
    bool weak_http_auth;       // HTTP Basic Auth弱口令
    char weak_http_cred[48];   // 被猜中的HTTP密码
    bool strong_http;          // HTTP不需要密码或密码强
    bool telnet_weak;          // Telnet默认密码登录成功
    bool ftp_anonymous;        // FTP匿名登录成功
} scanned_host_t;

// Deauth攻击事件记录（单帧级）
typedef struct {
    uint8_t attacker_mac[6];   // 发送Deauth帧的设备MAC（可能伪造）
    uint8_t victim_mac[6];     // 被断开连接的设备MAC
    uint16_t reason_code;      // Deauth原因码
    int8_t rssi;               // 接收信号强度
    uint32_t timestamp_ms;     // 检测时间戳（毫秒）
} deauth_event_t;

// 攻击事件日志（按攻击次数记录，非单帧）
#define MAX_ATTACK_LOG 10
typedef struct {
    uint32_t timestamp_s;      // 攻击时间（秒）
    uint8_t attacker_mac[6];   // 攻击者MAC
    uint16_t frame_count;      // 窗口内Deauth帧数
    uint8_t risk_level;        // 攻击风险等级
} attack_log_entry_t;

// ==================== 前向声明 ====================
static void uart_init(void);
static void uart_receive_task(void *pvParameters);
static void display_update_task(void *pvParameters);
static void port_scan_task(void *pvParameters);
static void wifi_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);

// ==================== 全局变量 ====================

// WiFi连接状态
static EventGroupHandle_t s_wifi_event_group = NULL;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_retry_count = 0;  // 连接重试计数
static volatile bool g_sta_connected = false;       // 是否已连接到AP板WiFi
static esp_netif_t *g_sta_netif = NULL;    // STA网络接口
static char g_sta_ip_str[16] = {0};        // 本机IP地址字符串

// 设备列表（来自混杂模式帧捕获，记录探测到的WiFi设备）
static device_entry_t g_devices[MAX_DEVICES];
static uint8_t g_device_count = 0;
static SemaphoreHandle_t g_devices_mutex = NULL;

// 端口扫描结果
static scanned_host_t g_scanned_hosts[MAX_SCANNED_HOSTS];
static uint8_t g_scanned_host_count = 0;
static uint16_t g_total_open_ports = 0;   // 当前扫描周期发现的开放端口总数
static uint8_t g_weak_count = 0;           // 当前扫描周期发现的弱口令主机数
static SemaphoreHandle_t g_scan_mutex = NULL;
static volatile bool g_port_scan_running = false;  // 端口扫描是否正在进行

// Deauth检测状态
static deauth_event_t g_deauth_events[DEAUTH_THRESHOLD];  // 最近的Deauth事件环形缓冲区
static volatile uint8_t g_deauth_event_idx = 0;            // 环形缓冲区写入索引
static volatile uint8_t g_deauth_count_in_window = 0;      // 时间窗口内的Deauth帧计数
static SemaphoreHandle_t g_deauth_mutex = NULL;
static volatile bool g_deauth_alert_trigger = false;        // 由回调设置，超时清除（显示用）
static volatile bool g_deauth_beep_trigger = false;         // 由回调设置，主循环清除（蜂鸣用）
static volatile uint32_t g_deauth_last_detected_ms = 0;    // 最后一次检测到Deauth帧的时间（用于超时清除）

// 攻击事件日志（环形缓冲区）
static attack_log_entry_t g_attack_log[MAX_ATTACK_LOG];
static uint8_t g_attack_log_idx = 0;       // 写入索引
static uint8_t g_attack_log_count = 0;     // 总事件数

// 告警与风险状态
static volatile uint8_t g_current_risk_level = 0;  // 当前综合风险等级(0-4)
static volatile bool g_alert_active = false;        // 是否处于告警状态

// 蜜罐状态（云端同步）
static volatile bool g_honeypot_enabled = false;
static char g_honeypot_ssid[32] = "Free_WiFi";

// 深度扫描标志（由云端命令触发）
static volatile bool g_deep_scan_pending = false;

// 端口扫描任务句柄（用于触发即时扫描）
static TaskHandle_t g_port_scan_task_handle = NULL;

// MQTT强制发布标志（设备变化时立即上报）
static volatile bool g_mqtt_force_publish = false;

// AP板状态（通过UART接收）
static uint8_t g_ap_sta_count = 0;       // AP板WifiWarden连接的设备数（含扫描板自身）
static bool g_ap_sta_connected = false;     // AP板UART连接状态
static SemaphoreHandle_t g_ap_count_mutex = NULL;

// AP板上游WiFi信息（通过UART接收）
static char g_ap_upstream_ssid[33] = {0};
static int8_t g_ap_upstream_rssi = 0;
static bool g_ap_upstream_connected = false;
static SemaphoreHandle_t g_wifi_mutex = NULL;

// AP板上报的已连接设备IP和MAC列表（通过UART接收HOST:IP,MAC消息）
static char g_known_host_ips[MAX_SCANNED_HOSTS][16];
static char g_known_host_macs[MAX_SCANNED_HOSTS][18];
static char g_known_host_names[MAX_SCANNED_HOSTS][32];  // DHCP hostname
static uint8_t g_known_host_count = 0;
static uint32_t g_last_host_rx_ms = 0;   // 上次收到HOST的时间，用于检测批次边界
static SemaphoreHandle_t g_known_host_mutex = NULL;

// 统计信息
static volatile uint32_t g_total_deauth_frames = 0;    // 累计接收的Deauth帧数
static volatile uint32_t g_total_probe_frames = 0;     // 累计接收的Probe Request帧数
static volatile uint32_t g_total_scan_cycles = 0;      // 累计完成的端口扫描周期数

// MAC地址
static uint8_t s_device_mac[6];
static char s_device_mac_str[18];

// ==================== 工具函数 ====================

// 通过UART向AP板发送踢设备命令
// 当发现高危端口或弱口令时，自动断开该设备
static void kick_device(const char *mac_str) {
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "KICK:%s\n", mac_str);
    uart_write_bytes(UART_NUM, buffer, len);
    ESP_LOGW(TAG, "Sent KICK command for %s", mac_str);
}

// MAC地址转可读字符串
static void hex_to_str(const uint8_t *hex, char *str, size_t len) {
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             hex[0], hex[1], hex[2], hex[3], hex[4], hex[5]);
}

// 在设备列表中查找指定MAC的设备，返回索引，-1表示未找到
static int find_device(const uint8_t *mac) {
    for (int i = 0; i < g_device_count; i++) {
        if (memcmp(g_devices[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// 添加或更新设备到列表（需在g_devices_mutex保护下调用）
static int add_device(const uint8_t *mac, int8_t rssi, const char *ssid) {
    // 过滤ESP32开发板（通过OUI表识别）
    if (is_esp32_mac(mac)) {
        return -1;
    }
    if (g_device_count >= MAX_DEVICES) {
        return -1;
    }
    int idx = find_device(mac);
    if (idx >= 0) {
        // 已存在，更新信息
        g_devices[idx].rssi = rssi;
        g_devices[idx].last_seen = xTaskGetTickCount();
        if (ssid) strncpy(g_devices[idx].ssid, ssid, MAX_SSID_LEN - 1);
        return idx;
    }
    // 新设备，添加到列表末尾
    idx = g_device_count++;
    memcpy(g_devices[idx].mac, mac, 6);
    hex_to_str(mac, g_devices[idx].mac_str, 18);
    g_devices[idx].rssi = rssi;
    if (ssid) strncpy(g_devices[idx].ssid, ssid, MAX_SSID_LEN - 1);
    g_devices[idx].last_seen = xTaskGetTickCount();
    g_devices[idx].risk_level = 0;
    g_devices[idx].blacklisted = false;
    return idx;
}

// ==================== 硬件驱动 ====================

// LED初始化
static void led_init(void) {
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_GPIO, 0);
}

static void led_set(bool on) {
    gpio_set_level(LED_GPIO, on ? 1 : 0);
}

static void led_blink(int times, int delay_ms) {
    for (int i = 0; i < times; i++) {
        led_set(true);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        led_set(false);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

// 蜂鸣器初始化（低电平触发）
static void beeper_init(void) {
    gpio_reset_pin(BEEPER_GPIO);
    gpio_set_direction(BEEPER_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BEEPER_GPIO, 1);  // 高电平不响
}

static void beeper_beep(int duration_ms) {
    gpio_set_level(BEEPER_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(duration_ms));
    gpio_set_level(BEEPER_GPIO, 1);
}

// 根据风险等级发出不同的蜂鸣模式
static void beeper_alert_pattern(uint8_t risk_level) {
    if (risk_level >= 4) {
        // 极高危：急促长鸣5次
        for (int i = 0; i < 5; i++) {
            beeper_beep(200);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    } else if (risk_level >= 3) {
        // 高危：3次短鸣
        for (int i = 0; i < 3; i++) {
            beeper_beep(100);
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    } else if (risk_level >= 2) {
        // 中危：1次短鸣
        beeper_beep(100);
    } else {
        // 低危：极短提示
        beeper_beep(50);
    }
}

// ==================== UART功能 ====================
// 扫描板通过UART与AP板通信，接收AP板的设备数量和上游WiFi信息

static void uart_init(void) {
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 122,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(UART_NUM, UART_BUF_SIZE, UART_BUF_SIZE, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_TX_PIN, UART_RX_PIN,
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    ESP_LOGI(TAG, "UART initialized: TX=%d, RX=%d, Baud=%d", UART_TX_PIN, UART_RX_PIN, UART_BAUD_RATE);
}

// UART接收任务 - 解析AP板发送的数据
// 协议格式:
//   "DEV:<count>"         - AP板连接的设备数量(含扫描板自身，显示时需减1)
//   "WIFI:<SSID>,<RSSI>"  - AP板上游WiFi信息
static void uart_receive_task(void *pvParameters) {
    uint8_t data[UART_BUF_SIZE + 1];  // +1 给null终止符留空间
    uint32_t last_receive_tick = 0;
    bool uart_data_received = false;

    while (1) {
        int len = uart_read_bytes(UART_NUM, data, UART_BUF_SIZE, pdMS_TO_TICKS(100));

        if (len > 0) {
            data[len] = '\0';

            // 数据有效性校验：长度4-240字节，至少30%可打印字符
            bool is_valid = (len >= 4 && len <= 240);
            uint8_t printable_count = 0;
            for (int i = 0; i < len; i++) {
                if (data[i] >= 0x20 && data[i] <= 0x7E) printable_count++;
            }

            if (!is_valid || printable_count < len * 3 / 10) {
                ESP_LOGW(TAG, "UART: invalid data len=%d, printable=%d/%d", 
                         len, printable_count, len);
                continue;
            }

            last_receive_tick = xTaskGetTickCount();
            uart_data_received = true;

            // 逐行解析数据
            char *str = (char *)data;
            char *line_start = str;

            for (int i = 0; i <= len; i++) {
                if (str[i] == '\n' || str[i] == '\0' || str[i] == '\r') {
                    char old_char = str[i];
                    str[i] = '\0';

                    // 解析 "DEV:3" - AP板连接设备数量
                    if (strncmp(line_start, "DEV:", 4) == 0) {
                        int count = atoi(line_start + 4);
                        if (count >= 0 && count <= 10) {
                            uint8_t old_count;

                            if (g_ap_count_mutex) xSemaphoreTake(g_ap_count_mutex, portMAX_DELAY);
                            old_count = g_ap_sta_count;
                            g_ap_sta_count = (uint8_t)count;
                            g_ap_sta_connected = true;

                            // 设备数量变化时蜂鸣器提示
                            if (count > old_count) {
                                beeper_beep(100);  // 新设备连入短响
                                // 新设备连入时不清空列表，HOST消息会追加
                            } else if (count < old_count) {
                                beeper_beep(200);  // 设备断开长响
                                // 不再清空已知IP列表——保持设备记录，数量只增不减
                                // 断开的设备仍保留在列表中，AP板后续HOST消息会刷新在线设备
                            }
                            // 设备数量变化时，标记MQTT立即发布
                            g_mqtt_force_publish = true;

                            if (g_ap_count_mutex) xSemaphoreGive(g_ap_count_mutex);
                            ESP_LOGI(TAG, "UART: DEV:%d", count);
                        }
                    }
                    // 解析 "WIFI:SSID,RSSI" - AP板上游WiFi信息
                    else if (strncmp(line_start, "WIFI:", 5) == 0) {
                        char *comma = strchr(line_start + 5, ',');
                        if (comma) {
                            *comma = '\0';

                            if (g_wifi_mutex) xSemaphoreTake(g_wifi_mutex, portMAX_DELAY);
                            strncpy(g_ap_upstream_ssid, line_start + 5, sizeof(g_ap_upstream_ssid) - 1);
                            g_ap_upstream_ssid[sizeof(g_ap_upstream_ssid) - 1] = '\0';

                            char *endptr;
                            long rssi_long = strtol(comma + 1, &endptr, 10);
                            if (endptr != comma + 1 && rssi_long >= -100 && rssi_long <= 0) {
                                g_ap_upstream_rssi = (int8_t)rssi_long;
                                g_ap_upstream_connected = true;
                                ESP_LOGI(TAG, "UART: WIFI:%s,%d", g_ap_upstream_ssid, g_ap_upstream_rssi);
                            }

                            if (g_wifi_mutex) xSemaphoreGive(g_wifi_mutex);
                        }
                    }
                    // 解析 "HOST:192.168.4.3,AA:BB:CC:DD:EE:FF,vivo-X90" - IP,MAC,hostname
                    else if (strncmp(line_start, "HOST:", 5) == 0) {
                        char *host_data = line_start + 5;
                        char *comma_pos = strchr(host_data, ',');
                        if (comma_pos) {
                            *comma_pos = '\0';
                            char *host_ip = host_data;
                            char *host_mac = comma_pos + 1;
                            // 解析可选的hostname字段（第三个逗号后）
                            char *host_name = NULL;
                            char *comma2_pos = strchr(host_mac, ',');
                            if (comma2_pos) {
                                *comma2_pos = '\0';
                                host_name = comma2_pos + 1;
                                // 去除尾部空白
                                char *nl = strchr(host_name, '\r');
                                if (nl) *nl = '\0';
                                nl = strchr(host_name, '\n');
                                if (nl) *nl = '\0';
                            }
                            bool valid = true;
                            int dots = 0;
                            for (int k = 0; host_ip[k] != '\0'; k++) {
                                if (host_ip[k] == '.') dots++;
                                else if (host_ip[k] < '0' || host_ip[k] > '9') { valid = false; break; }
                            }
                            if (valid && dots == 3) {
                                if (g_known_host_mutex) xSemaphoreTake(g_known_host_mutex, portMAX_DELAY);
                                // 检测批次边界：距上次HOST超过1秒=新批次，清空旧列表
                                uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
                                if (now - g_last_host_rx_ms > 1000) g_known_host_count = 0;
                                g_last_host_rx_ms = now;
                                // 查找是否已存在（按IP匹配），如果存在则更新
                                int exist_idx = -1;
                                for (int k = 0; k < g_known_host_count; k++) {
                                    if (strcmp(g_known_host_ips[k], host_ip) == 0) {
                                        exist_idx = k; break;
                                    }
                                }
                                if (exist_idx >= 0) {
                                    // 已存在，更新MAC和hostname
                                    strncpy(g_known_host_macs[exist_idx], host_mac, 17);
                                    g_known_host_macs[exist_idx][17] = '\0';
                                    if (host_name && host_name[0] != '\0') {
                                        strncpy(g_known_host_names[exist_idx], host_name, 31);
                                        g_known_host_names[exist_idx][31] = '\0';
                                    }
                                } else if (g_known_host_count < MAX_SCANNED_HOSTS) {
                                    strncpy(g_known_host_ips[g_known_host_count], host_ip, 15);
                                    g_known_host_ips[g_known_host_count][15] = '\0';
                                    strncpy(g_known_host_macs[g_known_host_count], host_mac, 17);
                                    g_known_host_macs[g_known_host_count][17] = '\0';
                                    if (host_name && host_name[0] != '\0') {
                                        strncpy(g_known_host_names[g_known_host_count], host_name, 31);
                                        g_known_host_names[g_known_host_count][31] = '\0';
                                    } else {
                                        g_known_host_names[g_known_host_count][0] = '\0';
                                    }
                                    g_known_host_count++;
                                }
                                ESP_LOGI(TAG, "UART: HOST:%s,%s,%s", host_ip, host_mac,
                                         (host_name && host_name[0]) ? host_name : "");
                                if (g_known_host_mutex) xSemaphoreGive(g_known_host_mutex);
                            }
                        }
                    }

                    line_start = str + i + 1;
                    if (old_char == '\0') break;
                }
            }
        } else {
            // 检测UART连接超时（10秒无数据，AP板每2秒发一次）
            if (uart_data_received && last_receive_tick > 0) {
                uint32_t idle_ticks = xTaskGetTickCount() - last_receive_tick;
                if (idle_ticks > pdMS_TO_TICKS(10000)) {
                    g_ap_sta_connected = false;
                    g_ap_upstream_connected = false;
                    last_receive_tick = xTaskGetTickCount();
                    ESP_LOGW(TAG, "UART connection timeout");
                }
            }
        }
    }
}

// ==================== 802.11帧解析 ====================

/**
 * 从原始802.11帧的Frame Control字段提取帧类型和子类型
 * Frame Control第一个字节: [Protocol(2bit) | Type(2bit) | Subtype(4bit)]
 */
static inline void parse_frame_type(const uint8_t *payload, uint8_t *type, uint8_t *subtype) {
    *type = (payload[0] >> 2) & 0x03;
    *subtype = (payload[0] >> 4) & 0x0F;
}

/**
 * 从802.11管理帧中提取三个MAC地址
 * 管理帧头部结构: FrameCtrl(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtrl(2)
 * Addr1 = 接收方/目标地址
 * Addr2 = 发送方/源地址
 * Addr3 = BSSID（基本服务集标识）
 */
static inline void parse_mgmt_addrs(const uint8_t *payload,
                                     uint8_t *addr1, uint8_t *addr2, uint8_t *addr3) {
    memcpy(addr1, payload + 4, 6);    // 目标地址
    memcpy(addr2, payload + 10, 6);   // 源地址
    memcpy(addr3, payload + 16, 6);   // BSSID
}

/**
 * 从Probe Request帧中提取SSID
 * Probe Request帧结构: 管理帧头(24字节) + Tagged Parameters
 * 第一个Tag通常是SSID(Tag ID=0)，包含设备正在寻找的WiFi名称
 */
static int parse_ssid_from_probe(const uint8_t *payload, uint16_t len,
                                  char *ssid, uint8_t ssid_buf_len) {
    if (len <= 24) return -1;

    const uint8_t *tagged_params = payload + 24;
    uint16_t tagged_len = len - 24;
    uint16_t offset = 0;

    while (offset + 2 <= tagged_len) {
        uint8_t tag_id = tagged_params[offset];
        uint8_t tag_len = tagged_params[offset + 1];

        if (tag_id == 0) {  // SSID Tag
            if (tag_len == 0) {
                // 长度为0表示广播探测（设备在搜索所有WiFi）
                ssid[0] = '\0';
                return 0;
            }
            uint8_t copy_len = (tag_len < ssid_buf_len - 1) ? tag_len : ssid_buf_len - 1;
            memcpy(ssid, tagged_params + offset + 2, copy_len);
            ssid[copy_len] = '\0';
            return 0;
        }

        offset += 2 + tag_len;
    }

    ssid[0] = '\0';
    return -1;
}

/**
 * 从Beacon帧中提取SSID
 * Beacon帧结构: 管理帧头(24字节) + Timestamp(8) + BeaconInterval(2) + Capability(2) + Tagged Params
 * 所以SSID Tag从偏移36字节(24+12)开始
 */
static int parse_ssid_from_beacon(const uint8_t *payload, uint16_t len,
                                   char *ssid, uint8_t ssid_buf_len) {
    if (len <= 36) return -1;

    const uint8_t *tagged_params = payload + 36;
    uint16_t tagged_len = len - 36;
    uint16_t offset = 0;

    while (offset + 2 <= tagged_len) {
        uint8_t tag_id = tagged_params[offset];
        uint8_t tag_len = tagged_params[offset + 1];

        if (tag_id == 0) {  // SSID Tag
            if (tag_len == 0) {
                ssid[0] = '\0';
                return 0;
            }
            uint8_t copy_len = (tag_len < ssid_buf_len - 1) ? tag_len : ssid_buf_len - 1;
            memcpy(ssid, tagged_params + offset + 2, copy_len);
            ssid[copy_len] = '\0';
            return 0;
        }

        offset += 2 + tag_len;
    }

    ssid[0] = '\0';
    return -1;
}

/**
 * 混杂模式回调函数 - 处理捕获的802.11帧
 *
 * 此函数在WiFi任务上下文中运行，必须快速返回！
 * - 不能调用vTaskDelay等阻塞函数
 * - 不能做耗时操作
 * - 告警触发只设置标志，由主循环负责蜂鸣器操作
 */
static void wifi_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    // 只处理管理帧（Beacon/Probe/Deauth等都是管理帧）
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    int8_t rssi = pkt->rx_ctrl.rssi;

    // 管理帧头部至少24字节
    if (len < 24) return;

    // 解析帧类型和子类型
    uint8_t frame_type, frame_subtype;
    parse_frame_type(payload, &frame_type, &frame_subtype);

    // 再次确认是管理帧（双重检查）
    if (frame_type != WIFI_FRAME_TYPE_MGMT) return;

    // 解析MAC地址
    uint8_t addr1[6], addr2[6], addr3[6];
    parse_mgmt_addrs(payload, addr1, addr2, addr3);

    switch (frame_subtype) {
    case WIFI_FRAME_SUBTYPE_DEAUTH: {
        // ======== Deauth帧检测 ========
        // Deauth帧用于断开WiFi连接。正常情况下AP或设备会偶尔发送，
        // 但短时间内大量Deauth帧意味着有人在执行Deauth攻击（WiFi干扰攻击）
        g_total_deauth_frames++;

        // 提取Reason Code（帧体前2字节，位于24字节头部之后）
        uint16_t reason_code = 0;
        if (len >= 26) {
            reason_code = payload[24] | (payload[25] << 8);
        }

        ESP_LOGW(TAG, "DEAUTH detected! Src=%02X:%02X:%02X:%02X:%02X:%02X "
                 "Dst=%02X:%02X:%02X:%02X:%02X:%02X Reason=%u RSSI=%d",
                 addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5],
                 addr1[0], addr1[1], addr1[2], addr1[3], addr1[4], addr1[5],
                 reason_code, rssi);

        // 记录Deauth事件并检测是否构成攻击
        // 使用短超时获取互斥锁，避免在回调中长时间阻塞
        if (g_deauth_mutex && xSemaphoreTake(g_deauth_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
            g_deauth_last_detected_ms = now_ms;  // 记录最后一次Deauth帧时间

            // 写入环形缓冲区
            deauth_event_t *evt = &g_deauth_events[g_deauth_event_idx % DEAUTH_THRESHOLD];
            memcpy(evt->attacker_mac, addr2, 6);
            memcpy(evt->victim_mac, addr1, 6);
            evt->reason_code = reason_code;
            evt->rssi = rssi;
            evt->timestamp_ms = now_ms;
            g_deauth_event_idx++;

            // 统计时间窗口内的Deauth帧数量
            // 环形缓冲区：从最新写入位置逆序遍历，只检查有效范围内的事件
            uint32_t window_start_ms = now_ms - (DEAUTH_WINDOW_SEC * 1000);
            uint8_t count = 0;
            uint8_t total = (g_deauth_event_idx < DEAUTH_THRESHOLD) ?
                             g_deauth_event_idx : DEAUTH_THRESHOLD;
            // 从最新事件开始反向遍历，确保取到时间窗口内的最新事件
            uint8_t start = (total > 0) ? (g_deauth_event_idx - 1) % DEAUTH_THRESHOLD : 0;
            for (uint8_t i = 0; i < total; i++) {
                uint8_t idx = (start - i + DEAUTH_THRESHOLD) % DEAUTH_THRESHOLD;
                if (g_deauth_events[idx].timestamp_ms >= window_start_ms) {
                    count++;
                }
            }
            g_deauth_count_in_window = count;

            // 超过阈值则判定为Deauth攻击，触发告警
            if (count >= DEAUTH_THRESHOLD && !g_deauth_alert_trigger) {
                g_deauth_alert_trigger = true;  // 显示标语+超时清除
                g_deauth_beep_trigger = true;   // 触发蜂鸣（主循环清）
                g_alert_active = true;
                g_current_risk_level = 4;  // Deauth攻击=最高风险等级
                ESP_LOGE(TAG, "DEAUTH ATTACK DETECTED! %u frames in %d sec window!",
                         count, DEAUTH_WINDOW_SEC);

                // 记录到攻击日志
                attack_log_entry_t *log = &g_attack_log[g_attack_log_idx % MAX_ATTACK_LOG];
                log->timestamp_s = (uint32_t)(esp_timer_get_time() / 1000000);
                memcpy(log->attacker_mac, addr2, 6);
                log->frame_count = count;
                log->risk_level = 4;
                g_attack_log_idx++;
                if (g_attack_log_count < MAX_ATTACK_LOG) g_attack_log_count++;
            }

            xSemaphoreGive(g_deauth_mutex);
        }
        break;
    }

    case WIFI_FRAME_SUBTYPE_PROBE_REQ: {
        // ======== Probe Request捕获 ========
        // 设备在寻找WiFi时会广播Probe Request帧
        // 用途：发现附近设备、设备指纹识别、信号监测
        g_total_probe_frames++;

        char ssid[MAX_SSID_LEN] = {0};
        parse_ssid_from_probe(payload, len, ssid, MAX_SSID_LEN);

        // 将探测设备添加到设备列表
        if (g_devices_mutex && xSemaphoreTake(g_devices_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            add_device(addr2, rssi, ssid[0] ? ssid : NULL);
            xSemaphoreGive(g_devices_mutex);
        }
        break;
    }

    case WIFI_FRAME_SUBTYPE_BEACON: {
        // ======== Beacon帧监控 ========
        // AP每隔约100ms广播Beacon帧声明自己的存在
        // 用途：发现附近AP、信号强度监控、伪造AP检测
        char ssid[MAX_SSID_LEN] = {0};
        parse_ssid_from_beacon(payload, len, ssid, MAX_SSID_LEN);

        // 将AP添加到设备列表
        if (g_devices_mutex && xSemaphoreTake(g_devices_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            add_device(addr2, rssi, ssid[0] ? ssid : NULL);
            xSemaphoreGive(g_devices_mutex);
        }
        break;
    }

    default:
        // 其他管理帧类型（Association/Authentication等）暂不处理
        break;
    }
}

// ==================== 端口扫描功能 ====================

/**
 * 扫描指定IP的指定端口（TCP Connect扫描）
 *
 * 原理：尝试与目标端口建立完整的TCP连接
 * - 连接成功 → 端口开放（有服务在监听）
 * - 收到RST → 端口关闭（无服务但主机存在）
 * - 超时无响应 → 端口被防火墙过滤或主机不存在
 *
 * 返回：true=端口开放，false=端口关闭/超时
 */
static bool scan_port(const char *ip, uint16_t port) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // 设置非阻塞模式，以便使用select实现超时控制
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    bool port_open = false;

    if (ret == 0) {
        // 立即连接成功（局域网内偶尔出现）
        port_open = true;
    } else if (errno == EINPROGRESS) {
        // 连接正在进行中，使用select等待结果
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        struct timeval tv;
        tv.tv_sec = TCP_CONNECT_TIMEOUT_MS / 1000;
        tv.tv_usec = (TCP_CONNECT_TIMEOUT_MS % 1000) * 1000;

        ret = select(sock + 1, NULL, &write_fds, NULL, &tv);

        if (ret > 0) {
            // select返回，检查连接是否真正成功
            int error = 0;
            socklen_t elen = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &elen);
            port_open = (error == 0);  // error=0表示连接成功
            // error=ECONNREFUSED表示端口关闭但主机存在
        }
        // ret=0: 超时，端口可能被过滤
        // ret<0: select错误
    }
    // errno=ECONNREFUSED: 端口关闭但主机存在

    close(sock);
    return port_open;
}

/**
 * 主机存活性探测 - 判断指定IP是否有设备在线
 *
 * 原理：依次尝试TCP连接多个常见端口，根据响应判断主机是否存在
 * - 连接成功 → 主机存在且端口开放
 * - 收到RST(ECONNREFUSED) → 主机存在但端口关闭
 * - 超时无响应 → 主机可能不存在
 *
 * 多端口探测原因：很多设备不开放80端口（ESP32就没有HTTP服务器），
 * 但可能开放其他端口（SSH=22, ADB=5555, HTTP代理=8080等）
 * 只要任一端口有响应就说明主机存活
 */
static bool is_host_alive(const char *ip) {
    // 探测端口列表：覆盖常见服务，提高发现率
    static const uint16_t probe_ports[] = {80, 22};  // 只探测2个最常见端口，大幅加速
    static const int probe_count = sizeof(probe_ports) / sizeof(probe_ports[0]);

    for (int p = 0; p < probe_count; p++) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(probe_ports[p]);
        dest_addr.sin_addr.s_addr = inet_addr(ip);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int ret = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        bool alive = false;

        if (ret == 0) {
            // 立即连接成功
            alive = true;
        } else if (errno == EINPROGRESS) {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = TCP_PROBE_TIMEOUT_MS * 1000;

            ret = select(sock + 1, NULL, &write_fds, NULL, &tv);

            if (ret > 0) {
                int error = 0;
                socklen_t elen = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &elen);
                // error=0: 连接成功，主机存在
                // error=ECONNREFUSED: 端口关闭但主机确实存在（收到了RST）
                alive = (error == 0 || error == ECONNREFUSED);
            }
        } else if (errno == ECONNREFUSED) {
            // 连接被拒绝，但说明主机存在
            alive = true;
        }

        close(sock);

        if (alive) return true;
    }


    return false;
}

/**
 * 通过ARP表查询指定IP的MAC地址
 * 原理：lwIP维护ARP缓存表，端口扫描时TCP连接会触发ARP解析
 * 扫描完成后直接从ARP表查MAC，无需额外网络请求
 */
static bool get_mac_by_ip(const char *ip_str, uint8_t *mac_out) {
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA");
    }
    if (!sta_netif) return false;

    struct netif *netif = esp_netif_get_netif_impl(sta_netif);
    if (!netif) return false;

    ip4_addr_t target_ip;
    target_ip.addr = inet_addr(ip_str);

    struct eth_addr *eth_ret = NULL;
    const ip4_addr_t *ip_ret = NULL;

    if (etharp_find_addr(netif, &target_ip, &eth_ret, &ip_ret) == ERR_OK) {
        if (eth_ret) {
            memcpy(mac_out, eth_ret->addr, 6);
            return true;
        }
    }
    return false;
}

/**
 * 根据开放端口计算单个主机的风险等级
 * 返回0-4的风险等级
 */
static uint8_t calculate_host_risk(const scanned_host_t *host) {
    uint8_t risk = 0;
    for (int i = 0; i < host->open_port_count; i++) {
        uint16_t port = host->open_ports[i];
        switch (port) {
        case 23:    // Telnet - 明文远程管理，IoT设备常见，极高危
        case 5555:  // ADB - Android调试端口，可被远程控制，极高危
            risk = 4;
            break;
        case 445:   // SMB - 蠕虫传播通道，高危
        case 3389:  // RDP - 远程桌面暴力破解目标，高危
        case 5900:  // VNC - 远程桌面，高危
            if (risk < 3) risk = 3;
            break;
        case 21:    // FTP - 明文传输，中危
        case 80:    // HTTP - IoT管理页面，中危
        case 8080:  // HTTP代理/IoT管理，中危
            if (risk < 2) risk = 2;
            break;
        case 22:    // SSH - 有加密但可被暴力破解，低危
        case 443:   // HTTPS - 有加密，低危
        case 8443:  // HTTPS备用，低危
            if (risk < 1) risk = 1;
            break;
        default:
            if (risk < 1) risk = 1;
            break;
        }
    }
    return risk;
}

// ==================== 弱口令检测 ====================

/**
 * Base64编码（用于HTTP Basic Auth）
 * 将用户名密码对编码为 "admin:admin" → "YWRtaW46YWRtaW4="
 */
static void base64_encode(const char *input, int input_len, char *output, int output_len) {
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0;
    uint8_t buf[3];

    while (input_len > 0 && j + 4 < output_len) {
        int chunk = (input_len < 3) ? input_len : 3;
        for (int k = 0; k < chunk; k++) buf[k] = input[i++];
        input_len -= chunk;

        output[j++] = b64_table[(buf[0] >> 2) & 0x3F];
        output[j++] = b64_table[((buf[0] << 4) | (buf[1] >> 4)) & 0x3F];
        output[j++] = (chunk > 1) ? b64_table[((buf[1] << 2) | (buf[2] >> 6)) & 0x3F] : '=';
        output[j++] = (chunk > 2) ? b64_table[buf[2] & 0x3F] : '=';
    }
    if (j < output_len) output[j] = '\0';
}

/**
 * 尝试HTTP Basic Auth弱口令
 *
 * 原理：
 * 1. 先发一个不带认证的GET请求，看是否返回401（需要认证）
 * 2. 如果是401，遍历常见密码组合重发带Authorization头的请求
 * 3. 如果返回200（成功），说明密码被猜中
 *
 * 结果写入host结构体
 */
static void check_http_basic_auth(const char *ip, uint16_t port, scanned_host_t *host) {
    // 从 weak_passwords.h 中读取HTTP默认密码字典
    // HTTP_DEFAULT_CREDS 定义在 weak_passwords.h 中，存储在Flash

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(ip);

    // === 第1步：发GET请求看是否需要认证 ===
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    // 设置超时
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        close(sock);
        return;
    }

    // 发送GET请求
    char req[256];
    int len = snprintf(req, sizeof(req),
        "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", ip);
    write(sock, req, len);

    // 读取响应
    char resp[1024] = {0};
    int total = 0;
    while (total < (int)sizeof(resp) - 1) {
        int n = read(sock, resp + total, sizeof(resp) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    close(sock);
    resp[total] = '\0';

    // 检查是否需要认证
    bool requires_auth = (strstr(resp, "401") != NULL);
    bool login_success = (strstr(resp, "200") != NULL && strstr(resp, "401") == NULL);

    if (!requires_auth && !login_success) {
        // 无法确定状态，跳过
        return;
    }

    if (!requires_auth || login_success) {
        // 不需要认证就访问到了（说明管理页面公开），这是另一种风险
        host->strong_http = true;
        return;
    }

    // === 第2步：需要认证，尝试默认密码 ===
    for (int c = 0; HTTP_DEFAULT_CREDS[c] != NULL; c++) {
        // 生成Base64认证头
        char b64[64];
        base64_encode(HTTP_DEFAULT_CREDS[c], strlen(HTTP_DEFAULT_CREDS[c]), b64, sizeof(b64));

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
            close(sock);
            continue;
        }

        len = snprintf(req, sizeof(req),
            "GET / HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n",
            ip, b64);
        write(sock, req, len);

        memset(resp, 0, sizeof(resp));
        total = 0;
        while (total < (int)sizeof(resp) - 1) {
            int n = read(sock, resp + total, sizeof(resp) - 1 - total);
            if (n <= 0) break;
            total += n;
        }
        close(sock);
        resp[total] = '\0';

        // 200 OK = 密码正确
        if (strstr(resp, "200 OK") || strstr(resp, "200 Ok") || strstr(resp, "200 ok")) {
            host->weak_http_auth = true;
            strncpy(host->weak_http_cred, HTTP_DEFAULT_CREDS[c], sizeof(host->weak_http_cred) - 1);
            host->risk_level = 4;  // 弱口令=最高风险
            ESP_LOGW(TAG, "WEAK HTTP AUTH! %s:%d -> %s (risk=4)", ip, port, HTTP_DEFAULT_CREDS[c]);
            return;
        }

        // 如果密码尝试导致429/403，停止尝试
        if (strstr(resp, "429") || strstr(resp, "403")) {
            break;
        }
    }
}

/**
 * 尝试Telnet默认密码登录
 *
 * 原理：
 * 1. 连接23端口，等待 "login:" 提示
 * 2. 发送用户名
 * 3. 等待 "Password:" 提示
 * 4. 发送密码
 * 5. 如果收到shell提示符($/#/>)，说明登录成功
 */
static void check_telnet_password(const char *ip, scanned_host_t *host) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(23);
    dest.sin_addr.s_addr = inet_addr(ip);

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        close(sock);
        return;
    }

    // 读取初始banner（等待login提示）
    char resp[256] = {0};
    int total = 0;
    uint32_t start = (uint32_t)(esp_timer_get_time() / 1000);
    while ((esp_timer_get_time() / 1000) - start < 3000) {
        char c = 0;
        if (read(sock, &c, 1) == 1) {
            if (total < (int)sizeof(resp) - 1) resp[total++] = c;
            resp[total] = '\0';
        }

        // 检测到login提示符
        if (strstr(resp, "login:") || strstr(resp, "Login:") ||
            strstr(resp, "Username:") || strstr(resp, "username:")) {
            break;
        }
    }

    // 从 weak_passwords.h 中读取Telnet默认密码字典
    // TELNET_DEFAULT_CREDS 定义在 weak_passwords.h 中，存储在Flash

    for (int c = 0; TELNET_DEFAULT_CREDS[c] != NULL; c++) {
        // 解析用户名和密码
        char user_pass[24];
        strncpy(user_pass, TELNET_DEFAULT_CREDS[c], sizeof(user_pass) - 1);
        char *colon = strchr(user_pass, ':');
        if (!colon) continue;
        *colon = '\0';
        const char *username = user_pass;
        const char *password = colon + 1;

        // 如果已经收到login提示，发送用户名
        if (total > 0) {
            write(sock, username, strlen(username));
            write(sock, "\r\n", 2);
        }

        // 等待Password提示
        memset(resp, 0, sizeof(resp));
        total = 0;
        start = (uint32_t)(esp_timer_get_time() / 1000);
        bool got_password_prompt = false;
        while ((esp_timer_get_time() / 1000) - start < 2000) {
            char c = 0;
            if (read(sock, &c, 1) == 1) {
                if (total < (int)sizeof(resp) - 1) resp[total++] = c;
                resp[total] = '\0';
            }
            if (strstr(resp, "Password:") || strstr(resp, "password:")) {
                got_password_prompt = true;
                break;
            }
        }

        if (!got_password_prompt) continue;

        // 发送密码
        write(sock, password, strlen(password));
        write(sock, "\r\n", 2);

        // 检查是否登录成功（获取到shell提示符）
        memset(resp, 0, sizeof(resp));
        total = 0;
        start = (uint32_t)(esp_timer_get_time() / 1000);
        bool login_ok = false;
        while ((esp_timer_get_time() / 1000) - start < 2000) {
            char c = 0;
            if (read(sock, &c, 1) == 1) {
                if (total < (int)sizeof(resp) - 1) resp[total++] = c;
                resp[total] = '\0';
            }
            // shell提示符标志登录成功：$ # > % 
            if (strchr(resp, '$') || strchr(resp, '#') ||
                strstr(resp, "Last login")) {
                login_ok = true;
                break;
            }
        }

        if (login_ok) {
            host->telnet_weak = true;
            host->risk_level = 4;
            ESP_LOGW(TAG, "WEAK TELNET! %s -> %s/%s (risk=4)",
                     ip, username, password);
            close(sock);
            return;
        }

        // 重新连接尝试下一组密码
        close(sock);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) break;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
            close(sock);
            break;
        }
        total = 0;
    }

    close(sock);
}

/**
 * 检查FTP匿名登录
 *
 * 原理：
 * 1. 连接21端口，读取banner
 * 2. 发送 "USER anonymous"
 * 3. 如果返回230 → 直接登录成功（无密码要求）
 * 4. 如果返回331 → 发送 "PASS anonymous@" 
 * 5. 如果返回230 → 匿名登录成功
 */
static void check_ftp_anonymous(const char *ip, scanned_host_t *host) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(21);
    dest.sin_addr.s_addr = inet_addr(ip);

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        close(sock);
        return;
    }

    char buf[256] = {0};
    int total = 0;
    uint32_t start = (uint32_t)(esp_timer_get_time() / 1000);

    // 读取banner
    while ((esp_timer_get_time() / 1000) - start < 2000) {
        int n = read(sock, buf + total, sizeof(buf) - 1 - total);
        if (n > 0) {
            total += n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n")) break;  // 收到完整行
        } else {
            break;
        }
    }

    if (total == 0) {
        close(sock);
        return;
    }

    // 发送 USER anonymous
    write(sock, "USER anonymous\r\n", 16);

    memset(buf, 0, sizeof(buf));
    total = 0;
    start = (uint32_t)(esp_timer_get_time() / 1000);
    while ((esp_timer_get_time() / 1000) - start < 2000) {
        int n = read(sock, buf + total, sizeof(buf) - 1 - total);
        if (n > 0) {
            total += n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n")) break;
        } else {
            break;
        }
    }

    // 230 = 直接登录成功（服务器不要求密码）
    if (strstr(buf, "230 ")) {
        host->ftp_anonymous = true;
        host->risk_level = (host->risk_level < 4) ? 4 : host->risk_level;
        ESP_LOGW(TAG, "FTP ANONYMOUS! %s (risk=4)", ip);
        close(sock);
        return;
    }

    // 331 = 需要密码
    if (strstr(buf, "331 ")) {
        write(sock, "PASS anonymous@\r\n", 17);

        memset(buf, 0, sizeof(buf));
        total = 0;
        start = (uint32_t)(esp_timer_get_time() / 1000);
        while ((esp_timer_get_time() / 1000) - start < 2000) {
            int n = read(sock, buf + total, sizeof(buf) - 1 - total);
            if (n > 0) {
                total += n;
                buf[total] = '\0';
                if (strstr(buf, "\r\n")) break;
            } else {
                break;
            }
        }

        if (strstr(buf, "230 ")) {
            host->ftp_anonymous = true;
            host->risk_level = (host->risk_level < 4) ? 4 : host->risk_level;
            ESP_LOGW(TAG, "FTP ANONYMOUS! %s (risk=4)", ip);
        }
    }

    close(sock);
}

/**
 * 隐藏后台发现 - 对HTTP端口尝试常见管理路径
 * 返回：找到的后台页面路径字符串（需调用者free），未找到返回NULL
 */
static char* check_admin_pages(const char *ip, uint16_t port) {
    for (int i = 0; ADMIN_PATHS[i] != NULL; i++) {
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(ip);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
            close(sock);
            continue;
        }

        char req[512];
        int len = snprintf(req, sizeof(req),
            "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            ADMIN_PATHS[i], ip);
        write(sock, req, len);

        char resp[512] = {0};
        int total = 0;
        while (total < (int)sizeof(resp) - 1) {
            int n = read(sock, resp + total, sizeof(resp) - 1 - total);
            if (n <= 0) break;
            total += n;
        }
        close(sock);
        resp[total] = '\0';

        // 检查是否返回200（找到页面）且包含login/form等关键词
        if (strstr(resp, "200 OK") || strstr(resp, "200 ok")) {
            if (strstr(resp, "login") || strstr(resp, "Login") ||
                strstr(resp, "password") || strstr(resp, "Password") ||
                strstr(resp, "form") || strstr(resp, "admin")) {
                char *result = (char *)malloc(64);
                if (result) {
                    snprintf(result, 64, "ADMIN:%s", ADMIN_PATHS[i]);
                    ESP_LOGW(TAG, "[DEEP_SCAN] Found admin page: %s:%d%s",
                             ip, port, ADMIN_PATHS[i]);
                    return result;
                }
            }
        }

        vTaskDelay(pdMS_TO_TICKS(30));
    }
    return NULL;
}

/**
 * 端口扫描任务
 *
 * 扫描流程：
 * 1. 主机发现：扫描已知IP列表（来自AP板HOST消息），跳过全扫254个
 * 2. 端口扫描：对每个存活主机，扫描高危端口列表
 * 3. 深度扫描：仅在云端触发时执行（弱口令检测 + 隐藏后台发现）
 * 4. 设备识别：通过ARP表获取MAC，通过OUI识别厂商
 * 5. 风险计算：根据开放端口类型和数量计算风险等级
 * 6. 自动防御：风险>=4时通过UART通知AP板踢除设备
 * 7. 更新全局状态：更新风险等级和告警状态
 */
static void port_scan_task(void *pvParameters) {
    ESP_LOGI(TAG, "Port scan task started (interval=%ds, subnet=%s)",
             PORT_SCAN_INTERVAL_SEC, TARGET_SUBNET_PREFIX);

    while (1) {
        // 等待WiFi连接建立
        if (!g_sta_connected) {
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        g_port_scan_running = true;
        ESP_LOGI(TAG, "========== Network Scan Start ==========");

        // 本轮扫描结果缓存
        scanned_host_t scan_results[MAX_SCANNED_HOSTS];
        uint8_t alive_count = 0;
        uint16_t total_open = 0;

        // ====== 阶段1：主机发现（精准定位）=====
        // 不再全扫254个IP，而是从AP板HOST消息中获取已知设备的IP列表
        // 这使扫描时间从~4分钟降到~5秒（假设3台设备×2探测端口×100ms超时）

        char alive_ips[MAX_SCANNED_HOSTS][16];
        uint8_t target_ip_count = 0;
        char target_ips[MAX_SCANNED_HOSTS][16];

        // 从已知主机IP列表获取目标
        if (g_known_host_mutex) xSemaphoreTake(g_known_host_mutex, portMAX_DELAY);
        for (int i = 0; i < g_known_host_count && target_ip_count < MAX_SCANNED_HOSTS; i++) {
            // 跳过扫描板自身的IP
            if (strcmp(g_known_host_ips[i], g_sta_ip_str) != 0) {
                strncpy(target_ips[target_ip_count], g_known_host_ips[i], 15);
                target_ips[target_ip_count][15] = '\0';
                target_ip_count++;
            }
        }
        if (g_known_host_mutex) xSemaphoreGive(g_known_host_mutex);

        ESP_LOGI(TAG, "Phase 1: Target host discovery (%d known IPs)...", target_ip_count);

        // 只扫描AP板告知的已知IP
        for (int i = 0; i < target_ip_count && g_sta_connected; i++) {
            const char *ip = target_ips[i];

            // 如果正在遭受Deauth攻击，暂停扫描
            if (g_alert_active) {
                ESP_LOGW(TAG, "Scan paused due to active alert");
                break;
            }

            if (is_host_alive(ip)) {
                if (alive_count < MAX_SCANNED_HOSTS) {
                    strncpy(alive_ips[alive_count], ip, 15);
                    alive_ips[alive_count][15] = '\0';
                    alive_count++;
                }
                ESP_LOGI(TAG, "Host alive: %s (%d/%d)", ip, alive_count, target_ip_count);
            }

            // 每个IP探测间加入短暂延迟，避免网络拥塞
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        ESP_LOGI(TAG, "Phase 1 complete: %d hosts found", alive_count);

        // ====== 阶段2：端口扫描 ======
        // 对每个存活主机扫描高危端口
        ESP_LOGI(TAG, "Phase 2: Port scanning %d hosts...", alive_count);

        for (int h = 0; h < alive_count && h < MAX_SCANNED_HOSTS; h++) {
            memset(&scan_results[h], 0, sizeof(scanned_host_t));
            strncpy(scan_results[h].ip_str, alive_ips[h], sizeof(scan_results[h].ip_str) - 1);
            scan_results[h].is_alive = true;

            // 从HOST消息匹配MAC、厂商和hostname
            bool got_vendor_from_hosts = false;
            if (g_known_host_mutex) xSemaphoreTake(g_known_host_mutex, pdMS_TO_TICKS(50));
            for (int k = 0; k < g_known_host_count; k++) {
                if (strcmp(g_known_host_ips[k], alive_ips[h]) == 0) {
                    strncpy(scan_results[h].mac_str, g_known_host_macs[k], 17);
                    // 复制hostname
                    if (g_known_host_names[k][0] != '\0') {
                        strncpy(scan_results[h].hostname, g_known_host_names[k], 31);
                    }
                    // 解析MAC字符串到6字节数组用于OUI查找
                    uint8_t mac_bytes[6] = {0};
                    if (sscanf(g_known_host_macs[k], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
                        strncpy(scan_results[h].vendor, lookup_vendor(mac_bytes),
                                sizeof(scan_results[h].vendor) - 1);
                        got_vendor_from_hosts = true;
                    }
                    break;
                }
            }
            if (g_known_host_mutex) xSemaphoreGive(g_known_host_mutex);
            scan_results[h].last_scanned = (uint32_t)(esp_timer_get_time() / 1000000);

            // 通过ARP表获取MAC地址（补充known_hosts未提供的信息）
            if (get_mac_by_ip(alive_ips[h], scan_results[h].mac)) {
                hex_to_str(scan_results[h].mac, scan_results[h].mac_str, 18);
                // 仅当known_hosts未提供vendor时，才用ARP+OUI补充
                if (!got_vendor_from_hosts) {
                    strncpy(scan_results[h].vendor, lookup_vendor(scan_results[h].mac),
                            sizeof(scan_results[h].vendor) - 1);
                }
                ESP_LOGI(TAG, "Host %s -> MAC:%s Vendor:%s",
                         alive_ips[h], scan_results[h].mac_str, scan_results[h].vendor);
            } else if (!got_vendor_from_hosts) {
                strncpy(scan_results[h].vendor, "Unknown", sizeof(scan_results[h].vendor) - 1);
            }

            for (int p = 0; p < HIGH_RISK_PORT_COUNT; p++) {
                if (g_alert_active) break;  // 攻击中停止扫描

                if (scan_port(alive_ips[h], HIGH_RISK_PORTS[p])) {
                    ESP_LOGW(TAG, "OPEN PORT: %s:%d (%s)",
                             alive_ips[h], HIGH_RISK_PORTS[p],
                             HIGH_RISK_PORTS[p] == 23 ? "Telnet!" :
                             HIGH_RISK_PORTS[p] == 445 ? "SMB!" :
                             HIGH_RISK_PORTS[p] == 5555 ? "ADB!" :
                             HIGH_RISK_PORTS[p] == 3389 ? "RDP!" : "other");

                    if (scan_results[h].open_port_count < 16) {
                        scan_results[h].open_ports[scan_results[h].open_port_count++] = HIGH_RISK_PORTS[p];
                        total_open++;
                    }
                }
            }

            // ====== 弱口令检测 + 隐藏后台发现（仅在深度扫描时执行）=====
            if (g_deep_scan_pending) {
                ESP_LOGI(TAG, "[DEEP_SCAN] Weak password & admin discovery for %s...", alive_ips[h]);

                for (int p = 0; p < scan_results[h].open_port_count; p++) {
                    uint16_t port = scan_results[h].open_ports[p];
                    if (port == 80 || port == 8080) {
                        // HTTP管理页面弱口令检测
                        check_http_basic_auth(alive_ips[h], port, &scan_results[h]);
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                    if (port == 23) {
                        check_telnet_password(alive_ips[h], &scan_results[h]);
                        vTaskDelay(pdMS_TO_TICKS(200));
                    }
                    if (port == 21) {
                        check_ftp_anonymous(alive_ips[h], &scan_results[h]);
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                }

                // 隐藏后台发现 - 对HTTP端口尝试常见路径
                for (int p = 0; p < scan_results[h].open_port_count; p++) {
                    if (scan_results[h].open_ports[p] == 80 ||
                        scan_results[h].open_ports[p] == 8080) {
                        char *found_page = check_admin_pages(alive_ips[h],
                            scan_results[h].open_ports[p]);
                        if (found_page) {
                            if (!scan_results[h].weak_http_auth) {
                                scan_results[h].weak_http_auth = true;
                                strncpy(scan_results[h].weak_http_cred, found_page,
                                        sizeof(scan_results[h].weak_http_cred) - 1);
                            }
                            free(found_page);
                        }
                        vTaskDelay(pdMS_TO_TICKS(50));
                    }
                }
            }

            // 更新风险等级（弱口令检测可能已将其设为4）
            if (scan_results[h].risk_level == 0) {
                scan_results[h].risk_level = calculate_host_risk(&scan_results[h]);
            }

            if (scan_results[h].open_port_count > 0) {
                ESP_LOGW(TAG, "Host %s: %d open ports, risk=%d",
                         alive_ips[h], scan_results[h].open_port_count, scan_results[h].risk_level);
            }

            // 自动踢除：风险等级>=4且已知MAC的设备
            // 触发条件：弱口令被发现 或 Deauth攻击源
            if (scan_results[h].risk_level >= 4 &&
                scan_results[h].mac_str[0] != '\0') {
                ESP_LOGW(TAG, "Auto-kicking high risk host %s (%s)",
                         alive_ips[h], scan_results[h].mac_str);
                kick_device(scan_results[h].mac_str);
            }

            // 主机间扫描间隔
            vTaskDelay(pdMS_TO_TICKS(50));
        }

        // ====== 阶段3：更新全局状态 ======
        if (g_scan_mutex) xSemaphoreTake(g_scan_mutex, portMAX_DELAY);

        // 将本轮扫描结果写入全局数组
        g_scanned_host_count = alive_count < MAX_SCANNED_HOSTS ? alive_count : MAX_SCANNED_HOSTS;
        memcpy(g_scanned_hosts, scan_results, sizeof(scanned_host_t) * g_scanned_host_count);
        g_total_open_ports = total_open;

        // 统计弱口令主机数
        g_weak_count = 0;
        for (int i = 0; i < g_scanned_host_count; i++) {
            if (scan_results[i].weak_http_auth ||
                scan_results[i].telnet_weak ||
                scan_results[i].ftp_anonymous) {
                g_weak_count++;
            }
        }

        // 如果是深度扫描，设置完成标志，让MQTT任务发送深度扫描报告
        if (g_deep_scan_pending) {
            g_deep_scan_pending = false;
            // MQTT发布任务会检测g_weak_count等字段，自动在下次发布中包含深度扫描信息
            ESP_LOGI(TAG, "[DEEP_SCAN] Deep scan completed, %d weak hosts found", g_weak_count);
        }

        if (g_scan_mutex) xSemaphoreGive(g_scan_mutex);

        // 计算综合风险等级：取所有主机中的最高风险，并叠加Deauth风险
        uint8_t max_port_risk = 0;
        for (int i = 0; i < alive_count; i++) {
            if (scan_results[i].risk_level > max_port_risk) {
                max_port_risk = scan_results[i].risk_level;
            }
        }

        // 综合风险 = max(端口扫描风险, Deauth风险)
        // Deauth告警超时清除由display_update_task统一管理
        if (!g_deauth_alert_trigger) {
            g_current_risk_level = max_port_risk;
            g_alert_active = (max_port_risk >= 3);
        }

        g_total_scan_cycles++;

        ESP_LOGI(TAG, "========== Scan Complete: %d hosts, %d open ports, risk=%d ==========",
                 alive_count, total_open, (int)g_current_risk_level);

        g_port_scan_running = false;

        // 等待下一个扫描周期（可被云端命令提前唤醒）
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(PORT_SCAN_INTERVAL_SEC * 1000));
    }
}

// ==================== WiFi初始化 ====================

/**
 * WiFi事件处理器
 * 处理STA模式下的连接、断开、获取IP等事件
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            // WiFi STA已启动，开始连接AP板
            ESP_LOGI(TAG, "WiFi STA started, connecting to %s...", SCANNER_AP_SSID);
            esp_wifi_connect();
            break;

        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "WiFi connected to AP: %s", SCANNER_AP_SSID);
            break;

        case WIFI_EVENT_STA_DISCONNECTED: {
            // 连接断开，清除状态
            wifi_event_sta_disconnected_t *disconn_event = 
                (wifi_event_sta_disconnected_t *)event_data;
            g_sta_connected = false;
            g_sta_ip_str[0] = '\0';
            s_retry_count++;

            // reason码参考：201=无AP, 202=认证失败, 204=握手超时, 15=断开
            ESP_LOGW(TAG, "WiFi disconnected! reason=%d, retry=%d, ssid=%s",
                     disconn_event->reason, s_retry_count, SCANNER_AP_SSID);

            // 关闭混杂模式（未连接时捕获的帧无意义）
            esp_wifi_set_promiscuous(false);

            // 【重要】事件回调中不能调用vTaskDelay！
            // 直接重连，由WiFi驱动内部控制重连间隔
            esp_wifi_connect();
            break;
        }

        default:
            break;
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            // 成功获取IP地址，可以开始端口扫描和帧嗅探
            ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
            snprintf(g_sta_ip_str, sizeof(g_sta_ip_str), IPSTR, IP2STR(&event->ip_info.ip));
            ESP_LOGI(TAG, "Got IP: %s (gateway: " IPSTR ")",
                     g_sta_ip_str, IP2STR(&event->ip_info.gw));

            g_sta_connected = true;

            // 配置公共DNS（AP板DHCP不转发DNS，手动指定确保域名解析）
            esp_netif_dns_info_t dns = { .ip = { .u_addr = { .ip4 = { .addr = ESP_IP4TOADDR(223, 5, 5, 5) } } } };
            esp_netif_set_dns_info(g_sta_netif, ESP_NETIF_DNS_MAIN, &dns);

            // 开启混杂模式，接收周围WiFi设备的管理帧
            // 设置过滤器：只捕获管理帧（Beacon/Probe/Deauth等），忽略数据帧和控制帧
            wifi_promiscuous_filter_t filter = {
                .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
            };
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_callback));
            ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
            ESP_LOGI(TAG, "Promiscuous mode enabled (MGMT frames only)");

            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
}

/**
 * 初始化WiFi为STA模式
 * 扫描板以STA模式连接AP板的WiFi热点，进入AP板的内网进行安全监测
 */
static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();

    // 创建STA网络接口
    g_sta_netif = esp_netif_create_default_wifi_sta();

    // WiFi驱动初始化
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    // 注册WiFi和IP事件处理器
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    // 配置STA连接参数（连接AP板的WifiWarden热点）
    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, SCANNER_AP_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, SCANNER_AP_PASSWORD, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "WiFi STA mode initialized, target AP: %s", SCANNER_AP_SSID);
}

// ==================== MQTT + cJSON 云端通信 ====================

// MQTT配置
#define MQTT_BROKER_URI      CONFIG_MQTT_BROKER_URI
#define MQTT_USER            CONFIG_MQTT_USERNAME
#define MQTT_PASS            CONFIG_MQTT_PASSWORD
#define MQTT_PUB_INTERVAL_S  CONFIG_MQTT_PUBLISH_INTERVAL

// MQTT主题
#define MQTT_TOPIC_SENSE    "wifiwarden/sense/"  // + MAC, 上报感知数据
#define MQTT_TOPIC_COMMAND  "wifiwarden/command/" // + MAC, 接收云端命令
#define MQTT_TOPIC_STATUS   "wifiwarden/status"   // 设备状态

static esp_mqtt_client_handle_t g_mqtt_client = NULL;
static volatile bool g_mqtt_connected = false;
static char g_mqtt_topic_sense[64];   // 完整上报主题
static char g_mqtt_topic_cmd[64];     // 完整命令主题

/**
 * 构建JSON格式的感知数据包
 * 包含：设备信息、端口扫描结果、Deauth检测、弱口令、风险等级
 */
static char* build_sense_json(void) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    // 设备基本信息
    cJSON_AddStringToObject(root, "mac", s_device_mac_str);
    cJSON_AddStringToObject(root, "ip", g_sta_ip_str);
    cJSON_AddNumberToObject(root, "risk_level", g_current_risk_level);
    cJSON_AddBoolToObject(root, "alert", g_alert_active);
    cJSON_AddBoolToObject(root, "honeypot", g_honeypot_enabled);
    cJSON_AddBoolToObject(root, "scan_running", g_port_scan_running);
    cJSON_AddNumberToObject(root, "hosts_scanned", g_scanned_host_count);
    cJSON_AddNumberToObject(root, "total_open_ports", g_total_open_ports);

    // UART接收的AP板信息
    if (g_ap_count_mutex) xSemaphoreTake(g_ap_count_mutex, portMAX_DELAY);
    uint8_t dev_count = g_ap_sta_count;
    if (g_ap_count_mutex) xSemaphoreGive(g_ap_count_mutex);
    uint8_t ext_count = (dev_count > 0 && g_sta_connected) ? dev_count - 1 : 0;
    cJSON_AddNumberToObject(root, "ap_devices", ext_count);

    if (g_wifi_mutex) xSemaphoreTake(g_wifi_mutex, portMAX_DELAY);
    char upstream_ssid[33];
    strncpy(upstream_ssid, g_ap_upstream_ssid, sizeof(upstream_ssid) - 1);
    upstream_ssid[sizeof(upstream_ssid) - 1] = '\0';
    int8_t upstream_rssi = g_ap_upstream_rssi;
    if (g_wifi_mutex) xSemaphoreGive(g_wifi_mutex);

    cJSON_AddStringToObject(root, "upstream_ssid", upstream_ssid);
    cJSON_AddNumberToObject(root, "upstream_rssi", upstream_rssi);

    // 端口扫描结果（过滤ESP32开发板）
    cJSON *hosts = cJSON_CreateArray();
    if (g_scan_mutex) xSemaphoreTake(g_scan_mutex, portMAX_DELAY);
    for (int i = 0; i < g_scanned_host_count; i++) {
        if (is_esp32_mac(g_scanned_hosts[i].mac)) continue;
        cJSON *h = cJSON_CreateObject();
        cJSON_AddStringToObject(h, "ip", g_scanned_hosts[i].ip_str);
        cJSON_AddStringToObject(h, "mac", g_scanned_hosts[i].mac_str);
        cJSON_AddStringToObject(h, "vendor", g_scanned_hosts[i].vendor);
        if (g_scanned_hosts[i].hostname[0] != '\0') {
            cJSON_AddStringToObject(h, "hostname", g_scanned_hosts[i].hostname);
        }
        cJSON_AddNumberToObject(h, "risk_level", g_scanned_hosts[i].risk_level);

        // 开放端口列表
        cJSON *ports = cJSON_CreateArray();
        for (int p = 0; p < g_scanned_hosts[i].open_port_count; p++) {
            cJSON_AddItemToArray(ports, cJSON_CreateNumber(g_scanned_hosts[i].open_ports[p]));
        }
        cJSON_AddItemToObject(h, "open_ports", ports);

        // 弱口令
        if (g_scanned_hosts[i].weak_http_auth) {
            cJSON_AddStringToObject(h, "weak_http", g_scanned_hosts[i].weak_http_cred);
        }
        if (g_scanned_hosts[i].telnet_weak) cJSON_AddBoolToObject(h, "weak_telnet", true);
        if (g_scanned_hosts[i].ftp_anonymous) cJSON_AddBoolToObject(h, "weak_ftp", true);

        cJSON_AddItemToArray(hosts, h);
    }
    if (g_scan_mutex) xSemaphoreGive(g_scan_mutex);
    cJSON_AddItemToObject(root, "hosts", hosts);

    // 已知设备列表（含MAC和厂商，来自AP板HOST消息）
    cJSON *known = cJSON_CreateArray();
    if (g_known_host_mutex) xSemaphoreTake(g_known_host_mutex, pdMS_TO_TICKS(50));
    for (int k = 0; k < g_known_host_count; k++) {
        uint8_t mac_bytes[6] = {0};
        int parsed = sscanf(g_known_host_macs[k], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                            &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                            &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
        // 过滤ESP32开发板，不上报
        if (parsed == 6 && is_esp32_mac(mac_bytes)) {
            continue;
        }
        cJSON *kh = cJSON_CreateObject();
        cJSON_AddStringToObject(kh, "ip", g_known_host_ips[k]);
        cJSON_AddStringToObject(kh, "mac", g_known_host_macs[k]);
        const char *ven = (parsed == 6) ? lookup_vendor(mac_bytes) : NULL;
        cJSON_AddStringToObject(kh, "vendor", ven ? ven : "Unknown");
        // 添加DHCP hostname
        if (g_known_host_names[k][0] != '\0') {
            cJSON_AddStringToObject(kh, "hostname", g_known_host_names[k]);
        }
        cJSON_AddItemToArray(known, kh);
    }
    if (g_known_host_mutex) xSemaphoreGive(g_known_host_mutex);
    cJSON_AddItemToObject(root, "known_hosts", known);

    // Deauth统计（每次上报时根据当前时间重新计算窗口内帧数）
    {
        uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
        uint32_t window_start = now_ms - (DEAUTH_WINDOW_SEC * 1000);
        uint8_t wcount = 0;
        uint8_t total = (g_deauth_event_idx < DEAUTH_THRESHOLD) ? g_deauth_event_idx : DEAUTH_THRESHOLD;
        for (uint8_t i = 0; i < total; i++) {
            if (g_deauth_events[i % DEAUTH_THRESHOLD].timestamp_ms >= window_start) wcount++;
        }
        g_deauth_count_in_window = wcount;
    }
    cJSON *deauth = cJSON_CreateObject();
    cJSON_AddNumberToObject(deauth, "total", g_total_deauth_frames);
    cJSON_AddNumberToObject(deauth, "in_window", g_deauth_count_in_window);
    cJSON_AddItemToObject(root, "deauth", deauth);

    // 混杂模式统计
    cJSON_AddNumberToObject(root, "probe_frames", g_total_probe_frames);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

/**
 * MQTT事件回调 - 处理连接/断开/订阅/消息事件
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                                int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected to broker: %s", MQTT_BROKER_URI);
        g_mqtt_connected = true;

        // 订阅云端命令主题
        esp_mqtt_client_subscribe(g_mqtt_client, g_mqtt_topic_cmd, 1);
        ESP_LOGI(TAG, "MQTT subscribed: %s", g_mqtt_topic_cmd);

        // 订阅广播命令主题（云端可同时控制所有设备）
        esp_mqtt_client_subscribe(g_mqtt_client, "wifiwarden/command/broadcast", 1);
        ESP_LOGI(TAG, "MQTT subscribed: wifiwarden/command/broadcast");

        // 发布初次状态
        {
            char *json = build_sense_json();
            if (json) {
                esp_mqtt_client_publish(g_mqtt_client, g_mqtt_topic_sense,
                                        json, 0, 1, 0);
                free(json);
            }
        }
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        g_mqtt_connected = false;
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT subscribe success");
        break;

    case MQTT_EVENT_DATA: {
        // 收到云端下发的命令
        char topic[128] = {0};
        char msg[512] = {0};
        ESP_LOGI(TAG, "MQTT data received: topic_len=%d data_len=%d", event->topic_len, event->data_len);
        if (event->topic_len < 128 && event->data_len < 512) {
            strncpy(topic, event->topic, event->topic_len);
            strncpy(msg, event->data, event->data_len);
            msg[event->data_len] = '\0';
            ESP_LOGI(TAG, "MQTT command received: %s -> %s", topic, msg);

            // 解析JSON命令（兼容两种格式：
            // 直接格式 {"action":"...", "params":{...}}
            // 嵌套格式 {"command":{"action":"..."}, "timestamp":"..."}
            cJSON *root = cJSON_Parse(msg);
            if (root) {
                cJSON *cmd = cJSON_GetObjectItem(root, "command");
                if (!cmd) cmd = root;  // 直接格式，顶层就是命令

                cJSON *action = cJSON_GetObjectItem(cmd, "action");
                if (action && cJSON_IsString(action)) {
                    ESP_LOGW(TAG, "MQTT action: %s", action->valuestring);
                    if (strcmp(action->valuestring, "alert") == 0) {
                        // 云端要求告警
                        g_alert_active = true;
                        g_current_risk_level = 4;
                        beeper_alert_pattern(4);
                    } else if (strcmp(action->valuestring, "scan") == 0) {
                        // 云端触发即时扫描
                        ESP_LOGI(TAG, "Cloud triggered scan request");
                        if (g_port_scan_task_handle) {
                            xTaskNotifyGive(g_port_scan_task_handle);
                        }
                    } else if (strcmp(action->valuestring, "deep_scan") == 0) {
                        // 云端触发深度扫描（含弱口令+后台发现）
                        g_deep_scan_pending = true;
                        if (g_port_scan_task_handle) {
                            xTaskNotifyGive(g_port_scan_task_handle);
                        }
                        ESP_LOGE(TAG, "[DEEP_SCAN] Deep scan triggered by cloud!");
                    } else if (strcmp(action->valuestring, "blacklist") == 0) {
                        // 云端要求拉黑并踢除设备
                        cJSON *params = cJSON_GetObjectItem(cmd, "params");
                        if (params) {
                            cJSON *target_mac = cJSON_GetObjectItem(params, "target_mac");
                            if (target_mac && cJSON_IsString(target_mac)) {
                                ESP_LOGW(TAG, "[BLACKLIST] Kicking device: %s",
                                         target_mac->valuestring);
                                kick_device(target_mac->valuestring);
                            }
                        }
                    } else if (strcmp(action->valuestring, "unblacklist") == 0) {
                        // 云端要求从黑名单移除设备，允许重新连接
                        cJSON *params = cJSON_GetObjectItem(cmd, "params");
                        if (params) {
                            cJSON *target_mac = cJSON_GetObjectItem(params, "target_mac");
                            if (target_mac && cJSON_IsString(target_mac)) {
                                ESP_LOGI(TAG, "[UNBLACKLIST] Removing device: %s",
                                         target_mac->valuestring);
                                // 通过UART通知AP板从黑名单移除
                                char buffer[32];
                                int len = snprintf(buffer, sizeof(buffer), "UNBLK:%s\n", target_mac->valuestring);
                                uart_write_bytes(UART_NUM, buffer, len);
                            }
                        }
                    } else if (strcmp(action->valuestring, "honeypot_on") == 0) {
                        // 云端开启蜜罐
                        ESP_LOGE(TAG, "!!! HONEYPOT_ON COMMAND RECEIVED !!!");
                        g_honeypot_enabled = true;
                        cJSON *params = cJSON_GetObjectItem(cmd, "params");
                        if (params) {
                            cJSON *ssid_item = cJSON_GetObjectItem(params, "ssid");
                            if (ssid_item && cJSON_IsString(ssid_item)) {
                                strncpy(g_honeypot_ssid, ssid_item->valuestring,
                                        sizeof(g_honeypot_ssid) - 1);
                            }
                        }
                        g_mqtt_force_publish = true;  // 立即上报状态
                        ESP_LOGW(TAG, "Honeypot ENABLED by cloud (SSID=%s)", g_honeypot_ssid);
                    } else if (strcmp(action->valuestring, "honeypot_off") == 0) {
                        // 云端关闭蜜罐
                        g_honeypot_enabled = false;
                        g_mqtt_force_publish = true;  // 立即上报状态
                        ESP_LOGW(TAG, "Honeypot DISABLED by cloud");
                    }
                }
                cJSON_Delete(root);
            } else {
                ESP_LOGE(TAG, "MQTT JSON parse FAILED for: %s", msg);
            }
        } else {
            ESP_LOGE(TAG, "MQTT msg too large: topic_len=%d data_len=%d", event->topic_len, event->data_len);
        }
        break;
    }

    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error: error_handle=%p, msg_id=%d", event->error_handle, event->msg_id);
        if (event->error_handle) {
            ESP_LOGE(TAG, "MQTT error: transport_type=%d, esp_tls_last_esp_err=%d, esp_tls_stack_err=%d",
                     event->error_handle->error_type,
                     event->error_handle->esp_tls_last_esp_err,
                     event->error_handle->esp_tls_stack_err);
        }
        break;

    default:
        break;
    }
}

/**
 * MQTT发布任务 - 定时上报感知数据到云端
 */
static void mqtt_publish_task(void *pvParameters) {
    // 先等待WiFi连接
    while (!g_sta_connected) {
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    // 构建主题名
    snprintf(g_mqtt_topic_sense, sizeof(g_mqtt_topic_sense),
             "%s%s", MQTT_TOPIC_SENSE, s_device_mac_str);
    snprintf(g_mqtt_topic_cmd, sizeof(g_mqtt_topic_cmd),
             "%s%s", MQTT_TOPIC_COMMAND, s_device_mac_str);
    ESP_LOGI(TAG, "MQTT sense topic: %s", g_mqtt_topic_sense);
    ESP_LOGI(TAG, "MQTT cmd topic: %s", g_mqtt_topic_cmd);

    // 配置MQTT客户端（含用户名密码认证）
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .credentials.username = MQTT_USER,
        .credentials.authentication.password = MQTT_PASS,
    };

    g_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!g_mqtt_client) {
        ESP_LOGE(TAG, "MQTT client init failed");
        return;
    }

    esp_mqtt_client_register_event(g_mqtt_client, ESP_EVENT_ANY_ID,
                                    mqtt_event_handler, NULL);
    esp_mqtt_client_start(g_mqtt_client);

    // 定时发布数据（支持设备变化时立即发布）
    while (1) {
        // 每秒检查一次force_publish标志，最多等MQTT_PUB_INTERVAL_S秒
        for (int i = 0; i < MQTT_PUB_INTERVAL_S; i++) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            if (g_mqtt_force_publish) {
                g_mqtt_force_publish = false;
                break;
            }
        }

        if (g_mqtt_connected) {
            char *json = build_sense_json();
            if (json) {
                esp_mqtt_client_publish(g_mqtt_client, g_mqtt_topic_sense,
                                        json, 0, 1, 0);
                ESP_LOGI(TAG, "MQTT published: %zu bytes", strlen(json));
                free(json);
            }
        }
    }
}

// ==================== 屏幕显示 ====================
static bool s_display_ready = false;

// 根据RSSI获取信号强度颜色
static uint16_t get_rssi_color(int rssi) {
    if (rssi == 0) return ST7789_RED;
    if (rssi > -50) return ST7789_GREEN;
    if (rssi > -65) return ST7789_YELLOW;
    if (rssi > -80) return ST7789_ORANGE;
    return ST7789_LIGHT_RED;
}

static void display_init(void) {
    esp_err_t ret = st7789_init(
        SPI2_HOST,
        TFT_MOSI_GPIO, TFT_SCK_GPIO, TFT_CS_GPIO,
        TFT_DC_GPIO, TFT_RST_GPIO, TFT_BLK_GPIO
    );

    if (ret == ESP_OK) {
        st7789_clear(ST7789_BLACK);
        st7789_backlight_set(100);
        s_display_ready = true;
        ESP_LOGI(TAG, "ST7789 display initialized");
    } else {
        ESP_LOGE(TAG, "ST7789 display init failed");
    }
}

static void display_draw_title(void) {
    if (!s_display_ready) return;
    st7789_fill_rect(0, 0, 240, 35, ST7789_BLUE);
    st7789_draw_string_big(65, 8, "WiFiWarden", ST7789_WHITE, ST7789_BLUE);
}

static void display_draw_status(void) {
    if (!s_display_ready) return;

    char buf[32];
    uint16_t y = 45;

    st7789_fill_rect(0, 40, 240, 230, ST7789_BLACK);

    // ---- AP连接状态 ----
    // 显示扫描板是否成功连接到AP板的WifiWarden热点
    uint16_t ap_color = g_sta_connected ? ST7789_GREEN : ST7789_RED;
    st7789_draw_string_big(10, y, "AP:", ST7789_BLUE, ST7789_BLACK);
    st7789_draw_string_big(45, y, "WifiWarden", ST7789_WHITE, ST7789_BLACK);
    st7789_draw_string_big(180, y, g_sta_connected ? "[OK]" : "[OFF]", ap_color, ST7789_BLACK);
    y += 25;

    // ---- 风险等级 ----
    // 综合Deauth检测和端口扫描结果计算得出
    uint8_t risk = g_current_risk_level;
    uint16_t risk_color;
    if (risk >= 4) risk_color = ST7789_RED;
    else if (risk >= 3) risk_color = ST7789_ORANGE;
    else if (risk >= 1) risk_color = ST7789_YELLOW;
    else risk_color = ST7789_GREEN;
    st7789_draw_string_big(10, y, "Risk:", ST7789_YELLOW, ST7789_BLACK);
    st7789_draw_number_big(115, y - 3, risk, risk_color, ST7789_BLACK);
    y += 25;

    // ---- 外部设备数 ----
    // 显示连接到AP板WiFi的外部设备数（UART获取的总数减去扫描板自身）
    uint8_t display_count = 0;
    if (g_ap_count_mutex) xSemaphoreTake(g_ap_count_mutex, portMAX_DELAY);
    uint8_t raw_count = g_ap_sta_count;
    if (g_ap_count_mutex) xSemaphoreGive(g_ap_count_mutex);
    // 减去扫描板自身（扫描板也连接在AP板的WiFi上）
    display_count = (raw_count > 0) ? raw_count - 1 : 0;
    st7789_draw_string_big(10, y, "Devices:", ST7789_CYAN, ST7789_BLACK);
    st7789_draw_number_big(125, y - 3, display_count, ST7789_WHITE, ST7789_BLACK);
    y += 25;

    // ---- 端口扫描结果 ----
    // 显示扫描发现的主机数和开放端口数
    uint8_t hosts = 0;
    uint16_t ports = 0;
    uint8_t weak_count = 0;
    if (g_scan_mutex) xSemaphoreTake(g_scan_mutex, portMAX_DELAY);
    hosts = g_scanned_host_count;
    ports = g_total_open_ports;
    weak_count = g_weak_count;
    if (g_scan_mutex) xSemaphoreGive(g_scan_mutex);

    // 扫描状态显示：
    // - scanning(白色)：正在扫描网段
    // - H:x P:y(绿色)：扫描完成有结果（含W:n表示弱口令主机数）
    // - clean(绿色)：扫描完成，网络干净无威胁
    if (g_port_scan_running) {
        st7789_draw_string_big(10, y, "Scan:scanning", ST7789_WHITE, ST7789_BLACK);
    } else if (!g_sta_connected) {
        st7789_draw_string_big(10, y, "Scan:waiting", ST7789_YELLOW, ST7789_BLACK);
    } else if (hosts > 0) {
        if (weak_count > 0) {
            snprintf(buf, sizeof(buf), "H:%d P:%d W:%d", hosts, ports, weak_count);
            st7789_draw_string_big(10, y, "Scan:", ST7789_LIGHT_BLUE, ST7789_BLACK);
            st7789_draw_string_big(80, y, buf, ST7789_RED, ST7789_BLACK);
        } else {
            snprintf(buf, sizeof(buf), "H:%d P:%d", hosts, ports);
            st7789_draw_string_big(10, y, "Scan:", ST7789_LIGHT_BLUE, ST7789_BLACK);
            st7789_draw_string_big(80, y, buf, ST7789_GREEN, ST7789_BLACK);
        }
    } else if (g_total_scan_cycles > 0) {
        // 扫描完成但没发现其他主机 = 网络干净，这是安全的好状态
        st7789_draw_string_big(10, y, "Scan:clean", ST7789_GREEN, ST7789_BLACK);
    } else {
        st7789_draw_string_big(10, y, "Scan:waiting", ST7789_YELLOW, ST7789_BLACK);
    }
    y += 25;

    // ---- 上游WiFi ----
    // AP板连接的上游WiFi信息（来自UART）
    st7789_draw_string_big(10, y, "WiFi:", ST7789_BLUE, ST7789_BLACK);
    if (g_wifi_mutex) xSemaphoreTake(g_wifi_mutex, portMAX_DELAY);
    bool upstream_ok = g_ap_upstream_connected;
    char upstream_ssid[33];
    strncpy(upstream_ssid, g_ap_upstream_ssid, sizeof(upstream_ssid) - 1);
    upstream_ssid[sizeof(upstream_ssid) - 1] = '\0';
    int8_t upstream_rssi = g_ap_upstream_rssi;
    if (g_wifi_mutex) xSemaphoreGive(g_wifi_mutex);

    if (upstream_ok && upstream_ssid[0] != '\0') {
        st7789_draw_string_big(80, y, upstream_ssid, ST7789_WHITE, ST7789_BLACK);
    } else {
        st7789_draw_string_big(80, y, "---", ST7789_GRAY, ST7789_BLACK);
    }
    y += 25;

    // ---- 上游WiFi RSSI ----
    st7789_draw_string_big(10, y, "RSSI:", ST7789_LIGHT_BLUE, ST7789_BLACK);
    uint16_t rssi_color = get_rssi_color(upstream_rssi);
    if (upstream_ok) {
        snprintf(buf, sizeof(buf), "%d dBm", upstream_rssi);
    } else {
        snprintf(buf, sizeof(buf), "-- dBm");
    }
    st7789_draw_string_big(85, y, buf, rssi_color, ST7789_BLACK);
    y += 25;

    // ---- Deauth统计 ----
    st7789_draw_string_big(10, y, "Deauth:", ST7789_MAGENTA, ST7789_BLACK);
    // 窗口超时则清零，避免显示残留旧值
    uint32_t now_d = (uint32_t)(esp_timer_get_time() / 1000);
    uint8_t d_count = g_deauth_count_in_window;
    if (now_d - g_deauth_last_detected_ms > DEAUTH_WINDOW_SEC * 1000) {
        d_count = 0;
    }
    uint8_t d_threshold = DEAUTH_THRESHOLD;
    snprintf(buf, sizeof(buf), "%u/%u", d_count, d_threshold);
    uint16_t deauth_color;
    if (d_count >= d_threshold) {
        deauth_color = ST7789_RED;                          // 超过阈值→红色
    } else if (d_count >= (2 * d_threshold + 2) / 3) {      // >= ceil(2/3阈值)
        deauth_color = ST7789_YELLOW;                       // 接近阈值→黄色
    } else {
        deauth_color = ST7789_GREEN;                        // 安全范围→绿色
    }
    st7789_draw_string_big(100, y, buf, deauth_color, ST7789_BLACK);
    y += 25;

    // ---- 弱口令检测结果 ----
    {
        bool weak_http = false, weak_telnet = false, weak_ftp = false;
        if (g_scan_mutex) xSemaphoreTake(g_scan_mutex, portMAX_DELAY);
        for (int i = 0; i < g_scanned_host_count; i++) {
            if (g_scanned_hosts[i].weak_http_auth) weak_http = true;
            if (g_scanned_hosts[i].telnet_weak) weak_telnet = true;
            if (g_scanned_hosts[i].ftp_anonymous) weak_ftp = true;
        }
        if (g_scan_mutex) xSemaphoreGive(g_scan_mutex);

        st7789_draw_string_big(10, y, "Weak:", ST7789_RED, ST7789_BLACK);
        if (weak_http || weak_telnet || weak_ftp) {
            buf[0] = '\0';
            if (weak_http) strcat(buf, "HTTP ");
            if (weak_telnet) strcat(buf, "Tel ");
            if (weak_ftp) strcat(buf, "FTP ");
            st7789_draw_string_big(80, y, buf, ST7789_RED, ST7789_BLACK);
        } else {
            st7789_draw_string_big(80, y, "none", ST7789_GRAY, ST7789_BLACK);
        }
    }
    y += 25;

    // ---- MAC地址 ----
    st7789_draw_string_big(10, y, "MAC:", ST7789_MAGENTA, ST7789_BLACK);
    st7789_draw_string(70, y, s_device_mac_str, ST7789_WHITE, ST7789_BLACK);
}

static void display_draw_status_bar(void) {
    if (!s_display_ready) return;

    uint16_t y = 235;
    st7789_fill_rect(0, y, 240, 50, ST7789_BLACK);
    st7789_draw_line(0, y, 240, y, ST7789_DARK_BLUE);

    // 蜜罐状态（云端同步）
    if (g_honeypot_enabled) {
        st7789_draw_string_big(10, y + 5, "Honeypot: ON", ST7789_GREEN, ST7789_BLACK);
    } else {
        st7789_draw_string_big(10, y + 5, "Honeypot: off", ST7789_GRAY, ST7789_BLACK);
    }

    // 告警状态显示
    if (g_alert_active) {
        // Deauth攻击告警
        if (g_deauth_alert_trigger) {
            st7789_draw_string_big(10, y + 26, "DEAUTH ATTACK!", ST7789_RED, ST7789_BLACK);
        } else {
            // 检查是否有弱口令告警
            bool weak_found = false;
            if (g_scan_mutex) xSemaphoreTake(g_scan_mutex, portMAX_DELAY);
            for (int i = 0; i < g_scanned_host_count && !weak_found; i++) {
                if (g_scanned_hosts[i].weak_http_auth ||
                    g_scanned_hosts[i].telnet_weak ||
                    g_scanned_hosts[i].ftp_anonymous) {
                    weak_found = true;
                }
            }
            if (g_scan_mutex) xSemaphoreGive(g_scan_mutex);

            if (weak_found) {
                st7789_draw_string_big(10, y + 26, "WEAK PASSWORD!", ST7789_RED, ST7789_BLACK);
            } else if (g_current_risk_level >= 3) {
                st7789_draw_string_big(10, y + 26, "HIGH RISK PORT!", ST7789_ORANGE, ST7789_BLACK);
            }
        }
    }
}

static void display_update(void) {
    if (!s_display_ready) return;
    display_draw_title();
    display_draw_status();
    display_draw_status_bar();
}

// 屏幕更新任务 (每2秒刷新一次)
static void display_update_task(void *pvParameters) {
    ESP_LOGI(TAG, "Display update task started");
    while (1) {
        // 自动清除过期的 Deauth 告警（30秒无新Deauth帧）
        if (g_deauth_alert_trigger) {
            uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
            if (now_ms - g_deauth_last_detected_ms > DEAUTH_ALERT_TIMEOUT_MS) {
                g_deauth_alert_trigger = false;
                // 只清除Deauth告警标志，不重置risk_level（由port_scan_task统一管理）
                ESP_LOGI(TAG, "Deauth alert auto-cleared (display task, 30s timeout)");
            }
        }
        display_update();
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

// ==================== 主程序 ====================
void app_main(void) {
    ESP_LOGI(TAG, "WiFiWarden ESP32-S3 Scanner Starting...");
    ESP_LOGI(TAG, "Target AP: %s (scan only known IPs from AP board via HOST messages)", SCANNER_AP_SSID);

    // 初始化硬件外设
    led_init();
    beeper_init();
    led_blink(2, 200);  // 开机指示：闪2次
    beeper_beep(100);   // 开机提示音

    // 初始化UART（与AP板通信）
    uart_init();

    // 创建互斥锁
    g_ap_count_mutex = xSemaphoreCreateMutex();
    g_wifi_mutex = xSemaphoreCreateMutex();
    g_devices_mutex = xSemaphoreCreateMutex();
    g_scan_mutex = xSemaphoreCreateMutex();
    g_deauth_mutex = xSemaphoreCreateMutex();
    g_known_host_mutex = xSemaphoreCreateMutex();

    // 初始化屏幕
    display_init();

    // 初始化NVS和网络协议栈
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // 获取本机MAC地址
    esp_read_mac(s_device_mac, ESP_MAC_WIFI_STA);
    hex_to_str(s_device_mac, s_device_mac_str, 18);
    ESP_LOGI(TAG, "Device MAC: %s", s_device_mac_str);

    // 初始化WiFi（STA模式，连接AP板的WifiWarden热点）
    wifi_init_sta();

    // 启动各任务
    // 显示任务：刷新屏幕内容，优先级3
    xTaskCreate(display_update_task, "display", 4096, NULL, 3, NULL);
    // UART接收任务：接收AP板数据，优先级4（较高，保证实时性）
    xTaskCreate(uart_receive_task, "uart_rx", 4096, NULL, 4, NULL);
    // 端口扫描任务：周期性扫描网段，优先级2（较低，避免影响实时性）
    // 栈空间8KB：socket操作需要较大缓冲区
    xTaskCreate(port_scan_task, "port_scan", 8192, NULL, 2, &g_port_scan_task_handle);

    // MQTT云端上报任务：定时将扫描结果发布到云端
    xTaskCreate(mqtt_publish_task, "mqtt_pub", 8192, NULL, 2, NULL);

    ESP_LOGI(TAG, "WiFiWarden Scanner initialized successfully");
    ESP_LOGI(TAG, "UART: RX=%d <- AP TX, TX=%d -> AP RX", UART_RX_PIN, UART_TX_PIN);
    ESP_LOGI(TAG, "Waiting for WiFi connection to %s...", SCANNER_AP_SSID);

    // 主循环：LED状态指示 + 告警蜂鸣
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(500));

        // Deauth告警蜂鸣（由混杂回调设置beep标志，主循环消费后清除）
        if (g_deauth_beep_trigger) {
            g_deauth_beep_trigger = false;
            beeper_alert_pattern(4);  // Deauth攻击=最高等级告警
        }

        // LED状态指示
        if (g_alert_active) {
            // 告警状态：快速闪烁
            led_blink(1, 100);
        } else if (g_sta_connected) {
            // 已连接：慢闪
            led_set(true);
            vTaskDelay(pdMS_TO_TICKS(500));
            led_set(false);
        } else {
            // 未连接：超慢闪
            led_set(true);
            vTaskDelay(pdMS_TO_TICKS(200));
            led_set(false);
            vTaskDelay(pdMS_TO_TICKS(800));
        }
    }
}
