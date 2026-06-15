/**
 * WiFiWarden AP - ESP32-S3 WiFi热点发射模块
 * 功能：发射WifiWarden热点 + 设备计数 + NAT上网
 * 通信：通过UART向扫描板发送设备数量
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#ifdef CONFIG_LWIP_IPV4_NAPT
#include "lwip/lwip_napt.h"
#endif
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_timer.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "esp_netif_net_stack.h"

static const char *TAG = "WiFiWarden_AP";

// ==================== AP热点配置 ====================
// AP密码从Kconfig读取，默认为CONFIG_AP_PASSWORD
#define AP_SSID         CONFIG_AP_SSID
#define AP_PASSWORD     CONFIG_AP_PASSWORD
#define AP_CHANNEL      6
#define MAX_AP_STATIONS 10
#define MAX_BLACKLIST   20   // MAC黑名单最大条目数

// ==================== UART配置 ====================
// ESP32-S3 使用 GPIO1(TX) 和 GPIO3(RX) 作为UART1
#define UART_NUM        UART_NUM_1
#define UART_TX_PIN     GPIO_NUM_1
#define UART_RX_PIN     GPIO_NUM_3
#define UART_BAUD_RATE  115200
#define UART_BUF_SIZE   256

// ==================== 前向声明 ====================
static void uart_init(void);
static void uart_send_device_count(uint8_t count);
static void uart_send_host_ips(void);
static uint8_t get_ap_sta_count(void);

// ==================== 全局变量 ====================
static uint8_t s_device_mac[6];
static char s_device_mac_str[18];

// AP连接设备数
static uint8_t g_ap_sta_count = 0;
static bool s_sta_connected = false;
static SemaphoreHandle_t g_count_mutex = NULL;

// MAC黑名单（被拉黑的设备每次连接都会被立即踢除）
static uint8_t g_blacklist[MAX_BLACKLIST][6];
static uint8_t g_blacklist_count = 0;
static SemaphoreHandle_t g_blacklist_mutex = NULL;

// 上游WiFi信息（需要互斥锁保护）
static char s_upstream_ssid[33] = {0};
static int8_t s_upstream_rssi = 0;
static SemaphoreHandle_t g_wifi_mutex = NULL;

// DHCP客户端信息缓存（MAC → IP + hostname映射）
#define MAX_HOSTNAME_LEN 32
typedef struct {
    uint8_t mac[6];
    char ip[16];              // DHCP分配的IP地址
    char hostname[MAX_HOSTNAME_LEN];
    bool valid;
} host_entry_t;
static host_entry_t g_host_table[MAX_AP_STATIONS];
static SemaphoreHandle_t g_host_mutex = NULL;

// ==================== LED定义 ====================
#define LED_RED_GPIO    GPIO_NUM_7
#define LED_GREEN_GPIO  GPIO_NUM_8

static void led_set_red(bool on) {
    gpio_set_level(LED_RED_GPIO, on ? 1 : 0);
}

static void led_set_green(bool on) {
    gpio_set_level(LED_GREEN_GPIO, on ? 1 : 0);
}

// ==================== 工具函数 ====================
static void hex_to_str(const uint8_t *hex, char *str, size_t len) {
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             hex[0], hex[1], hex[2], hex[3], hex[4], hex[5]);
}

// ==================== MAC黑名单功能 ====================
static bool is_mac_blacklisted(const uint8_t *mac) {
    for (int i = 0; i < g_blacklist_count; i++) {
        if (memcmp(g_blacklist[i], mac, 6) == 0) return true;
    }
    return false;
}

static void add_to_blacklist(const uint8_t *mac) {
    if (is_mac_blacklisted(mac)) return;  // 已存在
    if (g_blacklist_count >= MAX_BLACKLIST) {
        // 满了就移除最早的
        memmove(g_blacklist[0], g_blacklist[1], (MAX_BLACKLIST - 1) * 6);
        g_blacklist_count--;
    }
    memcpy(g_blacklist[g_blacklist_count], mac, 6);
    g_blacklist_count++;
    char mac_str[18];
    hex_to_str(mac, mac_str, sizeof(mac_str));
    ESP_LOGW(TAG, "MAC blacklisted: %s (total=%d)", mac_str, g_blacklist_count);
}

static void remove_from_blacklist(const uint8_t *mac) {
    for (int i = 0; i < g_blacklist_count; i++) {
        if (memcmp(g_blacklist[i], mac, 6) == 0) {
            memmove(g_blacklist[i], g_blacklist[i + 1], (g_blacklist_count - i - 1) * 6);
            g_blacklist_count--;
            char mac_str[18];
            hex_to_str(mac, mac_str, sizeof(mac_str));
            ESP_LOGI(TAG, "MAC unblacklisted: %s (total=%d)", mac_str, g_blacklist_count);
            return;
        }
    }
}

// 获取AP连接设备数
static uint8_t get_ap_sta_count(void) {
    wifi_sta_list_t sta_list;
    esp_err_t err = esp_wifi_ap_get_sta_list(&sta_list);
    if (err == ESP_OK) {
        return sta_list.num;
    }
    return 0;
}

// 查找或创建hostname表条目
static host_entry_t* find_host_entry(const uint8_t *mac) {
    // 先查找已有条目
    for (int i = 0; i < MAX_AP_STATIONS; i++) {
        if (g_host_table[i].valid && memcmp(g_host_table[i].mac, mac, 6) == 0) {
            return &g_host_table[i];
        }
    }
    // 查找空位
    for (int i = 0; i < MAX_AP_STATIONS; i++) {
        if (!g_host_table[i].valid) {
            return &g_host_table[i];
        }
    }
    return NULL;
}

// 根据MAC查找hostname
static const char* lookup_hostname(const uint8_t *mac) {
    for (int i = 0; i < MAX_AP_STATIONS; i++) {
        if (g_host_table[i].valid && memcmp(g_host_table[i].mac, mac, 6) == 0) {
            if (g_host_table[i].hostname[0] != '\0') {
                return g_host_table[i].hostname;
            }
        }
    }
    return NULL;
}

// 根据MAC查找DHCP分配的IP（ARP失败时回退）
static const char* lookup_dhcp_ip(const uint8_t *mac) {
    for (int i = 0; i < MAX_AP_STATIONS; i++) {
        if (g_host_table[i].valid && memcmp(g_host_table[i].mac, mac, 6) == 0) {
            if (g_host_table[i].ip[0] != '\0') {
                return g_host_table[i].ip;
            }
        }
    }
    return NULL;
}

// ==================== UART功能 ====================
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

// 安装UART驱动
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM, UART_BUF_SIZE, UART_BUF_SIZE, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_TX_PIN, UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    ESP_LOGI(TAG, "UART initialized: TX=%d, RX=%d, Baud=%d", UART_TX_PIN, UART_RX_PIN, UART_BAUD_RATE);
}

// 通过UART发送设备数量
static void uart_send_device_count(uint8_t count) {
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "DEV:%d\n", count);
    int written = uart_write_bytes(UART_NUM, buffer, len);
    if (written < 0) {
        ESP_LOGE(TAG, "UART write DEV failed!");
    } else {
        ESP_LOGI(TAG, "UART sent: %s", buffer);
    }
}

// 通过ARP表获取已连接设备的IP地址
// AP作为网关，所有连接设备的通信都会经过ARP，查ARP缓存即可可靠获取IP
// 返回：找到的主机数，ips/macs参数填充IP和MAC
static int get_connected_ips_macs(char ips[][16], char macs[][18], int max_ips) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) return 0;
    if (sta_list.num == 0) return 0;

    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) return 0;

    struct netif *netif = esp_netif_get_netif_impl(ap_netif);
    if (!netif) return 0;

    // 先主动发ARP请求刷新缓存，确保所有station的ARP条目都存在
    // 扫描板如果长时间不主动和AP通信，ARP缓存会过期导致IP查不到
    LOCK_TCPIP_CORE();
    for (int j = 2; j <= 20; j++) {
        ip4_addr_t target_ip;
        IP4_ADDR(&target_ip, 192, 168, 4, j);
        etharp_request(netif, &target_ip);
    }
    UNLOCK_TCPIP_CORE();

    // 等待ARP响应（100ms足够局域网内完成）
    vTaskDelay(pdMS_TO_TICKS(100));

    int found = 0;

    // 加lwIP核心锁保护ARP表访问，防止与WiFi任务并发导致崩溃
    LOCK_TCPIP_CORE();
    for (int i = 0; i < sta_list.num && found < max_ips; i++) {
        for (int j = 2; j <= 20; j++) {
            ip4_addr_t check_ip;
            IP4_ADDR(&check_ip, 192, 168, 4, j);
            struct eth_addr *eth_ret = NULL;
            const ip4_addr_t *ip_ret = NULL;
            if (etharp_find_addr(netif, &check_ip, &eth_ret, &ip_ret) == ERR_OK) {
                if (eth_ret && ip_ret && memcmp(eth_ret->addr, sta_list.sta[i].mac, 6) == 0) {
                    snprintf(ips[found], 16, IPSTR, IP2STR(ip_ret));
                    snprintf(macs[found], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                             sta_list.sta[i].mac[0], sta_list.sta[i].mac[1],
                             sta_list.sta[i].mac[2], sta_list.sta[i].mac[3],
                             sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
                    found++;
                    break;
                }
            }
        }
    }
    UNLOCK_TCPIP_CORE();

    // 如果ARP表找不到某个station（可能刚连接ARP条目未建立），
    // 用DHCP事件记录的IP回退，否则用"0.0.0.0"占位
    for (int i = 0; i < sta_list.num && found < max_ips; i++) {
        bool already_found = false;
        for (int k = 0; k < found; k++) {
            char expected_mac[18];
            snprintf(expected_mac, sizeof(expected_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     sta_list.sta[i].mac[0], sta_list.sta[i].mac[1],
                     sta_list.sta[i].mac[2], sta_list.sta[i].mac[3],
                     sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
            if (strcmp(macs[k], expected_mac) == 0) {
                already_found = true;
                break;
            }
        }
        if (!already_found) {
            // 优先用DHCP事件记录的IP，避免0.0.0.0
            const char *dhcp_ip = lookup_dhcp_ip(sta_list.sta[i].mac);
            if (dhcp_ip) {
                snprintf(ips[found], 16, "%s", dhcp_ip);
            } else {
                snprintf(ips[found], 16, "0.0.0.0");
            }
            snprintf(macs[found], 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                     sta_list.sta[i].mac[0], sta_list.sta[i].mac[1],
                     sta_list.sta[i].mac[2], sta_list.sta[i].mac[3],
                     sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
            found++;
        }
    }
    return found;
}

// 通过UART发送已连接设备的IP、MAC地址和hostname
static void uart_send_host_ips(void) {
    char ips[MAX_AP_STATIONS][16];
    char macs[MAX_AP_STATIONS][18];
    int count = get_connected_ips_macs(ips, macs, MAX_AP_STATIONS);
    for (int i = 0; i < count; i++) {
        // 解析MAC字节用于hostname查找
        uint8_t mac_bytes[6] = {0};
        sscanf(macs[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

        const char *hostname = NULL;
        if (g_host_mutex) xSemaphoreTake(g_host_mutex, pdMS_TO_TICKS(50));
        hostname = lookup_hostname(mac_bytes);
        if (g_host_mutex) xSemaphoreGive(g_host_mutex);

        // HOST:ip,mac,hostname 格式（hostname可能为空）
        char buffer[80];
        int len;
        if (hostname && hostname[0] != '\0') {
            len = snprintf(buffer, sizeof(buffer), "HOST:%s,%s,%s\n", ips[i], macs[i], hostname);
        } else {
            len = snprintf(buffer, sizeof(buffer), "HOST:%s,%s\n", ips[i], macs[i]);
        }
        int written = uart_write_bytes(UART_NUM, buffer, len);
        if (written < 0) {
            ESP_LOGE(TAG, "UART write HOST failed!");
        } else {
            ESP_LOGI(TAG, "UART sent: %s", buffer);
        }
    }
}

// 获取并发送上游WiFi信息（使用互斥锁保护）
static void update_upstream_wifi_info(void) {
    wifi_ap_record_t ap_info;
    esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
    
    if (err == ESP_OK) {
        if (g_wifi_mutex) {
            xSemaphoreTake(g_wifi_mutex, portMAX_DELAY);
        }
        strncpy(s_upstream_ssid, (char*)ap_info.ssid, sizeof(s_upstream_ssid) - 1);
        s_upstream_ssid[sizeof(s_upstream_ssid) - 1] = '\0';
        s_upstream_rssi = ap_info.rssi;
        
        // 发送WiFi信息到扫描板
        char buffer[64];
        int len = snprintf(buffer, sizeof(buffer), "WIFI:%s,%d\n", s_upstream_ssid, s_upstream_rssi);
        int written = uart_write_bytes(UART_NUM, buffer, len);
        if (written < 0) {
            ESP_LOGE(TAG, "UART write WIFI failed!");
        } else {
            ESP_LOGI(TAG, "UART sent WiFi: %s, RSSI: %d", s_upstream_ssid, s_upstream_rssi);
        }
        
        if (g_wifi_mutex) {
            xSemaphoreGive(g_wifi_mutex);
        }
    }
}

// ==================== WiFi功能 ====================

// WiFi事件处理
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } 
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disconn = (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGW(TAG, "STA disconnected! reason=%d, retrying...", disconn->reason);
        s_sta_connected = false;
        s_upstream_ssid[0] = '\0';
        s_upstream_rssi = 0;
        // LED状态由led_task统一管理，不在事件回调中操作GPIO
        // 【重要】事件回调中不能调用vTaskDelay！直接重连
        esp_wifi_connect();
    } 
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "STA connected! Got IP: " IPSTR, IP2STR(&event->ip_info.ip));

        // 打印上游路由器实际信道，确认是否与AP信道一致
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            ESP_LOGI(TAG, "Upstream AP channel: %d (AP channel: %d)", ap_info.primary, AP_CHANNEL);
            if (ap_info.primary != AP_CHANNEL) {
                ESP_LOGW(TAG, "Channel mismatch! STA=%d AP=%d, APSTA may be unstable",
                         ap_info.primary, AP_CHANNEL);
            }
        }

        s_sta_connected = true;
        
        // 连接成功，更新并发送WiFi信息
        update_upstream_wifi_info();
    }
    // AP模式下：设备连接/断开事件
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " connected to AP", MAC2STR(event->mac));

        // 检查黑名单：被拉黑的设备立即踢除
        if (g_blacklist_mutex) xSemaphoreTake(g_blacklist_mutex, portMAX_DELAY);
        bool blocked = is_mac_blacklisted(event->mac);
        if (blocked) {
            // 先通知扫描板：即将踢人，防止其误计为 Deauth 攻击
            char prekick[32];
            int plen = snprintf(prekick, sizeof(prekick), "PREKICK:" MACSTR "\n", MAC2STR(event->mac));
            uart_write_bytes(UART_NUM, prekick, plen);
            vTaskDelay(pdMS_TO_TICKS(80));  // 等扫描板处理 PREKICK
            uint16_t aid = 0;
            if (esp_wifi_ap_get_sta_aid(event->mac, &aid) == ESP_OK) {
                esp_wifi_deauth_sta(aid);
                ESP_LOGW(TAG, "Blacklisted device " MACSTR " kicked immediately (PREKICK sent)!", MAC2STR(event->mac));
            }
        }
        if (g_blacklist_mutex) xSemaphoreGive(g_blacklist_mutex);

        if (g_count_mutex) {
            xSemaphoreTake(g_count_mutex, portMAX_DELAY);
        }
        g_ap_sta_count = get_ap_sta_count();
        if (g_count_mutex) {
            xSemaphoreGive(g_count_mutex);
        }
        ESP_LOGI(TAG, "AP connected devices: %d", g_ap_sta_count);
        // 设备数量和IP由uart_send_task定时发送（每2秒），事件回调中不直接发UART
        // 之前尝试在此处发HOST，但触发vTaskDelay违规（在事件回调中不可调用）
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " disconnected from AP", MAC2STR(event->mac));
        if (g_count_mutex) {
            xSemaphoreTake(g_count_mutex, portMAX_DELAY);
        }
        g_ap_sta_count = get_ap_sta_count();
        if (g_count_mutex) {
            xSemaphoreGive(g_count_mutex);
        }
        ESP_LOGI(TAG, "AP connected devices: %d", g_ap_sta_count);
        // 清除该设备的hostname缓存
        if (g_host_mutex) xSemaphoreTake(g_host_mutex, portMAX_DELAY);
        for (int i = 0; i < MAX_AP_STATIONS; i++) {
            if (g_host_table[i].valid && memcmp(g_host_table[i].mac, event->mac, 6) == 0) {
                g_host_table[i].valid = false;
                g_host_table[i].hostname[0] = '\0';
                break;
            }
        }
        if (g_host_mutex) xSemaphoreGive(g_host_mutex);
    }
    // DHCP分配IP事件：获取客户端IP和MAC
    else if (event_base == IP_EVENT && event_id == IP_EVENT_AP_STAIPASSIGNED) {
        ip_event_ap_staipassigned_t* event = (ip_event_ap_staipassigned_t*) event_data;
        ESP_LOGI(TAG, "DHCP assigned IP " IPSTR " to " MACSTR,
                 IP2STR(&event->ip), MAC2STR(event->mac));
        // 存储IP和MAC到缓存表
        if (g_host_mutex) xSemaphoreTake(g_host_mutex, portMAX_DELAY);
        host_entry_t *entry = find_host_entry(event->mac);
        if (entry) {
            memcpy(entry->mac, event->mac, 6);
            snprintf(entry->ip, sizeof(entry->ip), IPSTR, IP2STR(&event->ip));
            entry->valid = true;
        }
        if (g_host_mutex) xSemaphoreGive(g_host_mutex);
    }
}

// WiFi连接
static void wifi_connect(void) {
    wifi_config_t wifi_config = {
        .sta = {
            .scan_method = WIFI_FAST_SCAN,
            .listen_interval = 10,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    
    strncpy((char*)wifi_config.sta.ssid, CONFIG_WIFI_SSID, sizeof(wifi_config.sta.ssid));
    strncpy((char*)wifi_config.sta.password, CONFIG_WIFI_PASSWORD, sizeof(wifi_config.sta.password));
    
    // AP配置
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen(AP_SSID),
            .channel = AP_CHANNEL,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .max_connection = MAX_AP_STATIONS,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    strncpy((char*)ap_config.ap.ssid, AP_SSID, sizeof(ap_config.ap.ssid));
    strncpy((char*)ap_config.ap.password, AP_PASSWORD, sizeof(ap_config.ap.password));
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "WiFi starting - STA: %s", CONFIG_WIFI_SSID);
    ESP_LOGI(TAG, "AP starting - SSID: %s", AP_SSID);
}

// ==================== UART接收任务 ====================
// 接收扫描板发来的控制命令
// 支持：KICK:AA:BB:CC:DD:EE:FF - 断开指定设备

// MAC字符串转字节数组，如 "AA:BB:CC:DD:EE:FF" → {0xAA,0xBB,...}
static bool parse_mac_str(const char *str, uint8_t *mac) {
    int vals[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            if (vals[i] < 0 || vals[i] > 255) return false;
            mac[i] = (uint8_t)vals[i];
        }
        return true;
    }
    return false;
}

static void uart_receive_task(void *pvParameters) {
    uint8_t data[64];

    while (1) {
        int len = uart_read_bytes(UART_NUM, data, sizeof(data) - 1, pdMS_TO_TICKS(100));
        if (len <= 0) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        data[len] = '\0';

        // 解析 KICK:MAC 命令
        if (strncmp((char *)data, "KICK:", 5) == 0) {
            char *mac_str = (char *)data + 5;
            // 去除末尾换行符
            char *nl = strchr(mac_str, '\n');
            if (nl) *nl = '\0';
            nl = strchr(mac_str, '\r');
            if (nl) *nl = '\0';

            uint8_t target_mac[6];
            if (parse_mac_str(mac_str, target_mac)) {
                ESP_LOGW(TAG, "KICK command received, disconnecting " MACSTR,
                         MAC2STR(target_mac));
                // 先发 PREKICK 通知扫描板豁免此次 Deauth
                char prekick[32];
                int plen = snprintf(prekick, sizeof(prekick), "PREKICK:" MACSTR "\n", MAC2STR(target_mac));
                uart_write_bytes(UART_NUM, prekick, plen);
                vTaskDelay(pdMS_TO_TICKS(80));
                // 先尝试 get_sta_aid，失败则遍历 station list 用索引推算 AID
                uint16_t aid = 0;
                esp_err_t aid_ret = esp_wifi_ap_get_sta_aid(target_mac, &aid);
                if (aid_ret == ESP_OK && aid > 0) {
                    esp_wifi_deauth_sta(aid);
                    ESP_LOGW(TAG, "Deauth sent to " MACSTR " (AID=%u via get_sta_aid)", MAC2STR(target_mac), aid);
                } else {
                    // esp_wifi_ap_get_sta_aid 在部分 IDF 版本不可靠，用 station list 兜底
                    wifi_sta_list_t sta_list;
                    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
                        for (int i = 0; i < sta_list.num; i++) {
                            if (memcmp(sta_list.sta[i].mac, target_mac, 6) == 0) {
                                uint16_t fallback_aid = (uint16_t)(i + 1);  // SoftAP 按连接顺序分配AID
                                esp_wifi_deauth_sta(fallback_aid);
                                ESP_LOGW(TAG, "Deauth sent to " MACSTR " (AID=%u fallback)", MAC2STR(target_mac), fallback_aid);
                                break;
                            }
                        }
                    }
                }
                // 加入黑名单，防止设备重连
                if (g_blacklist_mutex) xSemaphoreTake(g_blacklist_mutex, portMAX_DELAY);
                add_to_blacklist(target_mac);
                if (g_blacklist_mutex) xSemaphoreGive(g_blacklist_mutex);
                // 更新设备计数
                if (g_count_mutex) xSemaphoreTake(g_count_mutex, portMAX_DELAY);
                g_ap_sta_count = get_ap_sta_count();
                if (g_count_mutex) xSemaphoreGive(g_count_mutex);
                // 发送更新后的计数
                uart_send_device_count(g_ap_sta_count);
            }
        }
        // 解析 UNBLK:MAC 命令 - 从黑名单移除设备，允许重新连接
        else if (strncmp((char *)data, "UNBLK:", 6) == 0) {
            char *mac_str = (char *)data + 6;
            char *nl = strchr(mac_str, '\n');
            if (nl) *nl = '\0';
            nl = strchr(mac_str, '\r');
            if (nl) *nl = '\0';

            uint8_t target_mac[6];
            if (parse_mac_str(mac_str, target_mac)) {
                ESP_LOGI(TAG, "UNBLK command received, removing " MACSTR " from blacklist",
                         MAC2STR(target_mac));
                if (g_blacklist_mutex) xSemaphoreTake(g_blacklist_mutex, portMAX_DELAY);
                remove_from_blacklist(target_mac);
                if (g_blacklist_mutex) xSemaphoreGive(g_blacklist_mutex);
            }
        }
    }
}

// ==================== UART发送任务 ====================
// 定时通过UART发送数据（每2秒）
static void uart_send_task(void *pvParameters) {
    uint32_t send_count = 0;
    while (1) {
        send_count++;
        // 发送设备数量
        if (g_count_mutex) {
            xSemaphoreTake(g_count_mutex, portMAX_DELAY);
        }
        uint8_t count = g_ap_sta_count;
        if (g_count_mutex) {
            xSemaphoreGive(g_count_mutex);
        }
        uart_send_device_count(count);

        // 发送已连接设备的IP地址（每周期都刷新，覆盖DHCP IP变化）
        uart_send_host_ips();

        // 发送上游WiFi信息
        if (s_sta_connected) {
            update_upstream_wifi_info();
        }

        // 心跳日志：每5次(10秒)打印一次，确认任务存活
        if (send_count % 5 == 0) {
            ESP_LOGI(TAG, "uart_send_task alive, cycle=%lu, sta=%d", 
                     (unsigned long)send_count, count);
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

// LED任务
static void led_task(void *pvParameters) {
    gpio_reset_pin(LED_RED_GPIO);
    gpio_set_direction(LED_RED_GPIO, GPIO_MODE_OUTPUT);
    gpio_reset_pin(LED_GREEN_GPIO);
    gpio_set_direction(LED_GREEN_GPIO, GPIO_MODE_OUTPUT);
    
    led_set_red(true);
    led_set_green(false);
    
    // LED任务循环：根据上游WiFi连接状态自动更新LED
    while (1) {
        if (s_sta_connected) {
            led_set_red(false);
            led_set_green(true);
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            led_set_red(true);
            led_set_green(false);
            vTaskDelay(pdMS_TO_TICKS(500));
            led_set_red(false);
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}

// ==================== 主程序 ====================
void app_main(void) {
    ESP_LOGI(TAG, "WiFiWarden AP Starting...");
    
    // 创建互斥锁
    g_count_mutex = xSemaphoreCreateMutex();
    g_wifi_mutex = xSemaphoreCreateMutex();
    g_host_mutex = xSemaphoreCreateMutex();
    g_blacklist_mutex = xSemaphoreCreateMutex();
    memset(g_host_table, 0, sizeof(g_host_table));
    g_blacklist_count = 0;
    
    // 初始化UART
    uart_init();
    
    // 初始化NVS
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // 创建AP网络接口
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    assert(ap_netif);
    
    // 配置AP DHCP
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(esp_netif_ip_info_t));
    ip_info.ip.addr = esp_ip4addr_aton("192.168.4.1");
    ip_info.gw.addr = esp_ip4addr_aton("192.168.4.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip_info));
    
    // 设置AP接口的DNS服务器（会通过DHCP分发给客户端）
    esp_netif_dns_info_t dns_info;
    memset(&dns_info, 0, sizeof(esp_netif_dns_info_t));
    dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton("8.8.8.8");
    dns_info.ip.type = ESP_IPADDR_TYPE_V4;
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_info));
    
    dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton("114.114.114.114");
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_BACKUP, &dns_info));

    esp_netif_dhcps_start(ap_netif);
    ESP_LOGI(TAG, "DHCP server started on 192.168.4.1");
    
    // 创建STA网络接口
    esp_netif_create_default_wifi_sta();
    
    // 获取MAC地址
    esp_read_mac(s_device_mac, ESP_MAC_WIFI_STA);
    hex_to_str(s_device_mac, s_device_mac_str, 18);
    ESP_LOGI(TAG, "Device MAC: %s", s_device_mac_str);
    
    // WiFi初始化
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    
    // 注册WiFi事件
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    // 注册DHCP分配IP事件（AP模式下获取客户端IP）
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &wifi_event_handler, NULL));
    
    // 启动WiFi
    wifi_connect();
    
    // 配置NAPT (Network Address Port Translation) - 让AP客户端能通过STA访问外网
    ESP_LOGI(TAG, "Configuring NAPT...");
    
#if CONFIG_ENABLE_NAPT && defined(CONFIG_LWIP_IPV4_NAPT)
    // 启用NAPT on AP interface
    esp_err_t err = esp_netif_napt_enable(ap_netif);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "NAPT enabled successfully!");
        ESP_LOGI(TAG, "AP clients can now access upstream WiFi");
    } else {
        ESP_LOGE(TAG, "NAPT enable failed: %s", esp_err_to_name(err));
        ESP_LOGI(TAG, "Please ensure IP_NAPT is enabled in menuconfig");
        ESP_LOGI(TAG, "Path: Component config -> LWIP -> Enable IP NAPT");
    }
#else
    ESP_LOGI(TAG, "NAPT is disabled in Kconfig");
#endif
    
    // 设置STA为默认网络接口
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA");
    if (sta_netif) {
        esp_netif_set_default_netif(sta_netif);
        ESP_LOGI(TAG, "STA set as default network interface");
    }
    
    ESP_LOGI(TAG, "DHCP server running on AP (192.168.4.1)");
    
    // 创建任务
    xTaskCreate(uart_send_task, "uart_send", 4096, NULL, 4, NULL);
    xTaskCreate(uart_receive_task, "uart_rx", 4096, NULL, 3, NULL);
    xTaskCreate(led_task, "led", 4096, NULL, 3, NULL);
    
    ESP_LOGI(TAG, "WiFiWarden AP initialized");
    ESP_LOGI(TAG, "AP SSID: %s, Password: %s", AP_SSID, AP_PASSWORD);
    ESP_LOGI(TAG, "UART connection to scan board: TX=%d -> RX=%d", UART_TX_PIN, UART_RX_PIN);
}
