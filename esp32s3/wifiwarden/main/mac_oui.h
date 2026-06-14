/**
 * mac_oui.h - MAC地址OUI厂商识别数据库
 *
 * 根据MAC地址前3字节(OUI)识别设备制造商。
 * 数据存储在Flash中（const），不占RAM。
 * 覆盖主流品牌：手机/路由器/IoT/电脑
 */

#ifndef MAC_OUI_H
#define MAC_OUI_H

#ifdef __cplusplus
extern "C" {
#endif

// OUI查找表条目
typedef struct {
    uint8_t oui[3];       // MAC前3字节
    char vendor[20];      // 厂商名称
} oui_entry_t;

static const oui_entry_t OUI_TABLE[] = {
    // ---- 手机厂商 ----
    {{0xE0,0x72,0xA1}, "ESP32-S3"},     // ESP32-S3 (乐鑫)
    {{0x10,0x08,0xB1}, "ESP32"},        // ESP32
    {{0x24,0x0A,0xC4}, "ESP"},          // ESP系列
    {{0x84,0xF7,0x03}, "Xiaomi"},       // 小米/红米手机
    {{0x98,0x8D,0x46}, "Xiaomi"},       // 小米/红米
    {{0x48,0xE7,0x29}, "Xiaomi"},       // 小米
    {{0x4C,0xE1,0x73}, "Xiaomi"},       // 小米
    {{0x34,0x95,0xDB}, "Xiaomi"},       // 小米
    {{0xD4,0x8A,0xFC}, "Xiaomi"},       // 小米
    {{0x88,0xC3,0x97}, "Apple"},        // iPhone/iPad
    {{0xBC,0xD0,0x74}, "Apple"},        // iPhone
    {{0xAC,0xBC,0x32}, "Apple"},        // iPhone
    {{0x0C,0x74,0xC2}, "Apple"},        // iPhone
    {{0x04,0x0C,0xCE}, "Apple"},        // iPhone
    {{0x70,0x30,0x5D}, "Apple"},        // iPhone
    {{0x7C,0x32,0x3E}, "Apple"},        // iPhone
    {{0x68,0x2C,0x97}, "Samsung"},      // 三星手机
    {{0x24,0x0F,0x5E}, "Samsung"},      // 三星
    {{0xCC,0xE7,0x12}, "Samsung"},      // 三星
    {{0x64,0x6B,0xF0}, "Huawei"},       // 华为手机
    {{0x48,0x57,0x02}, "Huawei"},       // 华为
    {{0xDC,0x0E,0xA1}, "Huawei"},       // 华为
    {{0x08,0xEA,0x40}, "Huawei"},       // 华为
    {{0xFC,0x5B,0x26}, "Huawei"},       // 华为
    {{0x28,0x6E,0xD4}, "Honor"},        // 荣耀
    {{0x3C,0x08,0xF6}, "Honor"},        // 荣耀
    {{0x9C,0x28,0xBF}, "OPPO"},         // OPPO
    {{0xF0,0x03,0x8C}, "OPPO"},         // OPPO
    {{0xA4,0x55,0x26}, "vivo"},         // vivo
    {{0x5C,0xE0,0xCA}, "vivo"},         // vivo
    {{0xC8,0x1E,0xE7}, "vivo"},         // vivo
    {{0x98,0x40,0xBB}, "vivo"},         // vivo
    {{0x50,0x91,0xE3}, "vivo"},         // vivo
    {{0x10,0xA5,0xD0}, "vivo"},         // vivo
    {{0x2C,0x54,0x91}, "OnePlus"},      // 一加
    {{0x3C,0x84,0x6A}, "Sony"},         // 索尼
    {{0xC8,0x60,0x00}, "LG"},           // LG
    {{0xEC,0x43,0xF6}, "Google"},       // Google Pixel
    {{0xFC,0x64,0xBA}, "Google"},       // Google

    // ---- 路由器/网络设备 ----
    {{0x64,0x6E,0x97}, "TP-Link"},      // TP-Link路由器
    {{0xEC,0x88,0x8F}, "TP-Link"},      // TP-Link
    {{0x50,0xAD,0x6C}, "TP-Link"},      // TP-Link
    {{0x08,0x10,0x76}, "TP-Link"},      // TP-Link
    {{0xA0,0xF3,0xC1}, "TP-Link"},      // TP-Link
    {{0x74,0xDA,0x38}, "TP-Link"},      // TP-Link
    {{0xC0,0x4A,0x00}, "TP-Link"},      // TP-Link
    {{0x9C,0xD2,0x4B}, "TP-Link"},      // TP-Link
    {{0x44,0x6E,0xE5}, "Xiaomi"},       // 小米路由器
    {{0xF4,0x09,0xD8}, "Xiaomi"},       // 小米路由器
    {{0xC8,0x3A,0x35}, "Xiaomi"},       // 小米路由器
    {{0x30,0xB5,0xC2}, "Tenda"},        // 腾达
    {{0x24,0x69,0x68}, "Tenda"},        // 腾达
    {{0x48,0x22,0x54}, "Tenda"},        // 腾达
    {{0xF0,0xFE,0x6B}, "Huawei"},       // 华为路由器
    {{0xCC,0x34,0x29}, "Huawei"},       // 华为路由器
    {{0x70,0xF1,0xA1}, "ASUS"},         // 华硕路由器
    {{0x10,0xBF,0x48}, "ASUS"},         // 华硕路由器
    {{0x74,0xD0,0x2B}, "ASUS"},         // 华硕
    {{0x58,0x97,0xBD}, "Netgear"},      // Netgear
    {{0xA0,0x04,0x60}, "Netgear"},      // Netgear
    {{0x00,0x22,0xB0}, "D-Link"},       // D-Link
    {{0x28,0x10,0x7B}, "D-Link"},       // D-Link
    {{0x0C,0x80,0x63}, "TOTOLINK"},     // TOTOLINK
    {{0xE0,0x60,0x66}, "MERCURY"},      // 水星
    {{0x00,0x20,0xE0}, "PCI"},          // 博达/必联

    // ---- 电脑/笔记本 ----
    {{0x3C,0x7C,0x3F}, "Dell"},         // Dell笔记本
    {{0xF4,0x8E,0x38}, "Dell"},         // Dell
    {{0x00,0x26,0xB9}, "Dell"},         // Dell
    {{0xAC,0x9E,0x17}, "Lenovo"},       // 联想
    {{0x38,0xE3,0xC5}, "Lenovo"},       // 联想
    {{0x88,0xAE,0x1D}, "Lenovo"},       // 联想
    {{0xE0,0x06,0xE6}, "HP"},           // HP
    {{0xE4,0xA7,0xA0}, "HP"},           // HP
    {{0x08,0xEC,0x67}, "HP"},           // HP
    {{0x5C,0xE0,0x8E}, "Hasee"},        // 神舟
    {{0x14,0x58,0xD0}, "Apple"},        // MacBook
    {{0x80,0xBE,0x05}, "Apple"},        // MacBook
    {{0xF0,0x18,0x98}, "Microsoft"},    // Surface

    // ---- IoT/智能家居 ----
    {{0x04,0xCF,0x8C}, "Xiaomi"},       // 小米智能家居
    {{0x54,0xEF,0x44}, "Xiaomi"},       // 小米IoT
    {{0xDC,0xFE,0x07}, "Xiaomi"},       // 小米IoT
    {{0x00,0x0C,0x43}, "WiFi-Camera"},  // 安防摄像头
    {{0x00,0x12,0x1B}, "IP-Camera"},    // 网络摄像头
    {{0xF8,0x1A,0x67}, "Tuya"},         // 涂鸦智能
    {{0x10,0xD5,0x86}, "Tuya"},         // 涂鸦智能
    {{0x60,0xA4,0x4C}, "Tuya"},         // 涂鸦
    {{0x18,0xFE,0x34}, "Raspberry"},    // 树莓派
    {{0xB8,0x27,0xEB}, "Raspberry"},    // 树莓派
    {{0xDC,0xA6,0x32}, "Raspberry"},    // 树莓派
    {{0x00,0x1A,0x11}, "Arduino"},      // Arduino

};

#define OUI_TABLE_SIZE (sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]))

/**
 * 根据MAC地址查询设备厂商
 * 返回厂商名称字符串，未找到返回"Unknown"
 * 注意：随机/隐私MAC返回"Privacy"
 */
static inline const char* lookup_vendor(const uint8_t *mac) {
    for (int i = 0; i < OUI_TABLE_SIZE; i++) {
        if (mac[0] == OUI_TABLE[i].oui[0] &&
            mac[1] == OUI_TABLE[i].oui[1] &&
            mac[2] == OUI_TABLE[i].oui[2]) {
            return OUI_TABLE[i].vendor;
        }
    }
    // 检测随机/隐私MAC（locally administered bit）
    if (mac[0] & 0x02) {
        return "Privacy";
    }
    return "Unknown";
}

/**
 * 检测是否为ESP32/ESP系列开发板MAC
 * 用于过滤开发板，不显示在设备列表中
 */
static inline bool is_esp32_mac(const uint8_t *mac) {
    const char *v = lookup_vendor(mac);
    return (v && v[0] == 'E' && v[1] == 'S' && v[2] == 'P');
}

#ifdef __cplusplus
}
#endif

#endif /* MAC_OUI_H */
