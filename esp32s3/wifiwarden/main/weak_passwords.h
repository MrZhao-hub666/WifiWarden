/**
 * weak_passwords.h - 常见默认密码字典（扩 展版）
 *
 * 字符串常量存储在Flash中（const数据），指针数组占用少量RAM。
 * 覆盖场景：路由器管理页面、IoT设备、摄像头、NAS、打印机等。
 * 注意：这是安全测试字典（公开已知的厂家默认密码），非系统凭据。
 *
 * 版本：v2.0 - 扩 展至 200+ HTTP + 60+ Telnet
 */

#ifndef WEAK_PASSWORDS_H
#define WEAK_PASSWORDS_H

#ifdef __cplusplus
extern "C" {
#endif

// ==================== HTTP Basic Auth 密码组合 (200+组) ====================
// 覆盖：路由器管理页、摄像头、NAS、IoT设备Web界面
// 格式："username:password"
static const char *HTTP_DEFAULT_CREDS[] = {
    // ===== 1. 通用弱口令 (40组) =====
    "admin:admin",          "admin:password",       "admin:123456",
    "admin:admin123",       "admin:root",           "admin:888888",
    "admin:666666",         "admin:123",            "admin:1234",
    "admin:12345",          "admin:12345678",       "admin:111111",
    "admin:000000",         "admin:pass",           "admin:admin1234",
    "admin:P@ssw0rd",       "admin:abc123",         "admin:letmein",
    "root:root",            "root:123456",          "root:admin",
    "root:toor",            "root:passwd",          "root:666666",
    "root:111111",          "root:1234",            "root:password",
    "root:P@ssw0rd",        "root:abc123",          "root:letmein",
    "user:user",            "user:123456",          "user:password",
    "guest:guest",          "test:test",            "test:123456",
    "support:support",      "nobody:nobody",        "sa:sa",
    "manager:manager",      "super:super",

    // ===== 2. 品牌路由器 (60组) =====
    // TP-Link
    "admin:admin",          "admin:1234",           "admin:(none)",
    "admin:tp-link",        "root:root",            "support:support",
    // 小米/红米
    "admin:admin",          "root:admin",           "admin:1234",
    "admin:xiaomi",         "root:xiaomi",          "admin:miadmin",
    // 华为/Huawei
    "admin:admin",          "admin:1234",           "root:admin",
    "admin:Huawei123",      "admin:Huawei@123",     "root:Huawei123",
    "admin:admin123",       "admin:Password123",
    // 华硕/ASUS
    "admin:admin",          "admin:password",       "admin:1234",
    "admin:asus",           "root:asus",            "admin:asustek",
    // 腾达/Tenda
    "admin:admin",          "admin:123456",         "admin:guest",
    "admin:tenda",          "root:tenda",           "user:user",
    // 水星/Mercury
    "admin:admin",          "admin:1234",           "admin:1",
    "admin:mercury",        "root:mercury",
    // 中兴/ZTE
    "admin:admin",          "admin:Zte1234",        "root:root",
    "admin:zte",            "root:zte",             "admin:Zte521",
    // 迅捷/FAST
    "admin:admin",          "admin:1234",           "admin:guest",
    // 斐讯/Phicomm
    "admin:admin",          "admin:123456",         "root:admin",
    "admin:phicomm",
    // 极路由/HiWiFi
    "admin:admin",          "root:admin",
    // Netgear
    "admin:password",       "admin:1234",           "admin:admin",
    "admin:netgear",        "root:netgear",         "admin:NETGEAR",
    // D-Link
    "admin:admin",          "admin:1234",           "admin:password",
    "admin:dlink",          "root:dlink",           "user:user",
    // Cisco/Linksys
    "admin:admin",          "admin:password",       "root:admin",
    "admin:cisco",          "cisco:cisco",          "admin:linksys",
    // TOTOLINK
    "admin:admin",          "admin:123456",         "admin:guest",
    // 磊科/Netcore
    "admin:admin",          "admin:1234",           "guest:guest",
    // 艾泰/UTT
    "admin:admin",          "admin:123456",         "root:root",
    // 蒲公英/Oray
    "admin:admin",          "root:admin",           "admin:oray",

    // ===== 3. 摄像头/IP摄像头 (35组) =====
    "admin:admin",          "admin:123456",         "admin:1234",
    "admin:888888",         "admin:666666",         "admin:111111",
    "admin:pass",           "root:root",            "root:123456",
    "admin:admin123",       "admin:11111111",       "admin:4321",
    "888888:888888",        "666666:666666",        "guest:guest",
    "user:user",            "admin:12345",          "admin:1",
    "admin:password",       "root:xc3511",          "admin:ikwb",
    "admin:ipcam",          "root:ipcam",           "admin:admin1",
    "admin:mei",            "admin:hichip",         "admin:hikvision",
    "admin:123456789",      "root:12345",           "admin:abc1234",
    "admin:123456a",        "admin:a123456",        "admin:pass123",
    "admin:0",              "admin:default",

    // ===== 4. NAS/存储 (20组) =====
    "admin:admin",          "admin:12345678",       "admin:1111",
    "root:root",            "admin:0000",           "admin:password",
    "admin:nas",            "root:nas",             "admin:synology",
    "admin:qnap",           "admin:1234567890",     "admin:admin1234",
    "guest:guest",          "admin:asustor",        "root:asustor",
    "admin:wdadmin",        "admin:1234",           "admin:123",
    "admin:789456",         "admin:000000",

    // ===== 5. 打印机/扫描仪 (15组) =====
    "admin:admin",          "admin:12345678",       "admin:1111",
    "root:root",            "admin:0000",           "admin:password",
    "admin:1234",           "admin:123456",         "admin:access",
    "admin:11111111",       "admin:222222",         "admin:00000000",
    "admin:print",          "root:print",           "admin:hp",

    // ===== 6. VoIP/电话设备 (15组) =====
    "admin:admin",          "admin:1234",           "admin:password",
    "admin:voip",           "root:voip",            "admin:123456",
    "admin:12345",          "admin:1111",           "admin:0000",
    "admin:default",        "admin:admin123",       "admin:4321",
    "admin:admin1234",      "root:root123",         "admin:cisco",

    // ===== 7. 工控/IoT/智能家居 (20组) =====
    "admin:admin",          "admin:123456",         "admin:1234",
    "admin:password",       "root:root",            "root:default",
    "admin:admin123",       "admin:smarthome",      "admin:iot",
    "admin:zigbee",         "admin:12345678",       "admin:1111",
    "admin:0000",           "admin:8888",           "admin:6666",
    "admin:pass123",        "admin:letmein",        "root:1234",
    "admin:control",        "admin:smart",

    // ===== 8. 其他常见组合 (15组) =====
    "admin:passw0rd",       "admin:PASSWORD",       "admin:Admin",
    "admin:Admin123",       "root:passw0rd",        "root:PASSWORD",
    "root:toor123",         "root:r00t",            "admin:r00t",
    "admin:@dmin",          "admin:security",       "admin:secure",
    "admin:changeme",       "admin:temp123",        "admin:temp",

    // ===== 9. 空密码/弱密码 (10组) =====
    "admin:",               "root:",                "user:",
    "guest:",               "support:",             "nobody:",
    "admin: ",              "root: ",               "admin:0",
    "root:0",

    NULL  // 结束标记
};

// ==================== Telnet 密码组合 (65组) ====================
// 覆盖：IoT设备、路由器、摄像头Telnet登录
static const char *TELNET_DEFAULT_CREDS[] = {
    // ===== 1. 通用 (20组) =====
    "root:root",            "root:123456",          "root:admin",
    "root:toor",            "root:passwd",          "root:666666",
    "root:1234",            "admin:admin",          "admin:123456",
    "admin:root",           "root:password",        "root:123",
    "root:111111",          "root:12345",           "root:12345678",
    "admin:1234",           "admin:password",       "admin:123",
    "root:passw0rd",        "root:P@ssw0rd",

    // ===== 2. 品牌默认 (15组) =====
    "root:Zte521",          "root:Huaw3i",          "root:Telnet",
    "root:default",         "root:password",        "apl:888888",
    "admin:111111",         "root:123",             "admin:1234",
    "admin:password",       "root:xc3511",          "root:admin123",
    "root:888888",          "admin:888888",         "root:Zte1234",

    // ===== 3. IoT/摄像头 (15组) =====
    "root:camera",          "admin:ipcam",          "admin:4321",
    "root:xmhdipc",         "admin:1234567890",     "root:ipcam",
    "admin:camera",         "root:admin123",        "admin:admin123",
    "root:hichip",          "admin:hichip",         "root:hikvision",
    "admin:hik123",         "root:ikwb",            "admin:ikwb",

    // ===== 4. 留空/简单密码 (15组) =====
    "root:",                "admin:",               "user:",
    "root:root123",         "admin:admin123",       "root:pass",
    "admin:pass",           "root:0",               "admin:0",
    "root:root1234",        "admin:admin1234",      "root:12",
    "admin:123",            "root:12345",           "admin:12345",

    NULL  // 结束标记
};

#ifdef __cplusplus
}
#endif

#endif /* WEAK_PASSWORDS_H */
