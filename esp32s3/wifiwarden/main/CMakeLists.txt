idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_event nvs_flash esp_netif driver freertos esp_timer st7789 lwip mqtt cjson
)
