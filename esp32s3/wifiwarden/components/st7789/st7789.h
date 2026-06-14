/**
 * ST7789 驱动 - 大字体版本
 * 适用于 GMT020-02-8p (2.0" 240x320)
 */

#ifndef ST7789_H
#define ST7789_H

#include <stdint.h>
#include "driver/spi_master.h"
#include "driver/gpio.h"

#define ST7789_WIDTH   240
#define ST7789_HEIGHT  320

// 颜色 (RGB565，字节交换后以适应ESP32小端→ST7789大端)
// ESP32以内存顺序发送uint16_t，即低字节先发；ST7789期望高字节在前。
// 因此每个颜色值预先交换高低字节，使SPI发送的字节序列匹配ST7789。
#define ST7789_BLACK     0x0000
#define ST7789_WHITE     0xFFFF
#define ST7789_RED       0x00F8
#define ST7789_GREEN     0xE007
#define ST7789_BLUE      0x1F00
#define ST7789_YELLOW    0xE0FF
#define ST7789_CYAN      0xFF07
#define ST7789_MAGENTA   0x1FF8
#define ST7789_ORANGE    0x20FA
#define ST7789_GRAY      0x1084
#define ST7789_DARK_BLUE 0x1F00
#define ST7789_DARK_GREEN 0xE003
#define ST7789_LIGHT_BLUE 0x1F84
#define ST7789_LIGHT_RED  0x10F8

// 初始化
esp_err_t st7789_init(spi_host_device_t host,
                      gpio_num_t mosi, gpio_num_t sck,
                      gpio_num_t cs, gpio_num_t dc,
                      gpio_num_t rst, gpio_num_t blk);

// 清屏
void st7789_clear(uint16_t color);

// 填充矩形
void st7789_fill_rect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);

// 画矩形边框
void st7789_draw_rect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);

// 画线
void st7789_draw_line(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2, uint16_t color);

// 显示字符串 - 小字体 (6x10)
void st7789_draw_string(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color);

// 显示字符串 - 中字体 (9x15) - 放大1.5倍
void st7789_draw_string_medium(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color);

// 显示字符串 - 大字体 (12x20) - 放大2倍
void st7789_draw_string_big(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color);

// 显示单个数字 - 大字体
void st7789_draw_number_big(uint16_t x, uint16_t y, int num, uint16_t fg_color, uint16_t bg_color);

// 背光
void st7789_backlight_set(uint8_t level);

#endif
