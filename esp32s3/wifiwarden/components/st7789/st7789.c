#include "st7789.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

// 标准 5x7 ASCII 字体（Arduino 标准库格式）
static const uint8_t font5x7[][5] = {
    {0x00,0x00,0x00,0x00,0x00}, // ' ' (32)
    {0x00,0x00,0x5F,0x00,0x00}, // '!'
    {0x00,0x07,0x00,0x07,0x00}, // '"'
    {0x14,0x7F,0x14,0x7F,0x14}, // '#'
    {0x24,0x2A,0x7F,0x2A,0x12}, // '$'
    {0x23,0x13,0x08,0x64,0x62}, // '%'
    {0x36,0x49,0x55,0x22,0x50}, // '&'
    {0x00,0x05,0x03,0x00,0x00}, // '''
    {0x00,0x1C,0x22,0x41,0x00}, // '('
    {0x00,0x41,0x22,0x1C,0x00}, // ')'
    {0x08,0x2A,0x1C,0x2A,0x08}, // '*'
    {0x08,0x08,0x3E,0x08,0x08}, // '+'
    {0x00,0x50,0x30,0x00,0x00}, // ','
    {0x08,0x08,0x08,0x08,0x08}, // '-'
    {0x00,0x60,0x60,0x00,0x00}, // '.'
    {0x20,0x10,0x08,0x04,0x02}, // '/'
    {0x3E,0x51,0x49,0x45,0x3E}, // '0'
    {0x00,0x42,0x7F,0x40,0x00}, // '1'
    {0x42,0x61,0x51,0x49,0x46}, // '2'
    {0x21,0x41,0x45,0x4B,0x31}, // '3'
    {0x18,0x14,0x12,0x7F,0x10}, // '4'
    {0x27,0x45,0x45,0x45,0x39}, // '5'
    {0x3C,0x4A,0x49,0x49,0x30}, // '6'
    {0x01,0x71,0x09,0x05,0x03}, // '7'
    {0x36,0x49,0x49,0x49,0x36}, // '8'
    {0x06,0x49,0x49,0x29,0x1E}, // '9'
    {0x00,0x36,0x36,0x00,0x00}, // ':'
    {0x00,0x56,0x36,0x00,0x00}, // ';'
    {0x00,0x08,0x14,0x22,0x41}, // '<'
    {0x14,0x14,0x14,0x14,0x14}, // '='
    {0x41,0x22,0x14,0x08,0x00}, // '>'
    {0x02,0x01,0x51,0x09,0x06}, // '?'
    {0x32,0x49,0x79,0x41,0x3E}, // '@'
    {0x7E,0x11,0x11,0x11,0x7E}, // 'A'
    {0x7F,0x49,0x49,0x49,0x36}, // 'B'
    {0x3E,0x41,0x41,0x41,0x22}, // 'C'
    {0x7F,0x41,0x41,0x22,0x1C}, // 'D'
    {0x7F,0x49,0x49,0x49,0x41}, // 'E'
    {0x7F,0x09,0x09,0x01,0x01}, // 'F'
    {0x3E,0x41,0x41,0x51,0x32}, // 'G'
    {0x7F,0x08,0x08,0x08,0x7F}, // 'H'
    {0x00,0x41,0x7F,0x41,0x00}, // 'I'
    {0x20,0x40,0x41,0x3F,0x01}, // 'J'
    {0x7F,0x08,0x14,0x22,0x41}, // 'K'
    {0x7F,0x40,0x40,0x40,0x40}, // 'L'
    {0x7F,0x02,0x04,0x02,0x7F}, // 'M'
    {0x7F,0x04,0x08,0x10,0x7F}, // 'N'
    {0x3E,0x41,0x41,0x41,0x3E}, // 'O'
    {0x7F,0x09,0x09,0x09,0x06}, // 'P'
    {0x3E,0x41,0x51,0x21,0x5E}, // 'Q'
    {0x7F,0x09,0x19,0x29,0x46}, // 'R'
    {0x46,0x49,0x49,0x49,0x31}, // 'S'
    {0x01,0x01,0x7F,0x01,0x01}, // 'T'
    {0x3F,0x40,0x40,0x40,0x3F}, // 'U'
    {0x1F,0x20,0x40,0x20,0x1F}, // 'V'
    {0x3F,0x40,0x30,0x40,0x3F}, // 'W'
    {0x63,0x14,0x08,0x14,0x63}, // 'X'
    {0x03,0x04,0x78,0x04,0x03}, // 'Y'
    {0x61,0x51,0x49,0x45,0x43}, // 'Z'
    {0x00,0x00,0x7F,0x41,0x41}, // '['
    {0x02,0x04,0x08,0x10,0x20}, // '\'
    {0x41,0x41,0x7F,0x00,0x00}, // ']'
    {0x04,0x02,0x01,0x02,0x04}, // '^'
    {0x40,0x40,0x40,0x40,0x40}, // '_'
    {0x00,0x01,0x02,0x04,0x00}, // '`'
    {0x20,0x54,0x54,0x54,0x78}, // 'a'
    {0x7F,0x48,0x44,0x44,0x38}, // 'b'
    {0x38,0x44,0x44,0x44,0x20}, // 'c'
    {0x38,0x44,0x44,0x48,0x7F}, // 'd'
    {0x38,0x54,0x54,0x54,0x18}, // 'e'
    {0x08,0x7E,0x09,0x01,0x02}, // 'f'
    {0x08,0x14,0x54,0x54,0x3C}, // 'g'
    {0x7F,0x08,0x04,0x04,0x78}, // 'h'
    {0x00,0x44,0x7D,0x40,0x00}, // 'i'
    {0x20,0x40,0x44,0x3D,0x00}, // 'j'
    {0x00,0x7F,0x10,0x28,0x44}, // 'k'
    {0x00,0x41,0x7F,0x40,0x00}, // 'l'
    {0x7C,0x04,0x18,0x04,0x78}, // 'm'
    {0x7C,0x08,0x04,0x04,0x78}, // 'n'
    {0x38,0x44,0x44,0x44,0x38}, // 'o'
    {0x7C,0x14,0x14,0x14,0x08}, // 'p'
    {0x08,0x14,0x14,0x18,0x7C}, // 'q'
    {0x7C,0x08,0x04,0x04,0x08}, // 'r'
    {0x48,0x54,0x54,0x54,0x20}, // 's'
    {0x04,0x3F,0x44,0x40,0x20}, // 't'
    {0x3C,0x40,0x40,0x20,0x7C}, // 'u'
    {0x1C,0x20,0x40,0x20,0x1C}, // 'v'
    {0x3C,0x40,0x30,0x40,0x3C}, // 'w'
    {0x44,0x28,0x10,0x28,0x44}, // 'x'
    {0x0C,0x50,0x50,0x50,0x3C}, // 'y'
    {0x44,0x64,0x54,0x4C,0x44}, // 'z'
    {0x00,0x08,0x36,0x41,0x00}, // '{'
    {0x00,0x00,0x7F,0x00,0x00}, // '|'
    {0x00,0x41,0x36,0x08,0x00}, // '}'
    {0x08,0x08,0x2A,0x1C,0x08}, // '~'
};

static spi_device_handle_t spi_dev = NULL;
static gpio_num_t dc_pin, rst_pin, blk_pin;

// ======== DMA安全缓冲区 ========
// ESP32-S3 的 CPU 写数据会进 cache，但 DMA 直接读物理 RAM（绕过 cache），
// 如果 buffer 在栈上，DMA 可能读到旧数据 → 第一个像素错位 = 左侧竖线。
// 解决：所有 SPI 数据都从 DMA 内存发送。

// 大缓冲区：fill_rect 用（16KB，一次最多发8192像素）
#define DMA_BUF_PIXELS   8192
static uint16_t *s_dma_buf = NULL;

// 小缓冲区：字符渲染 + 小数据用（1KB，够最大字符 12×16=192像素）
#define CHAR_BUF_PIXELS  256
static uint16_t *s_char_buf = NULL;

// ======== SPI命令/数据发送 ========

static void st7789_cmd(uint8_t cmd)
{
    spi_transaction_t t = { .length = 8, .tx_buffer = &cmd };
    gpio_set_level(dc_pin, 0);
    spi_device_polling_transmit(spi_dev, &t);
}

// 发送已在DMA内存中的数据（字符buffer / fill buffer）
static void st7789_data_dma(const uint8_t *data, size_t len)
{
    if (len == 0) return;
    spi_transaction_t t = { .length = len * 8, .tx_buffer = data };
    gpio_set_level(dc_pin, 1);
    spi_device_polling_transmit(spi_dev, &t);
}

// 发送任意数据（小数据自动拷贝到DMA-safe buffer）
static void st7789_data(const uint8_t *data, size_t len)
{
    if (len == 0) return;
    if (len <= CHAR_BUF_PIXELS * 2) {
        memcpy(s_char_buf, data, len);
        spi_transaction_t t = { .length = len * 8, .tx_buffer = s_char_buf };
        gpio_set_level(dc_pin, 1);
        spi_device_polling_transmit(spi_dev, &t);
    } else {
        st7789_data_dma(data, len);
    }
}

static void st7789_set_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
    uint8_t caset[4] = {x0 >> 8, x0 & 0xFF, x1 >> 8, x1 & 0xFF};
    uint8_t raset[4] = {y0 >> 8, y0 & 0xFF, y1 >> 8, y1 & 0xFF};
    st7789_cmd(0x2A); st7789_data(caset, 4);
    st7789_cmd(0x2B); st7789_data(raset, 4);
    st7789_cmd(0x2C);
}

// 单像素绘制（仅draw_line的斜线用）
static void draw_pixel(uint16_t x, uint16_t y, uint16_t color)
{
    if (x >= ST7789_WIDTH || y >= ST7789_HEIGHT) return;
    st7789_set_window(x, y, x, y);
    s_char_buf[0] = color;
    st7789_data_dma((const uint8_t *)s_char_buf, 2);
}

// ======== 缓冲式字符绘制：渲染到DMA内存，一次SPI事务发送 ========

#define CHAR_SMALL_W   6
#define CHAR_SMALL_H   10

static void draw_char_small(uint16_t x, uint16_t y, char c, uint16_t fg, uint16_t bg)
{
    if (c < 32 || c > 126) c = '?';
    if (x + CHAR_SMALL_W > ST7789_WIDTH || y + CHAR_SMALL_H > ST7789_HEIGHT) return;
    const uint8_t *font = font5x7[c - 32];

    // 直接渲染到 DMA 安全 buffer
    for (int row = 0; row < CHAR_SMALL_H; row++) {
        for (int col = 0; col < CHAR_SMALL_W; col++) {
            uint16_t pixel_color;
            if (col < 5 && row < 7) {
                pixel_color = (font[col] >> row) & 0x01 ? fg : bg;
            } else {
                pixel_color = bg;
            }
            s_char_buf[row * CHAR_SMALL_W + col] = pixel_color;
        }
    }
    st7789_set_window(x, y, x + CHAR_SMALL_W - 1, y + CHAR_SMALL_H - 1);
    st7789_data_dma((const uint8_t *)s_char_buf, CHAR_SMALL_W * CHAR_SMALL_H * 2);
}

#define CHAR_MEDIUM_W  9
#define CHAR_MEDIUM_H  15

static void draw_char_medium(uint16_t x, uint16_t y, char c, uint16_t fg, uint16_t bg)
{
    if (c < 32 || c > 126) c = '?';
    if (x + CHAR_MEDIUM_W > ST7789_WIDTH || y + CHAR_MEDIUM_H > ST7789_HEIGHT) return;
    const uint8_t *font = font5x7[c - 32];

    // 渲染到 DMA 安全 buffer
    for (int i = 0; i < CHAR_MEDIUM_W * CHAR_MEDIUM_H; i++) {
        ((uint16_t*)s_char_buf)[i] = bg;
    }

    for (int row = 0; row < 7; row++) {
        uint8_t col_bits = 0;
        for (int col = 0; col < 5; col++) {
            col_bits |= ((font[col] >> row) & 0x01) << col;
        }
        for (int scale_y = 0; scale_y < 2; scale_y++) {
            int dy = row * 2 + scale_y;
            for (int px = 0; px < 6; px++) {
                uint8_t src_col = px / 2;
                s_char_buf[dy * CHAR_MEDIUM_W + px] = (col_bits >> src_col) & 0x01 ? fg : bg;
            }
            s_char_buf[dy * CHAR_MEDIUM_W + 6] = (col_bits >> 3) & 0x01 ? fg : bg;
            s_char_buf[dy * CHAR_MEDIUM_W + 7] = (col_bits >> 4) & 0x01 ? fg : bg;
            s_char_buf[dy * CHAR_MEDIUM_W + 8] = bg;
        }
    }

    st7789_set_window(x, y, x + CHAR_MEDIUM_W - 1, y + CHAR_MEDIUM_H - 1);
    st7789_data_dma((const uint8_t *)s_char_buf, CHAR_MEDIUM_W * CHAR_MEDIUM_H * 2);
}

#define CHAR_BIG_W    12
#define CHAR_BIG_H    16

static void draw_char_big(uint16_t x, uint16_t y, char c, uint16_t fg, uint16_t bg)
{
    if (c < 32 || c > 126) c = '?';
    if (x + CHAR_BIG_W > ST7789_WIDTH || y + CHAR_BIG_H > ST7789_HEIGHT) return;
    const uint8_t *font = font5x7[c - 32];

    // 渲染到 DMA 安全 buffer（12×16 = 192像素 = 384字节）
    for (int i = 0; i < CHAR_BIG_W * CHAR_BIG_H; i++) {
        s_char_buf[i] = bg;
    }

    for (int row = 0; row < 7; row++) {
        for (int scale_y = 0; scale_y < 2; scale_y++) {
            int dy = row * 2 + scale_y;
            for (int col = 0; col < 5; col++) {
                uint16_t pixel_color = (font[col] >> row) & 0x01 ? fg : bg;
                s_char_buf[dy * CHAR_BIG_W + col * 2]     = pixel_color;
                s_char_buf[dy * CHAR_BIG_W + col * 2 + 1] = pixel_color;
            }
            // col 10,11 = 间距，已经是bg
        }
    }
    // row 14,15 = 底部间距，已经是bg

    st7789_set_window(x, y, x + CHAR_BIG_W - 1, y + CHAR_BIG_H - 1);
    st7789_data_dma((const uint8_t *)s_char_buf, CHAR_BIG_W * CHAR_BIG_H * 2);
}

// ======== 初始化 ========

esp_err_t st7789_init(spi_host_device_t host, gpio_num_t mosi, gpio_num_t sck, gpio_num_t cs,
                 gpio_num_t dc, gpio_num_t rst, gpio_num_t blk)
{
    dc_pin = dc; rst_pin = rst; blk_pin = blk;

    gpio_config_t io_conf = {
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = (1ULL << dc) | (1ULL << rst) | (1ULL << blk)
    };
    gpio_config(&io_conf);
    gpio_set_level(blk, 0);

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = mosi,
        .miso_io_num = -1,
        .sclk_io_num = sck,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = DMA_BUF_PIXELS * 2
    };
    esp_err_t ret = spi_bus_initialize(host, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) return ret;

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = 8 * 1000 * 1000,   // SPI时钟8MHz（2.4寸面板信号建立时间要求）
        .mode = 0,
        .spics_io_num = cs,
        .queue_size = 1
    };
    ret = spi_bus_add_device(host, &dev_cfg, &spi_dev);
    if (ret != ESP_OK) return ret;

    // 预分配 DMA 安全缓冲区（32字节对齐到cache line，确保cache flush完整）
    s_dma_buf = (uint16_t *)heap_caps_aligned_alloc(32, DMA_BUF_PIXELS * 2,
        MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (!s_dma_buf) return ESP_ERR_NO_MEM;

    s_char_buf = (uint16_t *)heap_caps_aligned_alloc(32, CHAR_BUF_PIXELS * 2,
        MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (!s_char_buf) { free(s_dma_buf); return ESP_ERR_NO_MEM; }

    // 硬件复位
    gpio_set_level(rst, 0);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(rst, 1);
    vTaskDelay(pdMS_TO_TICKS(100));

    // 初始化命令序列（拷贝到SRAM，避免DMA读Flash）
    const uint8_t init_cmds_flash[] = {
        0x11, 0xFF, 120,
        0x36, 1, 0x00,  // MADCTL: RGB（ESP32小端→ST7789大端，颜色值已预交换）
        0x3A, 1, 0x55,
        0xB2, 5, 0x0C, 0x0C, 0x00, 0x33, 0x33,
        0xB7, 1, 0x35,
        0xBB, 1, 0x19,
        0xC0, 1, 0x2C,
        0xC2, 1, 0x01,
        0xC3, 1, 0x12,
        0xC4, 1, 0x20,
        0xC6, 1, 0x0F,
        0xD0, 2, 0xA4, 0xA1,
        0xE0, 14, 0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
        0xE1, 14, 0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
        0x20, 0xFF, 10,   // INVOFF — 2.4" panel needs inversion OFF
        0x29, 0xFF, 10,
        0x00
    };

    uint8_t init_sram[sizeof(init_cmds_flash)];
    memcpy(init_sram, init_cmds_flash, sizeof(init_cmds_flash));

    for (int i = 0; init_sram[i];) {
        st7789_cmd(init_sram[i++]);
        uint8_t n = init_sram[i++];
        if (n == 0xFF) {
            vTaskDelay(pdMS_TO_TICKS(init_sram[i++]));
        } else {
            st7789_data(&init_sram[i], n);
            i += n;
        }
    }
    return ESP_OK;
}

// ======== 绘图函数 ========

void st7789_fill_rect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color)
{
    st7789_set_window(x, y, x + w - 1, y + h - 1);

    // 填充 DMA buffer
    for (uint32_t i = 0; i < DMA_BUF_PIXELS; i++) s_dma_buf[i] = color;

    uint32_t total = (uint32_t)w * h;
    while (total > 0) {
        uint32_t n = (total > DMA_BUF_PIXELS) ? DMA_BUF_PIXELS : total;
        st7789_data_dma((const uint8_t *)s_dma_buf, n * 2);
        total -= n;
    }
}

void st7789_clear(uint16_t color)
{
    st7789_fill_rect(0, 0, ST7789_WIDTH, ST7789_HEIGHT, color);
}

void st7789_draw_string(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color)
{
    while (*str) {
        draw_char_small(x, y, *str++, fg_color, bg_color);
        x += CHAR_SMALL_W;
        if (x + CHAR_SMALL_W > ST7789_WIDTH) break;
    }
}

void st7789_draw_string_medium(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color)
{
    while (*str) {
        draw_char_medium(x, y, *str++, fg_color, bg_color);
        x += CHAR_MEDIUM_W;
        if (x + CHAR_MEDIUM_W > ST7789_WIDTH) break;
    }
}

void st7789_draw_string_big(uint16_t x, uint16_t y, const char *str, uint16_t fg_color, uint16_t bg_color)
{
    while (*str) {
        draw_char_big(x, y, *str++, fg_color, bg_color);
        x += CHAR_BIG_W;
        if (x + CHAR_BIG_W > ST7789_WIDTH) break;
    }
}

void st7789_draw_number_big(uint16_t x, uint16_t y, int num, uint16_t fg_color, uint16_t bg_color)
{
    char buf[12];
    snprintf(buf, sizeof(buf), "%d", num);
    st7789_draw_string_big(x, y, buf, fg_color, bg_color);
}

void st7789_draw_line(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1, uint16_t color)
{
    // 水平线：一次fill_rect完成，避免逐像素SPI开销
    if (y0 == y1) {
        uint16_t lx = (x0 < x1) ? x0 : x1;
        uint16_t w = ((x0 > x1) ? x0 : x1) - lx + 1;
        st7789_fill_rect(lx, y0, w, 1, color);
        return;
    }
    // 垂直线
    if (x0 == x1) {
        uint16_t ly = (y0 < y1) ? y0 : y1;
        uint16_t h = ((y0 > y1) ? y0 : y1) - ly + 1;
        st7789_fill_rect(x0, ly, 1, h, color);
        return;
    }
    // 斜线：只能逐像素
    int dx = abs((int)x1 - (int)x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs((int)y1 - (int)y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    while (1) {
        draw_pixel(x0, y0, color);
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

void st7789_draw_rect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color)
{
    st7789_draw_line(x, y, x + w - 1, y, color);
    st7789_draw_line(x + w - 1, y, x + w - 1, y + h - 1, color);
    st7789_draw_line(x, y + h - 1, x + w - 1, y + h - 1, color);
    st7789_draw_line(x, y, x, y + h - 1, color);
}

void st7789_backlight_set(uint8_t on)
{
    gpio_set_level(blk_pin, on ? 1 : 0);
}
