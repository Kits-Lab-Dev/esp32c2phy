#ifndef __SPI_DRIVER_H
#define __SPI_DRIVER_H

#include "esp_err.h"
#include "driver/gpio.h"
#include "driver/spi_slave.h"
#include "unistd.h"

#define LED_PIN 1

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

#define SPI_BUF_DATA_LEN (1600 - sizeof(uint16_t) - sizeof(data_type))
#define SPI_BUF_LEN (sizeof(spi_buf))
#define SPI_DRIVER_QUEUE_SIZE 3

#define CALLOC(x, y) calloc(x, y)
#define MEM_ALLOC(x) heap_caps_malloc(x, MALLOC_CAP_DMA)
#define FREE(x)       \
    do                \
    {                 \
        if (x)        \
        {             \
            free(x);  \
            x = NULL; \
        }             \
    } while (0);

typedef enum __attribute__((packed))
{
    ESP_STA,
    ESP_AP,
    ESP_BT,
    ESP_CONTROL,
    ESP_NONE = 0xFFFF
} data_type;

typedef struct __attribute__((packed))
{
    data_type type;
    uint16_t len;
    uint8_t data[SPI_BUF_DATA_LEN];
} spi_buf;
typedef struct __attribute__((packed))
{
    data_type type;
    uint16_t len;
    uint8_t *data;
    void* eb;
    void(*free_data_fn)(void* p);
} p_spi_buf;

esp_err_t spi_init();
esp_err_t spi_write(p_spi_buf *buf);

#endif