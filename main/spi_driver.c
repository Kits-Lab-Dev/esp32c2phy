#include "sdkconfig.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "soc/gpio_reg.h"
#include "spi_driver.h"
#include "soc/gpio_reg.h"
#include "wifi.h"
#include "bt.h"
#include "control.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <unistd.h>

WORD_ALIGNED_ATTR uint8_t sendbuf[SPI_BUF_LEN] = {0};
WORD_ALIGNED_ATTR uint8_t recvbuf[SPI_BUF_LEN] = {0};

static QueueHandle_t spi_tx_queue;

#define SPI_BITS_PER_WORD 8
#define SPI_MODE_0 0
#define SPI_MODE_1 1
#define SPI_MODE_2 2
#define SPI_MODE_3 3

#if defined CONFIG_IDF_TARGET_ESP32C2

#define ESP_SPI_CONTROLLER SPI2_HOST
#define GPIO_MOSI 7
#define GPIO_MISO 2
#define GPIO_SCLK 6
#define GPIO_CS 10
#define DMA_CHAN SPI_DMA_CH_AUTO

#define GPIO_HS 3
#define GPIO_DR 4
#endif

#define GPIO_MASK_DATA_READY (1 << GPIO_DR)
#define GPIO_MASK_HANDSHAKE (1 << GPIO_HS)
#define GPIO_MASK_LED (1 << LED_PIN)

#define SPI_RX_QUEUE_SIZE 4
#define SPI_RX_TOTAL_QUEUE_SIZE SPI_RX_QUEUE_SIZE

#define SPI_TX_QUEUE_SIZE 4
#define SPI_TX_TOTAL_QUEUE_SIZE SPI_TX_QUEUE_SIZE
#define SPI_MEMPOOL_NUM_BLOCKS ((SPI_TX_TOTAL_QUEUE_SIZE + SPI_DRIVER_QUEUE_SIZE * 2 + SPI_RX_TOTAL_QUEUE_SIZE))

static inline void set_handshake_gpio(void)
{
    WRITE_PERI_REG(GPIO_OUT_W1TS_REG, GPIO_MASK_HANDSHAKE);
}

static inline void reset_handshake_gpio(void)
{
    WRITE_PERI_REG(GPIO_OUT_W1TC_REG, GPIO_MASK_HANDSHAKE);
}

static inline void set_dataready_gpio(void)
{
    WRITE_PERI_REG(GPIO_OUT_W1TS_REG, GPIO_MASK_DATA_READY);
}

static inline void reset_dataready_gpio(void)
{
    WRITE_PERI_REG(GPIO_OUT_W1TC_REG, GPIO_MASK_DATA_READY);
}

static void IRAM_ATTR gpio_disable_hs_isr_handler(void *arg)
{
    // reset_dataready_gpio();
    reset_handshake_gpio();
}

static void IRAM_ATTR spi_post_setup_cb(spi_slave_transaction_t *trans)
{
    set_handshake_gpio();
}

static void IRAM_ATTR spi_post_trans_cb(spi_slave_transaction_t *trans)
{
    reset_handshake_gpio();
}

static void IRAM_ATTR led_on(void)
{
    WRITE_PERI_REG(GPIO_OUT_W1TS_REG, GPIO_MASK_LED);
}

static esp_err_t IRAM_ATTR process_rx(spi_buf *buf)
{
    if (buf->len > SPI_BUF_LEN || buf->len == 0 || buf->type > ESP_CONTROL){
        return ESP_FAIL;
    }
    led_on();

    switch (buf->type)
    {
    case ESP_STA:
    case ESP_AP:
        return wifi_rx_process(buf->type, buf->data, buf->len);
    case ESP_BT:
        return bt_rx_process(buf->data, buf->len);
        break;
    case ESP_CONTROL:
        return control_rx_process(buf->data, buf->len);
        break;

    default:
        break;
    }

    return ESP_OK;
}

static void IRAM_ATTR spi_transaction_task(void *pvParameters)
{
    spi_slave_transaction_t spi_trans;
    spi_slave_transaction_t *rcv_trans;
    esp_err_t ret = ESP_OK;
    p_spi_buf tx;
    spi_buf *buf;

    for (;;)
    {
        spi_trans.rx_buffer = recvbuf;
        spi_trans.length = SPI_BUF_LEN * SPI_BITS_PER_WORD;
        ret = xQueueReceive(spi_tx_queue, &tx, 0);
        if (ret == pdTRUE)
        {
            buf = (spi_buf *)sendbuf;
            // buf->len = tx.len;
            // buf->type = tx.type;
            ((uint32_t*)buf)[0] = *((uint32_t*)&tx);
            // memcpy(buf->data, tx.data, tx.len);
            uint32_t l = (tx.len / 4) + 1;
            uint32_t *dst = (uint32_t *)buf->data;
            uint32_t *src = (uint32_t *)tx.data;
            while (l)
            {
                *(dst++) = *(src++);
                l--;
            }
            if (tx.free_data_fn)
            {
                if (tx.eb)
                    tx.free_data_fn(tx.eb); // wifi packet (esp_wifi_internal_free_rx_buffer)
                else
                    tx.free_data_fn(tx.data); // other (vPortFree)
            }
            spi_trans.tx_buffer = buf;
            ret = spi_slave_queue_trans(ESP_SPI_CONTROLLER, &spi_trans, portMAX_DELAY);
            set_dataready_gpio();
        }
        else
        {
            reset_dataready_gpio();
            ((uint32_t *)sendbuf)[0] = 0; // memset
            spi_trans.tx_buffer = sendbuf;
            ret = spi_slave_queue_trans(ESP_SPI_CONTROLLER, &spi_trans, portMAX_DELAY);
        }

        ret = spi_slave_get_trans_result(ESP_SPI_CONTROLLER, &rcv_trans, portMAX_DELAY);
        if (ret == ESP_OK && rcv_trans->rx_buffer == recvbuf)
        {
            buf = (spi_buf *)rcv_trans->rx_buffer;
            ret = process_rx(buf);
        }
    }
}

esp_err_t IRAM_ATTR spi_write(p_spi_buf *buf)
{
    led_on();

    esp_err_t ret = xQueueSend(spi_tx_queue, buf, portMAX_DELAY) == pdTRUE ? ESP_OK : ESP_FAIL;
    set_dataready_gpio();

    return ret;
}

esp_err_t spi_init()
{
    esp_err_t ret;

    spi_bus_config_t buscfg = {
        .mosi_io_num = GPIO_MOSI,
        .miso_io_num = GPIO_MISO,
        .sclk_io_num = GPIO_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = SPI_BUF_LEN};

    spi_slave_interface_config_t slvcfg = {
        .mode = SPI_MODE_2,
        .spics_io_num = GPIO_CS,
        .queue_size = SPI_DRIVER_QUEUE_SIZE,
        .flags = 0,
        .post_setup_cb = spi_post_setup_cb,
        .post_trans_cb = spi_post_trans_cb};

    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = GPIO_MASK_HANDSHAKE};

    gpio_config_t io_data_ready_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = GPIO_MASK_DATA_READY};

    gpio_config(&io_conf);
    gpio_config(&io_data_ready_conf);
    reset_handshake_gpio();
    reset_dataready_gpio();

    gpio_set_pull_mode(GPIO_HS, GPIO_PULLDOWN_ONLY);
    gpio_set_pull_mode(GPIO_DR, GPIO_PULLDOWN_ONLY);
    gpio_set_pull_mode(GPIO_MOSI, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_SCLK, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ONLY);

    gpio_reset_pin(GPIO_CS);

    gpio_config_t slave_disable_hs_pin_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = 1,
        .pin_bit_mask = (1 << GPIO_CS)};

    gpio_config(&slave_disable_hs_pin_conf);
    gpio_set_intr_type(GPIO_CS, GPIO_INTR_NEGEDGE);
    gpio_install_isr_service(0);
    gpio_isr_handler_add(GPIO_CS, gpio_disable_hs_isr_handler, NULL);

    ret = spi_slave_initialize(ESP_SPI_CONTROLLER, &buscfg, &slvcfg, DMA_CHAN);

    // gpio_set_drive_capability(CONFIG_ESP_SPI_GPIO_HANDSHAKE, GPIO_DRIVE_CAP_3);
    // gpio_set_drive_capability(CONFIG_ESP_SPI_GPIO_DATA_READY, GPIO_DRIVE_CAP_3);
    gpio_set_drive_capability(GPIO_SCLK, GPIO_DRIVE_CAP_3);
    gpio_set_drive_capability(GPIO_MISO, GPIO_DRIVE_CAP_3);
    gpio_set_pull_mode(GPIO_MISO, GPIO_PULLDOWN_ONLY);

    spi_tx_queue = xQueueCreate(4, sizeof(p_spi_buf));
    assert(spi_tx_queue);

    assert(xTaskCreate(spi_transaction_task, "spi_transaction_task", 1024, NULL, 22, NULL) == pdTRUE);
    vTaskDelay(10);
    return ret;
}
