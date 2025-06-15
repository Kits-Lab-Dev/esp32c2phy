#include "unistd.h"
#include "string.h"
#include "spi_driver.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_bt.h"
#include "esp_log.h"
#include "soc/lldesc.h"
#include "bt.h"

#include "ble_hci_trans.h"

#define BT_RX_QUEUE_ENABLED 1

#if (BT_RX_QUEUE_ENABLED)
static QueueHandle_t bt_queue;
#endif

bool bt_running(void)
{
	return esp_bt_controller_get_status() > ESP_BT_CONTROLLER_STATUS_INITED;
}

static void controller_rcv_pkt_ready(void)
{

}

static int host_rcv_pkt(uint8_t *data, uint16_t len)
{
    p_spi_buf buf;
    buf.data = malloc(len);
    memcpy(buf.data, data, len);
    buf.len = len;
    buf.type = ESP_BT;
    buf.eb = 0;
    buf.free_data_fn = free;
    int ret = ESP_OK;
    if (spi_write(&buf) != ESP_OK)
    {
        free(buf.data);
        ret = ESP_FAIL;
    }
	return ret;
}

static esp_vhci_host_callback_t vhci_host_cb = {
	.notify_host_send_available = controller_rcv_pkt_ready,
	.notify_host_recv = host_rcv_pkt
};

esp_err_t IRAM_ATTR bt_rx_process(uint8_t *data, uint16_t len)
{
    if (!bt_running())
    {
        return ESP_FAIL;
    }

#if (BT_RX_QUEUE_ENABLED)
    p_spi_buf buf;
    buf.data = malloc(len);
    if (!buf.data)
        return ESP_FAIL;

    memcpy(buf.data, data, len);

    buf.len = len;
    buf.free_data_fn = free;
    if (xQueueSend(bt_queue, &buf, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGE("BT", "Queue send failed");
        buf.free_data_fn(buf.data);
        return ESP_FAIL;
    }
    return ESP_OK;
#else

bt_send_packet(data, len);

    return ESP_OK;
#endif
}

#if (BT_RX_QUEUE_ENABLED)

static void IRAM_ATTR bt_task_rx(void *)
{
    p_spi_buf buf;
    for (;;)
    {
        if (xQueueReceive(bt_queue, &buf, portMAX_DELAY) == pdTRUE)
        {
            if (bt_running())
            {
                // bt_send_packet(buf.data, buf.len);
                esp_vhci_host_send_packet(buf.data, buf.len);
            }
            if (buf.free_data_fn)
            {
                buf.free_data_fn(buf.data);
            }
        }
    }
}
#endif


esp_err_t bt_start(void)
{
	if (bt_running()) {
		return 0;
	}

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK( esp_bt_controller_init(&bt_cfg) );
	ESP_ERROR_CHECK( esp_bt_controller_enable(ESP_BT_MODE_BLE));

	esp_err_t ret = ESP_OK;

	ret = esp_vhci_host_register_callback(&vhci_host_cb);
	if (ret != ESP_OK) {
		return ret;
	}
	return ESP_OK;
}

void bt_stop(void)
{
	if (!bt_running())
		return;

	esp_bt_controller_disable();
	esp_bt_controller_deinit();
}

esp_err_t bt_init(void)
{
#if (BT_RX_QUEUE_ENABLED)
    bt_queue = xQueueCreate(2, sizeof(p_spi_buf));
    return xTaskCreate(bt_task_rx, "bt_task_rx", 1024, NULL, 2, NULL) == pdTRUE ? ESP_OK : ESP_FAIL;
#else
    return ESP_OK;
#endif
}