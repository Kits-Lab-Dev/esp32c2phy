#include "wifi.h"
#include "unistd.h"
#include "string.h"
#include "spi_driver.h"

volatile uint8_t station_connected;
volatile uint8_t softap_started;

#define WIFI_RX_QUEUE_ENABLED 1

#if (WIFI_RX_QUEUE_ENABLED)

static void wifi_task_rx(void *);
static QueueHandle_t wifi_queue;

#define WIFI_TASK_STACK_SIZE 1024

static StackType_t wifiStack[WIFI_TASK_STACK_SIZE];
static StaticTask_t wifiTaskBuffer;

#define WIFI_QUEUE_LENGTH    4
uint8_t wifiQueueBuffer[ WIFI_QUEUE_LENGTH * sizeof(p_spi_buf) ];
static StaticQueue_t wifiStaticQueue;

#endif

esp_err_t wifi_init(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK(esp_event_loop_create_default());

	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

	// ESP_ERROR_CHECK(esp_wifi_start());
	esp_wifi_deinit();

#if (WIFI_RX_QUEUE_ENABLED)
	wifi_queue = xQueueCreateStatic(WIFI_QUEUE_LENGTH, sizeof(p_spi_buf), wifiQueueBuffer, &wifiStaticQueue);
	xTaskCreateStatic(wifi_task_rx, "wifi_task_rx", WIFI_TASK_STACK_SIZE, NULL, 21, wifiStack, &wifiTaskBuffer);
#endif

	return 0;
}

#if (WIFI_RX_QUEUE_ENABLED)

static void IRAM_ATTR wifi_task_rx(void *)
{
	p_spi_buf buf;
	for (;;)
	{
		if (xQueueReceive(wifi_queue, &buf, portMAX_DELAY) == pdTRUE)
		{
			int retry = 15;
			int ret = 0;
			do
			{
				ret = esp_wifi_internal_tx(buf.type, buf.data, buf.len);
				retry--;

				if (ret)
				{
					if (retry % 3)
						usleep(100);
					else
						vTaskDelay(1);
				}
			} while (ret && retry);

			if (buf.free_data_fn)
			{
				buf.free_data_fn(buf.data);
			}
		}
	}
}

#endif

esp_err_t IRAM_ATTR wifi_rx_process(int interface, uint8_t *data, uint16_t len)
{
	int ret = 0;

#if (WIFI_RX_QUEUE_ENABLED)

	p_spi_buf buf;
	buf.type = interface;
	buf.data = heap_caps_malloc(len, MALLOC_CAP_8BIT); //pvPortMalloc(len + 4);
	if (!buf.data)
		return ESP_FAIL;

	memcpy(buf.data, data, len);
	
	buf.len = len;
	buf.free_data_fn = free; //vPortFree;
	ret = xQueueSend(wifi_queue, &buf, portMAX_DELAY) == pdTRUE;

#else

	int retry = 6;
	do
	{
		if (interface == ESP_STA && station_connected)
			ret = esp_wifi_internal_tx(ESP_STA, (void *)data, len);
		else if (interface == ESP_AP && softap_started)
			ret = esp_wifi_internal_tx(ESP_AP, (void *)data, len);
		else
			return ESP_FAIL;

		retry--;

		if (ret)
		{
			if (retry % 3)
				usleep(600);
			else
				vTaskDelay(1);
		}

	} while (ret && retry);

#endif

	return ret;
}

static void send_to_host(int interface, uint8_t* data, uint16_t len)
{
p_spi_buf buf;
	buf.data = (uint8_t *)heap_caps_malloc(len, MALLOC_CAP_8BIT);
	memcpy(buf.data, data, len);
	buf.len = len;
	buf.type = interface;
	buf.eb = 0;
	buf.free_data_fn = free;
	spi_write(&buf);
}

esp_err_t IRAM_ATTR wlan_sta_rx_callback(void *buffer, uint16_t len, void *eb)
{
	esp_err_t ret = ESP_OK;

	if (!buffer || !eb)
	{
		if (eb)
		{
			esp_wifi_internal_free_rx_buffer(eb);
		}
		return ESP_OK;
	}
	send_to_host(ESP_STA, (uint8_t*)buffer, len);
	esp_wifi_internal_free_rx_buffer(eb);
	return ret;
}

esp_err_t IRAM_ATTR wlan_ap_rx_callback(void *buffer, uint16_t len, void *eb)
{
	esp_err_t ret = ESP_OK;

	if (!buffer || !eb)
	{
		if (eb)
		{
			esp_wifi_internal_free_rx_buffer(eb);
		}
		return ESP_OK;
	}
	send_to_host(ESP_AP, (uint8_t*)buffer, len);
	esp_wifi_internal_free_rx_buffer(eb);
	return ret;
}