#include "wifi.h"
#include "unistd.h"
#include "string.h"
#include "spi_driver.h"
#include "esp_rom_sys.h"

volatile uint8_t station_connected;
volatile uint8_t softap_started;

#define WIFI_RX_QUEUE_ENABLED 0

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

	// до wifi_init очереди нет, а без подключения кадр некуда отправить
	if (!wifi_queue || (interface == ESP_STA && !station_connected) || (interface == ESP_AP && !softap_started))
		return ESP_FAIL;
	p_spi_buf buf;
	buf.type = interface;
	buf.eb = NULL;
	buf.data = heap_caps_malloc(len, MALLOC_CAP_8BIT);
	if (!buf.data)
		return ESP_FAIL;

	memcpy(buf.data, data, len);
	
	buf.len = len;
	buf.free_data_fn = free; //vPortFree;
	ret = xQueueSend(wifi_queue, &buf, portMAX_DELAY) == pdTRUE;

#else

	// Без очереди и копии в куче: esp_wifi_internal_tx сам копирует кадр в буфер Wi-Fi.
	// Буферы заняты — короткое ожидание (STM32 тем временем ждёт handshake), потом по тику
	if (!((interface == ESP_STA && station_connected) || (interface == ESP_AP && softap_started)))
		return ESP_FAIL;
	for (int retry = 0; retry < 20; retry++)
	{
		ret = esp_wifi_internal_tx(interface, (void *)data, len);
		if (ret == ESP_OK)
			break;
		if (retry < 10)
			esp_rom_delay_us(50);
		else
			vTaskDelay(1);
	}

#endif

	return ret;
}

/* Буферы приёма Wi-Fi берутся из кучи, и пока кадры ждут отправки в SPI, она тает.
 * Ниже этого запаса кадр выбрасывается (TCP повторит и притормозит) — память
 * остаётся для BLE, точки доступа и управления */
#define RX_MIN_FREE_HEAP (10 * 1024)

/* Кадр из эфира уходит в SPI прямо в буфере Wi-Fi (eb), без копии в куче:
 * буфер освобождается после копирования в транзакцию SPI (spi_driver.c) */
static void IRAM_ATTR send_to_host(int interface, uint8_t *data, uint16_t len, void *eb)
{
	if (heap_caps_get_free_size(MALLOC_CAP_8BIT) < RX_MIN_FREE_HEAP)
	{
		esp_wifi_internal_free_rx_buffer(eb);
		return;
	}
	p_spi_buf buf;
	buf.data = data;
	buf.len = len;
	buf.type = interface;
	buf.eb = eb;
	buf.free_data_fn = esp_wifi_internal_free_rx_buffer;
	if (spi_write_nowait(&buf) != ESP_OK)
		esp_wifi_internal_free_rx_buffer(eb);
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
	send_to_host(ESP_STA, (uint8_t*)buffer, len, eb);
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
	send_to_host(ESP_AP, (uint8_t*)buffer, len, eb);
	return ret;
}