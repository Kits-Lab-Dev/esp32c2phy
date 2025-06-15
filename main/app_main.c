#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "spi_driver.h"
#include "esp_freertos_hooks.h"
#include "nvs_flash.h"
#include "wifi.h"
#include "control.h"
#include "driver/uart.h"
#include "bt.h"

const char fw_version[] = "ESP32C2-PHY 0.1";

uint8_t ap_mac[MAC_LEN] = {0};

uint32_t CPU_LOAD = 0;

void idle_task(void*)
{
    uint32_t LastTick = 0;
    // uint32_t count = 0;
    // uint32_t max_count = 0;

    for (;;)
    {
        // count++;
        // if ((xTaskGetTickCount() - LastTick) > 500)
        // {
        //     vTaskDelay(10);
        //     LastTick = xTaskGetTickCount();
        //     if (count > max_count)
        //         max_count = count + 1;
        //     CPU_LOAD = 1000 - (1000 * count / max_count);
        //     count = 0;
        //     fprintf(stdout, "CPU:%lu RAM:%d", CPU_LOAD, xPortGetFreeHeapSize());
        // }

        static uint32_t ticks;
        if (xTaskGetTickCount() - ticks > 1)
        {
            ticks = xTaskGetTickCount();
            gpio_set_level(LED_PIN, 0);
        }
    }
}

void esp_update_ap_mac(void)
{
    esp_wifi_get_mac(ESP_IF_WIFI_AP, ap_mac);
}

#define GPIO_OUTPUT_PIN_SEL ((1ULL << 18) | (1ULL << -1))
#define GPIO_INPUT_PIN_SEL ((1ULL << 5) | (1ULL << -1))

#include "freertos/portable.h"
// Main application
void app_main(void)
{
    esp_err_t ret;

    gpio_reset_pin(LED_PIN);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 1);

    ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(spi_init());
    ESP_ERROR_CHECK(control_init());
    ESP_ERROR_CHECK(wifi_init());
#ifdef CONFIG_BT_ENABLED
    ESP_ERROR_CHECK(bt_init());
#endif
    xTaskCreate(idle_task, "stats_idle_task", 1024, NULL, tskIDLE_PRIORITY, NULL);
}
