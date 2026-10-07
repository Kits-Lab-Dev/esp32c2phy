#ifndef __SPI_WIFI_H
#define __SPI_WIFI_H

#include "esp_private/wifi.h"

esp_err_t wifi_init(void);

esp_err_t wifi_rx_process(int interface, uint8_t *data, uint16_t len);
esp_err_t wlan_sta_rx_callback(void *buffer, uint16_t len, void *eb);
esp_err_t wlan_ap_rx_callback(void *buffer, uint16_t len, void *eb);

#endif