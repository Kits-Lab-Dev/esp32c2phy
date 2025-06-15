#include "esp_private/periph_ctrl.h"

esp_err_t bt_start(void);
void bt_stop(void);
bool bt_running(void);

esp_err_t bt_rx_process(uint8_t *data, uint16_t len);
esp_err_t bt_init(void);
