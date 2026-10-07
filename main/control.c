#include "control.h"
#include "esp_err.h"
#include "string.h"
#include "spi_driver.h"
#include "esp_log.h"

extern volatile uint8_t station_connected;
extern volatile uint8_t softap_started;
volatile bool wifi_config_process = false;

static bool scan_done = true;

static EventGroupHandle_t wifi_event_group;
static bool event_registered = false;

static QueueHandle_t control_queue;

static void ap_scan_list_event_handler(void *arg, esp_event_base_t event_base,
                                       int32_t event_id, void *event_data);

static void send_event(CtrlMsgId id, uint32_t queue, int interface, void *data, uint32_t len)
{
    p_spi_buf buf;

    int l = len > 0 ? len : 0;
    buf.data = (uint8_t *)heap_caps_malloc(sizeof(ControlMsg) + l, MALLOC_CAP_8BIT); //pvPortMalloc(sizeof(ControlMsg) + l);
    buf.len = sizeof(ControlMsg) + l;
    buf.type = ESP_CONTROL;
    buf.eb = NULL;
    buf.free_data_fn = free; //vPortFree;
    ControlMsg *msg = (ControlMsg *)buf.data;
    msg->type = interface;
    msg->id = id;
    msg->len = l;
    msg->queue = queue;
    if (len > 0)
        memcpy(buf.data + sizeof(ControlMsg), data, len);

    spi_write(&buf);
}

/* event handler for station connect/disconnect to/from AP */
static void station_event_handler(void *arg, esp_event_base_t event_base,
                                  int32_t event_id, void *event_data)
{
    if (event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        wifi_event_sta_disconnected_t *disconnected_event =
            (wifi_event_sta_disconnected_t *)event_data;

        station_connected = false;
        wifi_config_process = false;

        if ((WIFI_HOST_REQUEST_BIT & xEventGroupGetBits(wifi_event_group)) != WIFI_HOST_REQUEST_BIT)
        {
            wifiEventSTADisconnected ed;
            ed.reason = disconnected_event->reason;
            ed.rssi = disconnected_event->rssi;
            memcpy(ed.ssid, disconnected_event->ssid, disconnected_event->ssid_len);
            ed.ssid[disconnected_event->ssid_len] = 0;
            memcpy(ed.bssid, disconnected_event->bssid, BSSID_LENGTH);

            send_event(Event_StationDisconnectFromAP, 0, ESP_STA, &ed, sizeof(wifiEventSTADisconnected));
        }
    }
    else if (event_id == WIFI_EVENT_STA_CONNECTED)
    {
        if ((WIFI_HOST_REQUEST_BIT & xEventGroupGetBits(wifi_event_group)) != WIFI_HOST_REQUEST_BIT)
        {
            station_connected = true;
            wifi_config_process = false;
            esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, (wifi_rxcb_t)wlan_sta_rx_callback);
            wifi_event_sta_connected_t *connected_event = (wifi_event_sta_connected_t *)event_data;
            wifiEventSTAConnected cd;

            memcpy(cd.ssid, connected_event->ssid, connected_event->ssid_len);
            cd.ssid[connected_event->ssid_len] = 0;
            memcpy(cd.bssid, connected_event->bssid, BSSID_LENGTH);
            cd.channel = connected_event->channel;
            cd.aid = connected_event->aid;
            cd.authmode = connected_event->authmode;
            send_event(Event_StationConnectedToAP, 0, ESP_STA, &cd, sizeof(wifiEventSTAConnected));
        }
    }
}

static void softap_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_AP, (wifi_rxcb_t)wlan_ap_rx_callback);
        wifi_event_ap_staconnected_t *connected_event = (wifi_event_ap_staconnected_t *)event_data;
        wifiEventAPSTAConnected cd;

        memcpy(cd.mac, connected_event->mac, MAC_LEN);
        cd.aid = connected_event->aid;
        cd.is_mesh_child = connected_event->is_mesh_child;
        send_event(Event_StationConnectedToESPSoftAP, 0, ESP_AP, &cd, sizeof(wifiEventAPSTAConnected));
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t *disconnected_event =
            (wifi_event_ap_stadisconnected_t *)event_data;
        wifiEventAPSTADisconnected ed;
        ed.reason = disconnected_event->reason;
        ed.is_mesh_child = disconnected_event->is_mesh_child;
        ed.aid = disconnected_event->aid;
        memcpy(ed.mac, disconnected_event->mac, MAC_LEN);
        send_event(Event_StationConnectedToESPSoftAP, 0, ESP_AP, &ed, sizeof(wifiEventAPSTADisconnected));
    }
    else if (event_id == WIFI_EVENT_AP_START)
    {
        softap_started = true;
        wifi_config_process = false;
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_AP, (wifi_rxcb_t)wlan_ap_rx_callback);
        int ret = 0;
        send_event(Resp_StartSoftAP, *((uint32_t *)arg), ESP_AP, &ret, 4);
    }
    else if (event_id == WIFI_EVENT_AP_STOP)
    {
        softap_started = false;
        wifi_config_process = false;
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_AP, NULL);
        int ret = 0;
        send_event(Resp_StopSoftAP, *((uint32_t *)arg), ESP_AP, &ret, 4);
    }
}

/* register station connect/disconnect events */
static void station_event_register(void)
{
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_STA_CONNECTED, &station_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_STA_DISCONNECTED, &station_event_handler, NULL));
}

/* register softap start/stop, station connect/disconnect events */
static void softap_event_register(uint32_t queue)
{
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_AP_START, &softap_event_handler, &queue));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_AP_STOP, &softap_event_handler, &queue));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_AP_STACONNECTED, &softap_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               WIFI_EVENT_AP_STADISCONNECTED, &softap_event_handler, NULL));
}

/* unregister softap start/stop, station connect/disconnect events */
static void softap_event_unregister(void)
{
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,
                                                 WIFI_EVENT_AP_START, &softap_event_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,
                                                 WIFI_EVENT_AP_STOP, &softap_event_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,
                                                 WIFI_EVENT_AP_STACONNECTED, &softap_event_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,
                                                 WIFI_EVENT_AP_STADISCONNECTED, &softap_event_handler));
}

static void ap_scan_list_event_unregister(void)
{
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,
                                                 WIFI_EVENT_SCAN_DONE, &ap_scan_list_event_handler));
}

static esp_err_t req_get_mac_address(uint32_t queue, int interface)
{
    esp_err_t ret = ESP_OK;
    uint8_t mac[MAC_LEN] = {0};
    ret = esp_wifi_get_mac(interface, mac);
    send_event(Resp_GetMACAddress, queue, interface, mac, MAC_LEN);
    return ret;
}

static esp_err_t req_set_mac_address(uint32_t queue, int interface, uint8_t *mac, uint16_t len)
{
    if (len != MAC_LEN)
        return ESP_FAIL;

    esp_err_t ret = ESP_OK;
    ret = esp_wifi_set_mac(interface, mac);
    send_event(Resp_SetMACAddress, queue, interface, &ret, 4);
    return ret;
}

static esp_err_t req_get_wifi_mode(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    wifi_mode_t mode = WIFI_MODE_MAX;
    ret = esp_wifi_get_mode(&mode);
    send_event(Resp_GetWifiMode, queue, 0, &mode, 1);
    return ret;
}

static esp_err_t req_set_wifi_mode(uint32_t queue, uint8_t *mode, uint16_t len)
{
    if (len != 1)
        return ESP_FAIL;

    esp_err_t ret = ESP_OK;
    ret = esp_wifi_set_mode(*mode);
    send_event(Resp_SetWifiMode, queue, 0, &ret, 4);
    return ret;
}

static void ap_scan_list_event_handler(void *arg, esp_event_base_t event_base,
                                       int32_t event_id, void *event_data)
{
    esp_err_t ret = ESP_OK;
    uint16_t ap_count = 0;
    wifi_ap_record_t *ap_info = NULL;
    wifiAPrecord *recs = NULL;

    if ((event_base == WIFI_EVENT) && (event_id == WIFI_EVENT_SCAN_DONE))
    {
        ret = esp_wifi_scan_get_ap_num(&ap_count);
        if (ret || !ap_count)
        {
            send_event(Resp_GetAPScanList, *((uint32_t *)arg), ESP_STA, &ret, 4);
            return;
        }

        ap_info = (wifi_ap_record_t *)calloc(ap_count, sizeof(wifi_ap_record_t));
        recs = (wifiAPrecord *)calloc(ap_count, sizeof(wifiAPrecord));
        ret = esp_wifi_scan_get_ap_records(&ap_count, ap_info);
        if (ret)
        {
            scan_done = true;
            mem_free(ap_info);
            mem_free(recs);
            ap_scan_list_event_unregister();
            send_event(Resp_GetAPScanList, *((uint32_t *)arg), ESP_STA, &ret, 4);
            return;
        }

        if (ap_count > CONTROL_DATA_LEN / sizeof(wifiAPrecord))
            ap_count = CONTROL_DATA_LEN / sizeof(wifiAPrecord);

        for (int i = 0; i < ap_count; i++)
        {
            memcpy(recs[i].ssid, ap_info[i].ssid, SSID_LENGTH);
            memcpy(recs[i].bssid, ap_info[i].bssid, BSSID_LENGTH);
            recs[i].chnl = ap_info[i].primary;
            recs[i].rssi = ap_info[i].rssi;
        }
        send_event(Resp_GetAPScanList, *((uint32_t *)arg), ESP_STA, recs, ap_count * sizeof(wifiAPrecord));
        mem_free(ap_info);
        mem_free(recs);
        ap_scan_list_event_unregister();
        scan_done = true;
    }
}

static esp_err_t req_get_ap_scan_list(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    if (!scan_done)
    {
        ret = ESP_FAIL;
        send_event(Resp_GetAPScanList, queue, ESP_STA, &ret, 4);
        return ret;
    }

    wifi_mode_t mode = 0;
    wifi_scan_config_t scanConf = {
        .show_hidden = true};

    ret = esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &ap_scan_list_event_handler, &queue);
    if (ret)
    {
        send_event(Resp_GetAPScanList, queue, ESP_STA, &ret, 4);
        return ret;
    }
    ret = esp_wifi_get_mode(&mode);
    if (ret)
    {
        ap_scan_list_event_unregister();
        send_event(Resp_GetAPScanList, queue, ESP_STA, &ret, 4);
        return ret;
    }

    if ((softap_started) &&
        ((mode != WIFI_MODE_STA) && (mode != WIFI_MODE_NULL)))
    {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    }
    else
    {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    }

    ret = esp_wifi_scan_start(&scanConf, true);
    if (ret)
    {
        ap_scan_list_event_unregister();
        send_event(Resp_GetAPScanList, queue, ESP_STA, &ret, 4);
    }
    return ret;
}

static esp_err_t req_get_ap_config(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    wifi_ap_record_t ap_info;
    wifiAPConfig rec = {0};

    if (!station_connected)
    {
        ret = ESP_ERR_WIFI_NOT_CONNECT;
        send_event(Resp_GetAPConfig, queue, ESP_STA, &ret, 4);
        return ESP_ERR_WIFI_NOT_CONNECT;
    }

    ret = esp_wifi_sta_get_ap_info(&ap_info);
    if (ret)
    {
        send_event(Resp_GetAPConfig, queue, ESP_STA, &ret, 4);
        return ret;
    }

    memcpy(rec.ssid, ap_info.ssid, SSID_LENGTH);
    memcpy(rec.bssid, ap_info.bssid, BSSID_LENGTH);
    memcpy(rec.country_code, ap_info.country.cc, 3);
    rec.rssi = ap_info.rssi;
    rec.chnl = ap_info.primary;
    rec.authmode = ap_info.authmode;
    rec.schan = ap_info.country.schan;
    rec.nchan = ap_info.country.nchan;
    rec.max_tx_power = ap_info.country.max_tx_power;
    rec.phy_bits = ap_info.phy_11b |
                   ((ap_info.phy_11g & 0x01) << 1) |
                   ((ap_info.phy_11n & 0x01) << 2) |
                   ((ap_info.phy_lr & 0x01) << 3) |
                   ((ap_info.phy_11a & 0x01) << 4) |
                   ((ap_info.phy_11ac & 0x01) << 5) |
                   ((ap_info.phy_11ax & 0x01) << 6) |
                   ((ap_info.wps & 0x01) << 7) |
                   ((ap_info.ftm_responder & 0x01) << 8) |
                   ((ap_info.ftm_initiator & 0x01) << 9) |
                   ((ap_info.reserved) << 10);

    send_event(Resp_GetAPConfig, queue, ESP_STA, &rec, sizeof(wifiAPConfig));
    return ret;
}

static esp_err_t req_connect_ap(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_OK;
    wifi_config_t *wifi_cfg = NULL;
    wifiConnRecord *rec;
    if (len != sizeof(wifiConnRecord))
    {
        ret = ESP_FAIL;
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        return ESP_FAIL;
    }
    if (station_connected)
    {
        ret = esp_wifi_disconnect();
        if (ret)
        {
            send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
            return ESP_ERR_WIFI_NOT_CONNECT;
        }
    }

    if (!event_registered)
    {
        wifi_event_group = xEventGroupCreate();
        event_registered = true;
        station_event_register();
    }
    int timeout = 1000;
    while (wifi_config_process && timeout > 0)
    {
        timeout--;
        vTaskDelay(1);
    }
    if (wifi_config_process)
    {
        ret = ESP_FAIL;
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        return ret;
    }

    wifi_config_process = true;

    if (softap_started)
    {
        ret = esp_wifi_set_mode(WIFI_MODE_APSTA); // softap+station mode set
    }
    else
    {
        ret = esp_wifi_set_mode(WIFI_MODE_STA); // station mode set
    }

    wifi_cfg = (wifi_config_t *)calloc(1, sizeof(wifi_config_t));
    if (!wifi_cfg)
    {
        ret = ESP_FAIL;
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        return ret;
    }
    rec = (wifiConnRecord *)data;

    memcpy((char *)wifi_cfg->sta.ssid, rec->ssid, min(sizeof(wifi_cfg->sta.ssid), strlen((char *)rec->ssid) + 1));
    memcpy((char *)wifi_cfg->sta.password, rec->password, min(sizeof(wifi_cfg->sta.password), strlen((char *)rec->password) + 1));
    if (rec->bssid_set)
    {
        memcpy(wifi_cfg->sta.bssid, rec->bssid, BSSID_LENGTH);
    }
    wifi_cfg->sta.bssid_set = rec->bssid_set;
    if (rec->is_wpa3_supported)
    {
        wifi_cfg->sta.pmf_cfg.capable = true;
        wifi_cfg->sta.pmf_cfg.required = false;
    }
    if (rec->listen_interval >= 0)
    {
        wifi_cfg->sta.listen_interval = rec->listen_interval;
    }
    wifi_cfg->sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wifi_cfg->sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    ret = esp_wifi_set_config(ESP_IF_WIFI_STA, wifi_cfg);
    if (ret == ESP_ERR_WIFI_PASSWORD)
    {
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        mem_free(wifi_cfg);
        return ret;
    }
    else if (ret)
    {
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        mem_free(wifi_cfg);
        return ret;
    }

    ret = esp_wifi_connect();
    if (ret)
    {
        send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
        mem_free(wifi_cfg);
        return ret;
    }

    send_event(Resp_ConnectAP, queue, ESP_STA, &ret, 4);
    return ESP_OK;
}

static esp_err_t req_disconnect_ap(uint32_t queue)
{
    int ret = ESP_ERR_WIFI_NOT_CONNECT;
    if (!station_connected)
    {
        send_event(Resp_DisconnectAP, queue, ESP_STA, &ret, 4);
        return ret;
    }
    ret = esp_wifi_disconnect();
    send_event(Resp_DisconnectAP, queue, ESP_STA, &ret, 4);
    return ret;
}

static esp_err_t req_get_softap_config(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    wifiSoftAPConfig credentials = {0};
    wifi_config_t get_conf = {0};
    wifi_bandwidth_t get_bw = 0;
    ret = esp_wifi_get_config(ESP_IF_WIFI_AP, &get_conf);
    if (ret)
    {
        send_event(Resp_GetSoftAPConfig, queue, ESP_AP, &ret, 4);
        return ret;
    }
    ret = esp_wifi_get_bandwidth(ESP_IF_WIFI_AP, &get_bw);
    if (ret)
    {
        send_event(Resp_GetSoftAPConfig, queue, ESP_AP, &ret, 4);
        return ret;
    }

    if (strlen((char *)get_conf.ap.ssid))
    {
        memcpy((char *)credentials.ssid, (char *)&get_conf.ap.ssid,
               min(sizeof(credentials.ssid), strlen((char *)&get_conf.ap.ssid) + 1));
    }
    if (strlen((char *)get_conf.ap.password))
    {
        memcpy((char *)credentials.pwd, (char *)&get_conf.ap.password,
               min(sizeof(credentials.pwd), strlen((char *)&get_conf.ap.password) + 1));
    }
    credentials.chnl = get_conf.ap.channel;
    credentials.max_conn = get_conf.ap.max_connection;
    credentials.auth_mode = get_conf.ap.authmode;
    credentials.ssid_hidden = get_conf.ap.ssid_hidden;
    send_event(Resp_GetSoftAPConfig, queue, ESP_AP, &credentials, sizeof(wifiSoftAPConfig));
    return ESP_OK;
}

static esp_err_t req_set_softap_vender_specific_ie(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_OK;
    if (len != sizeof(vendorIEdata))
    {
        ret = ESP_FAIL;
        send_event(Resp_SetSoftAPVendorSpecificIE, queue, ESP_AP, &ret, 4);
        return ESP_FAIL;
    }

    vendorIEdata *v_data = (vendorIEdata *)data;
    vendor_ie_data_t vd;

    vd.element_id = v_data->element_id;
    vd.length = v_data->length;
    vd.vendor_oui_type = v_data->vendor_oui_type;
    memcpy(vd.vendor_oui, v_data->vendor_oui, sizeof(vd.vendor_oui));
    ret = esp_wifi_set_vendor_ie(v_data->enable, v_data->IEType, v_data->IEID, &vd);

    send_event(Resp_SetSoftAPVendorSpecificIE, queue, ESP_AP, &ret, sizeof(esp_err_t));
    return ret;
}

static esp_err_t req_start_softap(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_OK;
    wifi_config_t wifi_config = {0};
    wifiSoftAPConfig *cfg = (wifiSoftAPConfig *)data;

    int timeout = 1000;
    while (wifi_config_process && timeout > 0)
    {
        timeout--;
        vTaskDelay(1);
    }
    if (wifi_config_process)
    {
        ret = ESP_FAIL;
        send_event(Resp_StartSoftAP, queue, ESP_STA, &ret, 4);
        return ret;
    }

    wifi_config_process = true;

    if (station_connected)
    {
        ret = esp_wifi_set_mode(WIFI_MODE_APSTA);
    }
    else
    {
        ret = esp_wifi_set_mode(WIFI_MODE_AP);
    }
    if (ret)
    {
        goto err;
    }

    wifi_config.ap.authmode = cfg->auth_mode;
    if (wifi_config.ap.authmode != WIFI_AUTH_OPEN)
    {
        memcpy(wifi_config.ap.password, cfg->pwd, PASSWORD_LENGTH);
    }
    if (strlen((const char *)cfg->ssid) > 0)
    {
        memcpy(wifi_config.ap.ssid, cfg->ssid, SSID_LENGTH - 1);
        wifi_config.ap.ssid_len = strlen((const char *)cfg->ssid);
    }
    wifi_config.ap.channel = cfg->chnl;
    wifi_config.ap.max_connection = cfg->max_conn;
    wifi_config.ap.ssid_hidden = cfg->ssid_hidden;

    ret = esp_wifi_set_bandwidth(ESP_IF_WIFI_AP, cfg->bw);
    if (ret)
    {
        goto err;
    }

    if (softap_started)
    {
        softap_event_unregister();
        softap_started = false;
    }
    softap_event_register(queue);
    softap_started = true;

    ret = esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config);
    if (ret)
    {
        goto err;
    }

    return ESP_OK;

err:
    if (softap_started)
    {
        softap_event_unregister();
        softap_started = false;
    }
    send_event(Resp_StartSoftAP, queue, ESP_AP, &ret, 4);
    return ESP_FAIL;
}

static esp_err_t get_connected_sta_list(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    wifi_mode_t mode = 0;
    wifiConnectedStantion *results = NULL;
    wifi_sta_list_t stas_info;

    ret = esp_wifi_get_mode(&mode);
    if (ret)
    {
        goto err;
    }

    if ((mode == WIFI_MODE_STA) || (mode == WIFI_MODE_NULL))
    {
        ret = ESP_FAIL;
        goto err;
    }
    if (!softap_started)
    {
        ret = ESP_FAIL;
        goto err;
    }

    ret = esp_wifi_ap_get_sta_list(&stas_info);
    if (ret)
    {
        goto err;
    }
    if (!stas_info.num)
    {
        send_event(Resp_GetSoftAPConnectedSTAList, queue, ESP_AP, &ret, 4);
        return ESP_OK;
    }
    int count = stas_info.num;
    if (count > CONTROL_DATA_LEN / sizeof(wifiConnectedStantion))
        count = CONTROL_DATA_LEN / sizeof(wifiConnectedStantion);

    results = (wifiConnectedStantion *)calloc(count, sizeof(wifiConnectedStantion));
    if (!results)
    {
        ret = ESP_FAIL;
        goto err;
    }

    for (int i = 0; i < count; i++)
    {
        memcpy(results[i].mac, stas_info.sta[i].mac, MAC_LEN);
        results[i].rssi = stas_info.sta[i].rssi;
        results[i].phy_bits = stas_info.sta[i].phy_11b |
                              ((stas_info.sta[i].phy_11g & 0x01) << 1) |
                              ((stas_info.sta[i].phy_11n & 0x01) << 2) |
                              ((stas_info.sta[i].phy_lr & 0x01) << 3) |
                              ((stas_info.sta[i].phy_11a & 0x01) << 4) |
                              ((stas_info.sta[i].phy_11ac & 0x01) << 5) |
                              ((stas_info.sta[i].phy_11ax & 0x01) << 6) |
                              ((stas_info.sta[i].is_mesh_child & 0x01) << 7) |
                              ((stas_info.sta[i].reserved) << 8);
    }
    send_event(Resp_GetSoftAPConnectedSTAList, queue, ESP_AP, results, count * sizeof(wifiConnectedStantion));
    mem_free(results);
    return ESP_OK;
err:
    send_event(Resp_GetSoftAPConnectedSTAList, queue, ESP_AP, &ret, 4);
    return ESP_FAIL;
}

static esp_err_t req_stop_softap(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    wifi_mode_t mode = 0;

    if (!softap_started)
    {
        goto err;
    }

    ret = esp_wifi_get_mode(&mode);
    if (ret)
    {
        goto err;
    }

    if (mode == WIFI_MODE_AP)
    {
        ret = esp_wifi_set_mode(WIFI_MODE_NULL);
    }
    else if (mode == WIFI_MODE_APSTA)
    {
        ret = esp_wifi_set_mode(WIFI_MODE_STA);
    }
    if (ret)
    {
        goto err;
    }

    softap_event_unregister();
    softap_started = false;
    send_event(Resp_StopSoftAP, queue, ESP_AP, &ret, 4);
    return ESP_OK;

err:
    send_event(Resp_StopSoftAP, queue, ESP_AP, &ret, 4);
    return ESP_FAIL;
}

static esp_err_t req_set_power_save_mode(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_FAIL;
    uint8_t mode = data[0];

    if ((mode >= WIFI_PS_NONE) && (mode <= WIFI_PS_MAX_MODEM))
    {
        ret = esp_wifi_set_ps(mode);
        if (ret)
        {
            send_event(Resp_SetPowerSaveMode, queue, ESP_AP, &ret, 4);
            goto err;
        }
    }
    else
    {
        goto err;
    }
    send_event(Resp_SetPowerSaveMode, queue, ESP_AP, &ret, 4);
    return ESP_OK;

err:
    send_event(Resp_SetPowerSaveMode, queue, ESP_AP, &ret, 4);
    return ESP_FAIL;
}

static esp_err_t req_get_power_save_mode(uint32_t queue)
{
    esp_err_t ret = ESP_FAIL;
    uint8_t mode = 0;

    ret = esp_wifi_get_ps((wifi_ps_type_t *)&mode);
    if (ret)
    {
        send_event(Resp_GetPowerSaveMode, queue, ESP_AP, &ret, 4);
        goto err;
    }

    send_event(Resp_GetPowerSaveMode, queue, ESP_AP, &mode, 1);
    return ESP_OK;

err:
    send_event(Resp_GetPowerSaveMode, queue, ESP_AP, &ret, 4);
    return ret;
}

static esp_err_t req_set_wifi_max_tx_power(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_OK;
    int8_t tx_power = data[0];
    if ((tx_power > MAX_TX_POWER) || (tx_power < MIN_TX_POWER))
    {
        goto err;
    }

    ret = esp_wifi_set_max_tx_power(tx_power);
    if (ret)
    {
        goto err;
    }
    send_event(Resp_SetWifiMaxTxPower, queue, ESP_STA, &ret, 4);
    return ESP_OK;
err:
    send_event(Resp_SetWifiMaxTxPower, queue, ESP_STA, &ret, 4);
    return ret;
}

static esp_err_t req_get_wifi_curr_tx_power(uint32_t queue)
{
    esp_err_t ret = ESP_OK;
    int8_t tx_power;
    ret = esp_wifi_get_max_tx_power(&tx_power);
    if (ret)
    {
        goto err;
    }
    send_event(Resp_GetWifiCurrTxPower, queue, ESP_STA, &tx_power, 1);
    return ESP_OK;
err:
    send_event(Resp_GetWifiCurrTxPower, queue, ESP_STA, &ret, 4);
    return ret;
}

extern const char fw_version[];

static esp_err_t req_get_fw_version(uint32_t queue)
{
    char *v = malloc(strlen(fw_version) + 1);
    memset(v, 0, strlen(fw_version) + 1);
    memcpy(v, fw_version, strlen(fw_version));
    send_event(Resp_GetFwVersion, queue, ESP_STA, v, strlen(fw_version) + 1);
    mem_free(v);
    return ESP_OK;
}

static esp_err_t req_enable_disable(uint32_t queue, uint8_t *data, uint16_t len)
{
    esp_err_t ret = ESP_OK;
    wifi_mode_t mode = 0;
    feature f = (feature)data[0];
    uint8_t en = data[1];

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_get_mode(&mode);
    switch (f)
    {
    case ftWifi:
        if (en)
        {
            if (ret == ESP_ERR_WIFI_NOT_INIT)
            {
                esp_wifi_init(&cfg);
                esp_wifi_set_mode(WIFI_MODE_NULL);
                esp_wifi_start();
            }
        }
        else
        {
            esp_wifi_stop();
            esp_wifi_deinit();
        }
        break;

    case ftBluetooth:
#ifdef CONFIG_BT_ENABLED
        if (en)
        {
            //bluetooth не включается если не включен wifi
            if (ret == ESP_ERR_WIFI_NOT_INIT)
            {
                esp_wifi_init(&cfg);
                esp_wifi_set_mode(WIFI_MODE_NULL);
                esp_wifi_start();
            }
            bt_start();
        }
        else
        {
            bt_stop();
        }
#else
        if (en)
            ret = ESP_FAIL;
#endif
        break;

    default:
        goto err;
    }

    send_event(Resp_EnableDisable, queue, ESP_STA, &ret, 4);
    return ESP_OK;
err:
    send_event(Resp_EnableDisable, queue, ESP_STA, &ret, 4);
    return ret;
}

esp_err_t IRAM_ATTR control_rx_process(uint8_t *data, uint16_t len)
{
    if (len != SPI_BUF_DATA_LEN)
        return ESP_FAIL;

    esp_err_t ret = ESP_OK;
    ControlMsg *msg = (ControlMsg *)data;
    uint8_t *msgData = data + sizeof(ControlMsg);
    pControlMsg m = {
        .id = msg->id,
        .len = msg->len,
        .queue = msg->queue,
        .type = msg->type,
        .data = (uint8_t *)heap_caps_malloc(msg->len, MALLOC_CAP_8BIT),//pvPortMalloc(msg->len),
        .free_data_fn = free //vPortFree
        };
    for (int i = 0; i != msg->len; i++)
    {
        m.data[i] = msgData[i];
    }
    ret = xQueueSend(control_queue, &m, portMAX_DELAY) == pdTRUE;
    return ret;
}

static void control_task(void *)
{
    pControlMsg msg;
    for (;;)
    {
        if (xQueueReceive(control_queue, &msg, portMAX_DELAY) == pdTRUE)
        {
            switch (msg.id)
            {
            case Req_GetMACAddress:
                req_get_mac_address(msg.queue, msg.type);
                break;
            case Req_SetMACAddress:
                req_set_mac_address(msg.queue, msg.type, msg.data, msg.len);
                break;
            case Req_GetWifiMode:
                req_get_wifi_mode(msg.queue);
                break;
            case Req_SetWifiMode:
                req_set_wifi_mode(msg.queue, msg.data, msg.len);
                break;
            case Req_GetAPScanList:
                req_get_ap_scan_list(msg.queue);
                break;
            case Req_GetAPConfig:
                req_get_ap_config(msg.queue);
                break;
            case Req_ConnectAP:
                req_connect_ap(msg.queue, msg.data, msg.len);
                break;
            case Req_DisconnectAP:
                req_disconnect_ap(msg.queue);
                break;
            case Req_GetSoftAPConfig:
                req_get_softap_config(msg.queue);
                break;
            case Req_SetSoftAPVendorSpecificIE:
                req_set_softap_vender_specific_ie(msg.queue, msg.data, msg.len);
                break;
            case Req_StartSoftAP:
                req_start_softap(msg.queue, msg.data, msg.len);
                break;
            case Req_GetSoftAPConnectedSTAList:
                get_connected_sta_list(msg.queue);
                break;
            case Req_StopSoftAP:
                req_stop_softap(msg.queue);
                break;
            case Req_SetPowerSaveMode:
                req_set_power_save_mode(msg.queue, msg.data, msg.len);
                break;
            case Req_GetPowerSaveMode:
                req_get_power_save_mode(msg.queue);
                break;
            case Req_SetWifiMaxTxPower:
                req_set_wifi_max_tx_power(msg.queue, msg.data, msg.len);
                break;
            case Req_GetWifiCurrTxPower:
                req_get_wifi_curr_tx_power(msg.queue);
                break;
            case Req_GetFwVersion:
                req_get_fw_version(msg.queue);
                break;
            case Req_EnableDisable:
                req_enable_disable(msg.queue, msg.data, msg.len);
                break;
            default:
                break;
            }

            if (msg.free_data_fn)
                msg.free_data_fn(msg.data);
        }
    }
}

esp_err_t control_init(void)
{
    control_queue = xQueueCreate(2, sizeof(pControlMsg));
    assert(control_queue);
    return xTaskCreate(control_task, "control_task", 2048, NULL, 2, NULL) == pdTRUE ? ESP_OK : ESP_FAIL;
}