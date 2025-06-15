#ifndef __SPI_WIFI_CONTROL_H
#define __SPI_WIFI_CONTROL_H

#include "wifi.h"
#include "bt.h"
#include "spi_driver.h"

#define mem_free(x) \
  {                 \
    if (x)          \
    {               \
      free(x);      \
      x = NULL;     \
    }               \
  }

#define SSID_LENGTH 33
#define PASSWORD_LENGTH 64
#define MAC_LEN 6
#define BSSID_LENGTH MAC_LEN
#define VENDOR_OUI_BUF 3

#define CONTROL_DATA_LEN (SPI_BUF_DATA_LEN - sizeof(CtrlMsgId) - sizeof(uint16_t) - sizeof(data_type) - sizeof(uint32_t))

#define MIN_TX_POWER 8
#define MAX_TX_POWER 84

typedef enum __attribute__((packed))
{
  MsgId_Invalid = 0,
  /*
   ** Request Msgs *
   */
  Req_Base = 10,
  Req_GetMACAddress,
  Req_SetMACAddress,
  Req_GetWifiMode,
  Req_SetWifiMode,
  Req_GetAPScanList,
  Req_GetAPConfig,
  Req_ConnectAP,
  Req_DisconnectAP,
  Req_GetSoftAPConfig,
  Req_SetSoftAPVendorSpecificIE,
  Req_StartSoftAP,
  Req_GetSoftAPConnectedSTAList,
  Req_StopSoftAP,
  Req_SetPowerSaveMode,
  Req_GetPowerSaveMode,
  Req_OTABegin,
  Req_OTAWrite,
  Req_OTAEnd,
  Req_SetWifiMaxTxPower,
  Req_GetWifiCurrTxPower,
  Req_ConfigHeartbeat,
  Req_EnableDisable,
  Req_GetFwVersion,
  /*
   * Add new control path command response before Req_Max
   * and update Req_Max
   */
  Req_Max,
  /*
   ** Response Msgs *
   */
  Resp_Base = 50,
  Resp_GetMACAddress,
  Resp_SetMACAddress,
  Resp_GetWifiMode,
  Resp_SetWifiMode,
  Resp_GetAPScanList,
  Resp_GetAPConfig,
  Resp_ConnectAP,
  Resp_DisconnectAP,
  Resp_GetSoftAPConfig,
  Resp_SetSoftAPVendorSpecificIE,
  Resp_StartSoftAP,
  Resp_GetSoftAPConnectedSTAList,
  Resp_StopSoftAP,
  Resp_SetPowerSaveMode,
  Resp_GetPowerSaveMode,
  Resp_OTABegin,
  Resp_OTAWrite,
  Resp_OTAEnd,
  Resp_SetWifiMaxTxPower,
  Resp_GetWifiCurrTxPower,
  Resp_ConfigHeartbeat,
  Resp_EnableDisable,
  Resp_GetFwVersion,
  /*
   * Add new control path command response before Resp_Max
   * and update Resp_Max
   */
  Resp_Max,
  /*
   ** Event Msgs *
   */
  Event_Base = 100,
  Event_ESPInit,
  Event_Heartbeat,
  Event_StationDisconnectFromAP,
  Event_StationDisconnectFromESPSoftAP,
  Event_StationConnectedToAP,
  Event_StationConnectedToESPSoftAP,
  /*
   * Add new control path command notification before Event_Max
   * and update Event_Max
   */
  Event_Max
} CtrlMsgId;

typedef enum __attribute__((packed))
{
  AuthOpen = 0,
  AuthWEP = 1,
  AuthWPA_PSK = 2,
  AuthWPA2_PSK = 3,
  AuthWPA_WPA2_PSK = 4,
  AuthWPA2_ENTERPRISE = 5,
  AuthWPA3_PSK = 6,
  AuthWPA2_WPA3_PSK = 7
} wifiAuthMode;

typedef struct __attribute__((packed))
{
  CtrlMsgId id;
  data_type type;
  uint16_t len;
  uint32_t queue;
} ControlMsg;

typedef struct
{
  CtrlMsgId id;
  data_type type;
  uint16_t len;
  uint32_t queue;
  uint8_t *data;
  void (*free_data_fn)(void *p);
} pControlMsg;

typedef struct __attribute__((packed))
{
  uint8_t ssid[SSID_LENGTH];
  uint8_t pwd[PASSWORD_LENGTH];
  wifiAuthMode auth_mode;
  uint8_t chnl;
  uint8_t max_conn;
  uint8_t ssid_hidden;
  uint8_t bw;
} wifiSoftAPConfig;

typedef struct __attribute__((packed))
{
  uint8_t bssid[BSSID_LENGTH]; /**< MAC address of AP */
  uint8_t ssid[SSID_LENGTH];   /**< SSID of AP */
  uint8_t chnl;                /**< channel of AP */
  int8_t rssi;                 /**< signal strength of AP. Note that in some rare cases where signal strength is very strong, rssi values can be slightly positive */
  uint8_t authmode;            /**< authmode of AP */
  uint32_t phy_bits;
  char country_code[3]; /**< country code string */
  uint8_t schan;        /**< start channel */
  uint8_t nchan;        /**< total channel number */
  int8_t max_tx_power;  /**< This field is used for getting WiFi maximum transmitting power, call esp_wifi_set_max_tx_power to set the maximum transmitting power. */

} wifiAPConfig;

typedef struct __attribute__((packed))
{
  uint8_t ssid[SSID_LENGTH];
  uint8_t bssid[BSSID_LENGTH];
  uint8_t chnl;
  int8_t rssi;
} wifiAPrecord;

typedef struct __attribute__((packed))
{
  uint8_t ssid[SSID_LENGTH];
  uint8_t bssid[BSSID_LENGTH];
  uint8_t password[PASSWORD_LENGTH];
  bool bssid_set;
  bool is_wpa3_supported;
  int32_t listen_interval;
} wifiConnRecord;

typedef struct __attribute__((packed))
{
  uint8_t ssid[SSID_LENGTH];
  uint8_t bssid[BSSID_LENGTH];
  uint8_t channel;  /**< channel of connected AP*/
  uint8_t authmode; /**< authentication mode used by AP*/
  uint16_t aid;     /**< authentication id assigned by the connected AP */
  int8_t rssi;
} wifiEventSTAConnected;

typedef struct __attribute__((packed))
{
  uint8_t ssid[SSID_LENGTH];
  uint8_t bssid[BSSID_LENGTH];
  uint8_t reason; /**< reason of disconnection */
  int8_t rssi;    /**< rssi of disconnection */
} wifiEventSTADisconnected;

typedef struct __attribute__((packed))
{
  uint8_t mac[MAC_LEN]; /**< MAC address of the station connected to Soft-AP */
  uint8_t aid;          /**< the aid that soft-AP gives to the station connected to  */
  bool is_mesh_child;   /**< flag to identify mesh child */
} wifiEventAPSTAConnected;

typedef struct __attribute__((packed))
{
  uint8_t mac[MAC_LEN]; /**< MAC address of the station disconnects to soft-AP */
  uint8_t aid;          /**< the aid that soft-AP gave to the station disconnects to  */
  bool is_mesh_child;   /**< flag to identify mesh child */
  uint16_t reason;      /**< reason of disconnection */
} wifiEventAPSTADisconnected;

typedef enum __attribute__((packed))
{
  Beacon = 0,
  Probe_req = 1,
  Probe_resp = 2,
  Assoc_req = 3,
  Assoc_resp = 4
} VendorIEType;

typedef enum __attribute__((packed))
{
  IEID_ID_0 = 0,
  IEID_ID_1 = 1
} VendorIEID;

typedef struct __attribute__((packed))
{
  bool enable;
  VendorIEType IEType;
  VendorIEID IEID;
  uint8_t element_id;      /**< Should be set to WIFI_VENDOR_IE_ELEMENT_ID (0xDD) */
  uint8_t length;          /**< Length of all bytes in the element data following this field. Minimum 4. */
  uint8_t vendor_oui[3];   /**< Vendor identifier (OUI). */
  uint8_t vendor_oui_type; /**< Vendor-specific OUI type. */
} vendorIEdata;

typedef struct __attribute__((packed))
{
  uint8_t mac[MAC_LEN];
  int8_t rssi;
  uint32_t phy_bits;
} wifiConnectedStantion;

typedef enum __attribute__((packed))
{
  ftWifi = 1,
  ftBluetooth = 2
} feature;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define WIFI_NO_AP_FOUND_BIT BIT2
#define WIFI_WRONG_PASSWORD_BIT BIT3
#define WIFI_HOST_REQUEST_BIT BIT4

#define TIMEOUT_IN_MIN (60 * TIMEOUT_IN_SEC)
#define TIMEOUT_IN_HOUR (60 * TIMEOUT_IN_MIN)
#if WIFI_DUALBAND_SUPPORT
#define STA_MODE_TIMEOUT (15 * TIMEOUT_IN_SEC)
#else
#define STA_MODE_TIMEOUT (5 * TIMEOUT_IN_SEC)
#endif
#define RESTART_TIMEOUT (5 * TIMEOUT_IN_SEC)

esp_err_t control_rx_process(uint8_t *data, uint16_t len);
void esp_update_ap_mac(void);

esp_err_t control_init(void);

#endif