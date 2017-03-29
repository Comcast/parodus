/**
 * @file config.h
 *
 * @description This file contains configuration details of parodus
 *
 * Copyright (c) 2015  Comcast
 */
 
#ifndef _CONFIG_H_ 
#define _CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/

/* WRP CRUD Model Macros */
#define HW_MODELNAME                                	"hw-model"
#define HW_SERIALNUMBER                                 "hw-serial-number"
#define HW_MANUFACTURER                                 "hw-manufacturer"
#define HW_DEVICEMAC                                  	"hw-mac"
#define HW_LAST_REBOOT_REASON                           "hw-last-reboot-reason"
#define FIRMWARE_NAME                                  	"fw-name"
#define BOOT_TIME                                  	"boot-time"
#define LAST_RECONNECT_REASON                           "webpa-last-reconnect-reason"
#define WEBPA_PROTOCOL                                  "webpa-protocol"
#define WEBPA_INTERFACE                                 "webpa-inteface-used"
#define WEBPA_UUID                                      "webpa-uuid"
#define WEBPA_URL                                       "webpa-url"
#define WEBPA_PING_TIMEOUT                              "webpa-ping-timeout"
#define WEBPA_BACKOFF_MAX                               "webpa-backoff-max"

#define WEBPA_PROTOCOL_VALUE 				"WebPA-1.6"
#define WEBPA_PATH_URL                                    "/api/v2/device"
#define JWT_ALGORITHM									"jwt-algo"
#define	JWT_KEY											"jwt-key"
/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/

typedef struct
{
    char hw_model[64];
    char hw_serial_number[64];
    char hw_manufacturer[64];
    char hw_mac[64];
    char hw_last_reboot_reason[64];
    char fw_name[64];
    unsigned int boot_time;
    unsigned int webpa_ping_timeout;
    char webpa_url[124];
    char webpa_path_url[124];
    unsigned int webpa_backoff_max;
    char webpa_interface_used[16];
    char webpa_protocol[16];
    char webpa_uuid[64];
    unsigned int secureFlag;
	char jwt_algo[124];
    char jwt_key[124];
} ParodusCfg;

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/

void loadParodusCfg(ParodusCfg * config,ParodusCfg *cfg);

void parseCommandLine(int argc,char **argv,ParodusCfg * cfg);

// Accessor for the global config structure.
ParodusCfg *get_parodus_cfg(void);
void set_parodus_cfg(ParodusCfg *);

#ifdef __cplusplus
}
#endif

#endif
