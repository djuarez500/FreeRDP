/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Monitor Configuration Virtual Channel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_MONITORCFG_H
#define FREERDP_CHANNEL_MONITORCFG_H

#include <freerdp/api.h>
#include <freerdp/types.h>

#define MONITORCFG_CHANNEL_NAME "monitorcfg"
#define MONITORCFG_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::MonitorConfiguration"

/* Every PDU starts with UINT32 length (whole PDU) and UINT32 cmdId. */
#define MONITORCFG_CMDID_CAPS_ADVERTISE 1        /* client -> server */
#define MONITORCFG_CMDID_CAPS_CONFIRM 2          /* server -> client */
#define MONITORCFG_CMDID_SET_CONFIGURATION 3     /* client -> server */
#define MONITORCFG_CMDID_NOTIFY_CONFIGURATION 4  /* server -> client */
#define MONITORCFG_CMDID_REQUEST_CONFIGURATION 5 /* server -> client */

/* Capability set: { UINT32 signature, UINT32 version, UINT32 length (12) } */
#define MONITORCFG_CAPS_SIGNATURE 0x53504143 /* 'CAPS' */
#define MONITORCFG_CAPS_VERSION_1 0x00000001
#define MONITORCFG_CAPS_VERSION_1_1 0x00010100

/* SET: UINT32 sequence, UINT32 changed count (0 = the full layout), then monitor records
 * { UINT32 length, UINT32 action, BYTE id[16], blocks } with blocks { UINT32 length, UINT32 type }.
 */
#define MONITORCFG_ACTION_ADD 1
#define MONITORCFG_ACTION_UPDATE 2
#define MONITORCFG_ACTION_DELETE 3

/* Block types. DISPLAY_MODE: x, y, width, height, flags, orientation, refresh numerator,
 * refresh denominator, vsync divider, colour mode. SCALE: desktop and device scale (percent).
 * PHYSICAL_SIZE: width and height in millimetres. */
#define MONITORCFG_BLOCK_DISPLAY_MODE 2
#define MONITORCFG_BLOCK_SCALE 3
#define MONITORCFG_BLOCK_PHYSICAL_SIZE 4

/* DISPLAY_MODE flags: the size is the client window, not a real monitor */
#define MONITORCFG_DISPLAY_MODE_FLAG_WINDOW 0x00000001

#endif /* FREERDP_CHANNEL_MONITORCFG_H */
