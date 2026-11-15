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

#ifndef FREERDP_CHANNEL_MONITORCFG_CLIENT_MONITORCFG_H
#define FREERDP_CHANNEL_MONITORCFG_CLIENT_MONITORCFG_H

#include <freerdp/channels/monitorcfg.h>
#include <freerdp/channels/disp.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct s_monitorcfg_client_context MonitorCfgClientContext;

	/** @brief Send a new monitor layout to the server.
	 *
	 *  Takes the same layout as the Display Control channel. While the channel is not
	 *  confirmed yet the layout is kept and sent after the confirm.
	 *
	 *  @return CHANNEL_RC_OK on success, CHANNEL_RC_NOT_OPEN when the server never opened the
	 *  channel, another Win32 error code otherwise
	 */
	typedef UINT (*pcMonitorCfgSendMonitorLayout)(MonitorCfgClientContext* context,
	                                              UINT32 NumMonitors,
	                                              const DISPLAY_CONTROL_MONITOR_LAYOUT* Monitors);

	struct s_monitorcfg_client_context
	{
		void* handle;
		void* custom;

		WINPR_ATTR_NODISCARD pcMonitorCfgSendMonitorLayout SendMonitorLayout;
	};

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_MONITORCFG_CLIENT_MONITORCFG_H */
