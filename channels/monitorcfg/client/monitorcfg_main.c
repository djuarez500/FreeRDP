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

/*
 * Servers that open this channel lay out the remote desktop from it: no graphics surface exists
 * until the client has sent its monitor layout, and every later layout (window resized, full
 * screen toggled) is sent here instead of over Display Control.
 *
 * Exchange, as seen between Windows servers and clients:
 *   client: caps advertise (versions 1 and 1.1) when the channel opens
 *   server: caps confirm with the selected version
 *   client: the full layout (SET, changed count 0), and again whenever it changes
 *   server: notify { UINT32 sequence, UINT32 result, INT32 left, top, right, bottom } per SET
 *   server: request (rare) -> the client sends the full layout again
 */

#include <freerdp/config.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/stream.h>
#include <winpr/synch.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/channels/log.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/monitorcfg.h>

#define TAG CHANNELS_TAG("monitorcfg.client")

#define MONITORCFG_MAX_MONITORS 16
#define MONITORCFG_RECORD_LENGTH (24 + 0x30 + 0x10 + 0x10)

typedef struct
{
	GENERIC_DYNVC_PLUGIN base;
	MonitorCfgClientContext* context;
	rdpSettings* settings;
	CRITICAL_SECTION lock;
	BOOL confirmed;
	UINT32 sequence;
	UINT32 numMonitors; /* the layout to send; 0 = take it from the settings */
	DISPLAY_CONTROL_MONITOR_LAYOUT monitors[MONITORCFG_MAX_MONITORS];
} MONITORCFG_PLUGIN;

/* A session shown in a window sends one monitor with the window size and a zero id. */
static BOOL monitorcfg_windowed(rdpSettings* settings)
{
	return !freerdp_settings_get_bool(settings, FreeRDP_Fullscreen) &&
	       !freerdp_settings_get_bool(settings, FreeRDP_UseMultimon);
}

static UINT32 monitorcfg_scale(UINT32 v)
{
	return (v >= 100 && v <= 500) ? v : 100;
}

/* The layout of the session as configured: the monitors in full screen / multi-monitor mode,
 * otherwise the desktop size. Caller holds the lock. */
static void monitorcfg_layout_from_settings(MONITORCFG_PLUGIN* plugin)
{
	rdpSettings* settings = plugin->settings;
	plugin->numMonitors = 0;

	const UINT32 count = freerdp_settings_get_uint32(settings, FreeRDP_MonitorCount);
	if (!monitorcfg_windowed(settings) && count > 0)
	{
		for (UINT32 x = 0; x < count && x < MONITORCFG_MAX_MONITORS; x++)
		{
			const rdpMonitor* m =
			    freerdp_settings_get_pointer_array(settings, FreeRDP_MonitorDefArray, x);
			if (!m)
				break;
			DISPLAY_CONTROL_MONITOR_LAYOUT* l = &plugin->monitors[plugin->numMonitors++];
			l->Flags = m->is_primary ? DISPLAY_CONTROL_MONITOR_PRIMARY : 0;
			l->Left = m->x;
			l->Top = m->y;
			l->Width = (UINT32)m->width;
			l->Height = (UINT32)m->height;
			l->PhysicalWidth = m->attributes.physicalWidth;
			l->PhysicalHeight = m->attributes.physicalHeight;
			l->Orientation = m->attributes.orientation;
			l->DesktopScaleFactor = m->attributes.desktopScaleFactor;
			l->DeviceScaleFactor = m->attributes.deviceScaleFactor;
		}
	}
	if (plugin->numMonitors == 0)
	{
		DISPLAY_CONTROL_MONITOR_LAYOUT* l = &plugin->monitors[plugin->numMonitors++];
		l->Flags = DISPLAY_CONTROL_MONITOR_PRIMARY;
		l->Left = 0;
		l->Top = 0;
		l->Width = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
		l->Height = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
		l->PhysicalWidth = 0;
		l->PhysicalHeight = 0;
		l->Orientation = freerdp_settings_get_uint16(settings, FreeRDP_DesktopOrientation);
		l->DesktopScaleFactor = freerdp_settings_get_uint32(settings, FreeRDP_DesktopScaleFactor);
		l->DeviceScaleFactor = freerdp_settings_get_uint32(settings, FreeRDP_DeviceScaleFactor);
	}
}

static UINT monitorcfg_write(GENERIC_CHANNEL_CALLBACK* callback, wStream* s)
{
	WINPR_ASSERT(callback);
	WINPR_ASSERT(callback->channel);
	WINPR_ASSERT(callback->channel->Write);

	const size_t length = Stream_GetPosition(s);
	if (length > UINT32_MAX)
		return ERROR_INVALID_DATA;
	Stream_ResetPosition(s);
	Stream_Write_UINT32(s, (UINT32)length);
	if (!Stream_SetPosition(s, length))
		return ERROR_INVALID_DATA;
	return callback->channel->Write(callback->channel, (UINT32)length, Stream_Buffer(s), nullptr);
}

static UINT monitorcfg_send_caps(GENERIC_CHANNEL_CALLBACK* callback)
{
	wStream* s = Stream_New(nullptr, 8 + 2 * 12);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;
	Stream_Write_UINT32(s, 0); /* length */
	Stream_Write_UINT32(s, MONITORCFG_CMDID_CAPS_ADVERTISE);
	const UINT32 versions[] = { MONITORCFG_CAPS_VERSION_1, MONITORCFG_CAPS_VERSION_1_1 };
	for (size_t x = 0; x < ARRAYSIZE(versions); x++)
	{
		Stream_Write_UINT32(s, MONITORCFG_CAPS_SIGNATURE);
		Stream_Write_UINT32(s, versions[x]);
		Stream_Write_UINT32(s, 12);
	}
	const UINT rc = monitorcfg_write(callback, s);
	Stream_Free(s, TRUE);
	return rc;
}

/* Sends the stored layout as a full SET. Caller holds the lock. */
static UINT monitorcfg_send_layout(MONITORCFG_PLUGIN* plugin, GENERIC_CHANNEL_CALLBACK* callback)
{
	WINPR_ASSERT(plugin);
	if (plugin->numMonitors == 0)
		monitorcfg_layout_from_settings(plugin);

	const BOOL windowed = monitorcfg_windowed(plugin->settings);
	wStream* s = Stream_New(nullptr, 16 + 1ull * plugin->numMonitors * MONITORCFG_RECORD_LENGTH);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;

	plugin->sequence++;
	Stream_Write_UINT32(s, 0); /* length */
	Stream_Write_UINT32(s, MONITORCFG_CMDID_SET_CONFIGURATION);
	Stream_Write_UINT32(s, plugin->sequence);
	Stream_Write_UINT32(s, 0); /* changed count: the full layout */

	for (UINT32 x = 0; x < plugin->numMonitors; x++)
	{
		const DISPLAY_CONTROL_MONITOR_LAYOUT* m = &plugin->monitors[x];
		const UINT32 width = (m->Width < 200) ? 200 : m->Width;
		const UINT32 height = (m->Height < 200) ? 200 : m->Height;

		Stream_Write_UINT32(s, MONITORCFG_RECORD_LENGTH);
		Stream_Write_UINT32(s, MONITORCFG_ACTION_ADD);
		/* monitor id: all zero for a window, otherwise any stable non-zero value */
		Stream_Write_UINT32(s, windowed ? 0 : x + 1);
		Stream_Write_UINT32(s, windowed ? 0 : 0x4746434D); /* 'MCFG' */
		Stream_Zero(s, 8);

		Stream_Write_UINT32(s, 0x30);
		Stream_Write_UINT32(s, MONITORCFG_BLOCK_DISPLAY_MODE);
		Stream_Write_INT32(s, m->Left);
		Stream_Write_INT32(s, m->Top);
		Stream_Write_UINT32(s, width);
		Stream_Write_UINT32(s, height);
		Stream_Write_UINT32(s, windowed ? MONITORCFG_DISPLAY_MODE_FLAG_WINDOW : 0);
		Stream_Write_UINT32(s, m->Orientation);
		Stream_Write_UINT32(s, 60); /* refresh rate numerator */
		Stream_Write_UINT32(s, 1);  /* refresh rate denominator */
		Stream_Write_UINT32(s, 1);  /* vsync divider */
		Stream_Write_UINT32(s, 1);  /* colour mode */

		Stream_Write_UINT32(s, 0x10);
		Stream_Write_UINT32(s, MONITORCFG_BLOCK_SCALE);
		Stream_Write_UINT32(s, monitorcfg_scale(m->DesktopScaleFactor));
		Stream_Write_UINT32(s, monitorcfg_scale(m->DesktopScaleFactor));

		Stream_Write_UINT32(s, 0x10);
		Stream_Write_UINT32(s, MONITORCFG_BLOCK_PHYSICAL_SIZE);
		Stream_Write_UINT32(s, windowed ? 0 : m->PhysicalWidth);
		Stream_Write_UINT32(s, windowed ? 0 : m->PhysicalHeight);

		WLog_Print(plugin->base.log, WLOG_DEBUG,
		           "layout %" PRIu32 " monitor %" PRIu32 ": %" PRIu32 "x%" PRIu32 " at %" PRId32
		           ",%" PRId32 "%s",
		           plugin->sequence, x, width, height, m->Left, m->Top,
		           windowed ? " (window)" : "");
	}
	const UINT rc = monitorcfg_write(callback, s);
	Stream_Free(s, TRUE);
	return rc;
}

static UINT monitorcfg_on_open(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	WINPR_ASSERT(callback);
	MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)callback->plugin;
	WINPR_ASSERT(plugin);

	EnterCriticalSection(&plugin->lock);
	plugin->confirmed = FALSE;
	const UINT rc = monitorcfg_send_caps(callback);
	LeaveCriticalSection(&plugin->lock);
	if (rc != CHANNEL_RC_OK)
		WLog_Print(plugin->base.log, WLOG_ERROR, "sending the caps advertise failed: %" PRIu32, rc);
	return rc;
}

static UINT monitorcfg_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* s)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	WINPR_ASSERT(callback);
	MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)callback->plugin;
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(s);

	/* Malformed or unknown PDUs are logged and skipped: the channel stays open. */
	if (!Stream_CheckAndLogRequiredLengthWLog(plugin->base.log, s, 8))
		return CHANNEL_RC_OK;
	const UINT32 length = Stream_Get_UINT32(s);
	const UINT32 cmdId = Stream_Get_UINT32(s);
	if (length < 8 || length > Stream_Length(s))
	{
		WLog_Print(plugin->base.log, WLOG_WARN, "PDU length %" PRIu32 " does not match %" PRIuz,
		           length, Stream_Length(s));
		return CHANNEL_RC_OK;
	}

	UINT rc = CHANNEL_RC_OK;
	EnterCriticalSection(&plugin->lock);
	switch (cmdId)
	{
		case MONITORCFG_CMDID_CAPS_CONFIRM:
		{
			UINT32 signature = 0;
			UINT32 version = 0;
			if (Stream_CheckAndLogRequiredLengthWLog(plugin->base.log, s, 8))
			{
				Stream_Read_UINT32(s, signature);
				Stream_Read_UINT32(s, version);
			}
			WLog_Print(plugin->base.log, WLOG_INFO,
			           "caps confirm: version 0x%08" PRIx32 "; sending the monitor layout",
			           version);
			plugin->confirmed = TRUE;
			rc = monitorcfg_send_layout(plugin, callback);
		}
		break;

		case MONITORCFG_CMDID_NOTIFY_CONFIGURATION:
		{
			UINT32 sequence = 0;
			UINT32 result = 0;
			INT32 r[4] = WINPR_C_ARRAY_INIT;
			if (Stream_CheckAndLogRequiredLengthWLog(plugin->base.log, s, 24))
			{
				Stream_Read_UINT32(s, sequence);
				Stream_Read_UINT32(s, result);
				for (size_t x = 0; x < ARRAYSIZE(r); x++)
					Stream_Read_INT32(s, r[x]);
			}
			WLog_Print(plugin->base.log, result == 0 ? WLOG_DEBUG : WLOG_WARN,
			           "layout %" PRIu32 " %s (0x%08" PRIx32 "), desktop %" PRId32 ",%" PRId32
			           " - %" PRId32 ",%" PRId32,
			           sequence, result == 0 ? "applied" : "refused", result, r[0], r[1], r[2],
			           r[3]);
		}
		break;

		case MONITORCFG_CMDID_REQUEST_CONFIGURATION:
			if (plugin->confirmed)
				rc = monitorcfg_send_layout(plugin, callback);
			break;

		default:
			WLog_Print(plugin->base.log, WLOG_WARN, "unknown cmdId %" PRIu32 " ignored", cmdId);
			break;
	}
	LeaveCriticalSection(&plugin->lock);
	return rc;
}

static UINT monitorcfg_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	if (callback)
	{
		MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)callback->plugin;
		WINPR_ASSERT(plugin);
		EnterCriticalSection(&plugin->lock);
		if (plugin->base.listener_callback &&
		    plugin->base.listener_callback->channel_callback == callback)
			plugin->base.listener_callback->channel_callback = nullptr;
		plugin->confirmed = FALSE;
		free(callback);
		LeaveCriticalSection(&plugin->lock);
	}
	return CHANNEL_RC_OK;
}

static UINT monitorcfg_send_monitor_layout(MonitorCfgClientContext* context, UINT32 NumMonitors,
                                           const DISPLAY_CONTROL_MONITOR_LAYOUT* Monitors)
{
	WINPR_ASSERT(context);
	MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)context->handle;
	WINPR_ASSERT(plugin);
	if (NumMonitors == 0 || !Monitors)
		return ERROR_INVALID_PARAMETER;

	UINT rc = CHANNEL_RC_NOT_OPEN;
	EnterCriticalSection(&plugin->lock);
	plugin->numMonitors = 0;
	for (UINT32 x = 0; x < NumMonitors && x < MONITORCFG_MAX_MONITORS; x++)
		plugin->monitors[plugin->numMonitors++] = Monitors[x];

	GENERIC_CHANNEL_CALLBACK* callback =
	    plugin->base.listener_callback ? plugin->base.listener_callback->channel_callback : nullptr;
	if (callback && plugin->confirmed)
		rc = monitorcfg_send_layout(plugin, callback);
	else if (callback)
		rc = CHANNEL_RC_OK; /* sent after the confirm */
	LeaveCriticalSection(&plugin->lock);
	return rc;
}

static UINT monitorcfg_plugin_initialize(GENERIC_DYNVC_PLUGIN* base,
                                         WINPR_ATTR_UNUSED rdpContext* rcontext,
                                         rdpSettings* settings)
{
	MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)base;
	WINPR_ASSERT(plugin);
	plugin->settings = settings;
	InitializeCriticalSection(&plugin->lock);

	MonitorCfgClientContext* context =
	    (MonitorCfgClientContext*)calloc(1, sizeof(MonitorCfgClientContext));
	if (!context)
		return CHANNEL_RC_NO_MEMORY;
	context->handle = plugin;
	context->SendMonitorLayout = monitorcfg_send_monitor_layout;
	plugin->base.iface.pInterface = plugin->context = context;
	return CHANNEL_RC_OK;
}

static void monitorcfg_plugin_terminated(GENERIC_DYNVC_PLUGIN* base)
{
	MONITORCFG_PLUGIN* plugin = (MONITORCFG_PLUGIN*)base;
	WINPR_ASSERT(plugin);
	DeleteCriticalSection(&plugin->lock);
	free(plugin->context);
}

static const IWTSVirtualChannelCallback monitorcfg_callbacks = { monitorcfg_on_data_received,
	                                                             monitorcfg_on_open,
	                                                             monitorcfg_on_close, nullptr };

FREERDP_ENTRY_POINT(UINT VCAPITYPE monitorcfg_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints))
{
	return freerdp_generic_DVCPluginEntry(
	    pEntryPoints, TAG, MONITORCFG_DVC_CHANNEL_NAME, sizeof(MONITORCFG_PLUGIN),
	    sizeof(GENERIC_CHANNEL_CALLBACK), &monitorcfg_callbacks, monitorcfg_plugin_initialize,
	    monitorcfg_plugin_terminated);
}
