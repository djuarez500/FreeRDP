/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Mouse cursor shapes over a dynamic channel
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
 * Wire format, as seen between Windows servers and clients. Every message is one PDU:
 *
 *   header: UINT8 type, UINT8 updateType, UINT16 reserved (0)
 *
 *   type 1 caps advertise (client, sent when the channel opens) and
 *   type 2 caps confirm (server): header + capability set
 *       { UINT32 signature 'CAPS', UINT32 version (1), UINT32 length (12) }
 *   type 3 pointer (server): updateType is a fast-path pointer update code and the rest is
 *       that update's structure (MS-RDPBCGR 2.2.9.1.2.1.5 - 2.2.9.1.2.1.11).
 *
 * Servers send pointer messages without waiting for the confirm, so they are taken in any state.
 */

#include <freerdp/config.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/stream.h>

#include <freerdp/freerdp.h>
#include <freerdp/update.h>
#include <freerdp/channels/log.h>
#include <freerdp/client/channels.h>

#define TAG CHANNELS_TAG("mousecursor.client")

#define MOUSECURSOR_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::MouseCursor"

#define MOUSECURSOR_TYPE_CAPS_ADVERTISE 0x01
#define MOUSECURSOR_TYPE_CAPS_CONFIRM 0x02
#define MOUSECURSOR_TYPE_POINTER 0x03

#define MOUSECURSOR_CAPS_SIGNATURE 0x53504143 /* 'CAPS' */
#define MOUSECURSOR_CAPS_VERSION_1 0x00000001

typedef struct
{
	GENERIC_DYNVC_PLUGIN base;
	rdpContext* rdpcontext;
	BOOL confirmed;
} MOUSECURSOR_PLUGIN;

static UINT mousecursor_send_caps(GENERIC_CHANNEL_CALLBACK* callback)
{
	WINPR_ASSERT(callback);
	WINPR_ASSERT(callback->channel);
	WINPR_ASSERT(callback->channel->Write);

	BYTE pdu[16] = WINPR_C_ARRAY_INIT;
	wStream sbuffer = WINPR_C_ARRAY_INIT;
	wStream* s = Stream_StaticInit(&sbuffer, pdu, sizeof(pdu));
	Stream_Write_UINT8(s, MOUSECURSOR_TYPE_CAPS_ADVERTISE);
	Stream_Write_UINT8(s, 0);
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT32(s, MOUSECURSOR_CAPS_SIGNATURE);
	Stream_Write_UINT32(s, MOUSECURSOR_CAPS_VERSION_1);
	Stream_Write_UINT32(s, 12);
	return callback->channel->Write(callback->channel, sizeof(pdu), pdu, nullptr);
}

static UINT mousecursor_on_open(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	WINPR_ASSERT(callback);
	MOUSECURSOR_PLUGIN* plugin = (MOUSECURSOR_PLUGIN*)callback->plugin;
	WINPR_ASSERT(plugin);

	plugin->confirmed = FALSE;
	const UINT rc = mousecursor_send_caps(callback);
	if (rc != CHANNEL_RC_OK)
		WLog_Print(plugin->base.log, WLOG_ERROR, "sending the caps advertise failed: %" PRIu32, rc);
	return rc;
}

static UINT mousecursor_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* s)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	WINPR_ASSERT(callback);
	MOUSECURSOR_PLUGIN* plugin = (MOUSECURSOR_PLUGIN*)callback->plugin;
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(s);

	/* Unknown or malformed messages are logged and skipped: the channel stays open. */
	if (!Stream_CheckAndLogRequiredLengthWLog(plugin->base.log, s, 4))
		return CHANNEL_RC_OK;

	const BYTE type = Stream_Get_UINT8(s);
	const BYTE updateType = Stream_Get_UINT8(s);
	Stream_Seek_UINT16(s); /* reserved */

	switch (type)
	{
		case MOUSECURSOR_TYPE_CAPS_CONFIRM:
		{
			UINT32 signature = 0;
			UINT32 version = 0;
			if (Stream_CheckAndLogRequiredLengthWLog(plugin->base.log, s, 12))
			{
				Stream_Read_UINT32(s, signature);
				Stream_Read_UINT32(s, version);
			}
			plugin->confirmed = (signature == MOUSECURSOR_CAPS_SIGNATURE);
			WLog_Print(plugin->base.log, WLOG_DEBUG,
			           "caps confirm: signature 0x%08" PRIx32 " version %" PRIu32, signature,
			           version);
		}
		break;

		case MOUSECURSOR_TYPE_POINTER:
			if (!plugin->rdpcontext ||
			    !freerdp_update_recv_fastpath_pointer(plugin->rdpcontext, updateType, s))
				WLog_Print(plugin->base.log, WLOG_WARN,
				           "pointer update 0x%02" PRIx8 " (%" PRIuz " bytes) not applied",
				           updateType, Stream_Length(s));
			break;

		default:
			WLog_Print(plugin->base.log, WLOG_WARN,
			           "unknown message type 0x%02" PRIx8 " (%" PRIuz " bytes) ignored", type,
			           Stream_Length(s));
			break;
	}
	return CHANNEL_RC_OK;
}

static UINT mousecursor_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	if (callback)
	{
		MOUSECURSOR_PLUGIN* plugin = (MOUSECURSOR_PLUGIN*)callback->plugin;
		if (plugin && plugin->base.listener_callback &&
		    plugin->base.listener_callback->channel_callback == callback)
			plugin->base.listener_callback->channel_callback = nullptr;
		free(callback);
	}
	return CHANNEL_RC_OK;
}

static UINT mousecursor_plugin_initialize(GENERIC_DYNVC_PLUGIN* base, rdpContext* rcontext,
                                          WINPR_ATTR_UNUSED rdpSettings* settings)
{
	MOUSECURSOR_PLUGIN* plugin = (MOUSECURSOR_PLUGIN*)base;
	WINPR_ASSERT(plugin);
	plugin->rdpcontext = rcontext;
	return CHANNEL_RC_OK;
}

static const IWTSVirtualChannelCallback mousecursor_callbacks = { mousecursor_on_data_received,
	                                                              mousecursor_on_open,
	                                                              mousecursor_on_close, nullptr };

FREERDP_ENTRY_POINT(UINT VCAPITYPE mousecursor_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints))
{
	return freerdp_generic_DVCPluginEntry(pEntryPoints, TAG, MOUSECURSOR_DVC_CHANNEL_NAME,
	                                      sizeof(MOUSECURSOR_PLUGIN),
	                                      sizeof(GENERIC_CHANNEL_CALLBACK), &mousecursor_callbacks,
	                                      mousecursor_plugin_initialize, nullptr);
}
