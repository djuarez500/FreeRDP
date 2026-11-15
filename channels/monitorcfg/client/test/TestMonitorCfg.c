/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Monitor configuration channel client test
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

/* Drives the channel plugin through a fake channel manager. The capability advertise and the
 * layout of a 1280x720 window must be byte for byte what Windows clients send; a server request
 * makes the client send the layout again; a two-monitor layout carries position, size, scale and
 * physical size per monitor; malformed PDUs are skipped without closing the channel. */

#include <winpr/crt.h>
#include <winpr/stream.h>

#include <freerdp/addin.h>
#include <freerdp/client.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/monitorcfg.h>
#include <freerdp/settings.h>
#include <freerdp/dvc.h>

typedef struct
{
	IDRDYNVC_ENTRY_POINTS iface;
	rdpContext* context;
	IWTSPlugin* plugin;
} test_entry_points;

typedef struct
{
	IWTSVirtualChannelManager iface;
	IWTSListener listener;
	IWTSListenerCallback* listenerCallback;
} test_channel_manager;

static BYTE written[512] = WINPR_C_ARRAY_INIT;
static size_t writtenLength = 0;
static size_t writes = 0;

static UINT test_register_plugin(IDRDYNVC_ENTRY_POINTS* pEntryPoints,
                                 WINPR_ATTR_UNUSED const char* name, IWTSPlugin* pPlugin)
{
	((test_entry_points*)pEntryPoints)->plugin = pPlugin;
	return CHANNEL_RC_OK;
}

static IWTSPlugin* test_get_plugin(WINPR_ATTR_UNUSED IDRDYNVC_ENTRY_POINTS* pEntryPoints,
                                   WINPR_ATTR_UNUSED const char* name)
{
	return nullptr;
}

static const ADDIN_ARGV* test_get_plugin_data(WINPR_ATTR_UNUSED IDRDYNVC_ENTRY_POINTS* pEntryPoints)
{
	return nullptr;
}

static rdpSettings* test_get_rdp_settings(IDRDYNVC_ENTRY_POINTS* pEntryPoints)
{
	return ((test_entry_points*)pEntryPoints)->context->settings;
}

static rdpContext* test_get_rdp_context(IDRDYNVC_ENTRY_POINTS* pEntryPoints)
{
	return ((test_entry_points*)pEntryPoints)->context;
}

static UINT test_create_listener(IWTSVirtualChannelManager* pChannelMgr,
                                 WINPR_ATTR_UNUSED const char* pszChannelName,
                                 WINPR_ATTR_UNUSED ULONG ulFlags,
                                 IWTSListenerCallback* pListenerCallback, IWTSListener** ppListener)
{
	test_channel_manager* mgr = (test_channel_manager*)pChannelMgr;
	mgr->listenerCallback = pListenerCallback;
	if (ppListener)
		*ppListener = &mgr->listener;
	return CHANNEL_RC_OK;
}

static UINT test_destroy_listener(IWTSVirtualChannelManager* pChannelMgr,
                                  WINPR_ATTR_UNUSED IWTSListener* pListener)
{
	((test_channel_manager*)pChannelMgr)->listenerCallback = nullptr;
	return CHANNEL_RC_OK;
}

static UINT32 test_get_channel_id(WINPR_ATTR_UNUSED IWTSVirtualChannel* channel)
{
	return 1;
}

static const char* test_get_channel_name(WINPR_ATTR_UNUSED IWTSVirtualChannel* channel)
{
	return MONITORCFG_DVC_CHANNEL_NAME;
}

static IWTSVirtualChannel* test_find_channel_by_id(WINPR_ATTR_UNUSED IWTSVirtualChannelManager* mgr,
                                                   WINPR_ATTR_UNUSED UINT32 ChannelId)
{
	return nullptr;
}

static UINT test_channel_write(WINPR_ATTR_UNUSED IWTSVirtualChannel* pChannel, ULONG cbSize,
                               const BYTE* pBuffer, WINPR_ATTR_UNUSED void* pReserved)
{
	writes++;
	writtenLength = MIN(cbSize, sizeof(written));
	memcpy(written, pBuffer, writtenLength);
	return CHANNEL_RC_OK;
}

static UINT test_channel_close(WINPR_ATTR_UNUSED IWTSVirtualChannel* pChannel)
{
	return CHANNEL_RC_OK;
}

static UINT test_receive(IWTSVirtualChannelCallback* callback, const BYTE* data, size_t length)
{
	wStream* s = Stream_New(nullptr, length ? length : 1);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;
	Stream_Write(s, data, length);
	Stream_SealLength(s);
	Stream_ResetPosition(s);
	const UINT rc = callback->OnDataReceived(callback, s);
	Stream_Free(s, TRUE);
	return rc;
}

static UINT32 rd32(size_t offset)
{
	return (UINT32)written[offset] | ((UINT32)written[offset + 1] << 8) |
	       ((UINT32)written[offset + 2] << 16) | ((UINT32)written[offset + 3] << 24);
}

static BOOL check(const char* what, BOOL ok)
{
	if (!ok)
		(void)fprintf(stderr, "TestMonitorCfg: %s failed\n", what);
	return ok;
}

/* One monitor record of a SET: display mode, scale and physical size blocks */
static BOOL check_record(const char* what, size_t r, INT32 x, INT32 y, UINT32 w, UINT32 h,
                         UINT32 flags, UINT32 scale, UINT32 physW, UINT32 physH)
{
	const BOOL ok = (rd32(r) == 104) && (rd32(r + 4) == MONITORCFG_ACTION_ADD) &&
	                (rd32(r + 24) == 0x30) && (rd32(r + 28) == MONITORCFG_BLOCK_DISPLAY_MODE) &&
	                ((INT32)rd32(r + 32) == x) && ((INT32)rd32(r + 36) == y) &&
	                (rd32(r + 40) == w) && (rd32(r + 44) == h) && (rd32(r + 48) == flags) &&
	                (rd32(r + 56) == 60) && (rd32(r + 60) == 1) && (rd32(r + 64) == 1) &&
	                (rd32(r + 68) == 1) && (rd32(r + 72) == 0x10) &&
	                (rd32(r + 76) == MONITORCFG_BLOCK_SCALE) && (rd32(r + 80) == scale) &&
	                (rd32(r + 84) == scale) && (rd32(r + 88) == 0x10) &&
	                (rd32(r + 92) == MONITORCFG_BLOCK_PHYSICAL_SIZE) && (rd32(r + 96) == physW) &&
	                (rd32(r + 100) == physH);
	return check(what, ok);
}

static BOOL run(IWTSVirtualChannelCallback* callback, MonitorCfgClientContext* mc,
                rdpSettings* settings)
{
	/* the capability advertise (versions 1 and 1.1) is sent when the channel opens */
	static const BYTE caps[] = { 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x43, 0x41, 0x50,
		                         0x53, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x43, 0x41,
		                         0x50, 0x53, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00 };
	if (!check("caps advertise", (writes == 1) && (writtenLength == sizeof(caps)) &&
	                                 (memcmp(written, caps, sizeof(caps)) == 0)))
		return FALSE;

	/* after the confirm the window layout goes out unasked: one monitor, zero id, window flag */
	static const BYTE confirm[] = { 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x43, 0x41,
		                            0x50, 0x53, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00 };
	static const BYTE windowLayout[] = {
		0x78, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
		0xD0, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	if (!check("window layout after confirm",
	           (test_receive(callback, confirm, sizeof(confirm)) == CHANNEL_RC_OK) &&
	               (writes == 2) && (writtenLength == sizeof(windowLayout)) &&
	               (memcmp(written, windowLayout, sizeof(windowLayout)) == 0)))
		return FALSE;

	/* the server's notify is only logged */
	static const BYTE notify[] = { 0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                           0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0xD0, 0x02, 0x00, 0x00 };
	if (!check("notify",
	           (test_receive(callback, notify, sizeof(notify)) == CHANNEL_RC_OK) && (writes == 2)))
		return FALSE;

	/* full screen over two monitors: real monitors, no window flag, per-monitor scale and size */
	if (!freerdp_settings_set_bool(settings, FreeRDP_UseMultimon, TRUE))
		return FALSE;
	DISPLAY_CONTROL_MONITOR_LAYOUT monitors[2] = WINPR_C_ARRAY_INIT;
	monitors[0].Left = 2560;
	monitors[0].Top = 105;
	monitors[0].Width = 1920;
	monitors[0].Height = 1200;
	monitors[0].DesktopScaleFactor = 125;
	monitors[0].PhysicalWidth = 344;
	monitors[0].PhysicalHeight = 215;
	monitors[1].Flags = DISPLAY_CONTROL_MONITOR_PRIMARY;
	monitors[1].Width = 2560;
	monitors[1].Height = 1080;
	monitors[1].DesktopScaleFactor = 100;
	monitors[1].PhysicalWidth = 673;
	monitors[1].PhysicalHeight = 284;
	if (!check("two-monitor layout sent",
	           (mc->SendMonitorLayout(mc, 2, monitors) == CHANNEL_RC_OK) && (writes == 3) &&
	               (writtenLength == 224) && (rd32(0) == 224) &&
	               (rd32(4) == MONITORCFG_CMDID_SET_CONFIGURATION) && (rd32(8) == 2) &&
	               (rd32(12) == 0) && (rd32(16 + 8) != 0) && (rd32(120 + 8) != rd32(16 + 8))))
		return FALSE;
	if (!check_record("monitor 1", 16, 2560, 105, 1920, 1200, 0, 125, 344, 215) ||
	    !check_record("monitor 2", 120, 0, 0, 2560, 1080, 0, 100, 673, 284))
		return FALSE;

	/* a server request makes the client send the current layout again, next sequence */
	static const BYTE request[] = { 0x0C, 0x00, 0x00, 0x00, 0x05, 0x00,
		                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	if (!check("request", (test_receive(callback, request, sizeof(request)) == CHANNEL_RC_OK) &&
	                          (writes == 4) && (writtenLength == 224) && (rd32(8) == 3)))
		return FALSE;

	/* malformed PDUs: short, length larger than the data, unknown command; nothing is sent and
	 * the channel stays usable */
	static const BYTE shortPdu[] = { 0x08, 0x00, 0x00 };
	static const BYTE badLength[] = { 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
	static const BYTE unknown[] = { 0x08, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00 };
	if (!check("malformed PDUs",
	           (test_receive(callback, shortPdu, sizeof(shortPdu)) == CHANNEL_RC_OK) &&
	               (test_receive(callback, badLength, sizeof(badLength)) == CHANNEL_RC_OK) &&
	               (test_receive(callback, unknown, sizeof(unknown)) == CHANNEL_RC_OK) &&
	               (writes == 4)))
		return FALSE;

	return check("request after malformed PDUs",
	             (test_receive(callback, request, sizeof(request)) == CHANNEL_RC_OK) &&
	                 (writes == 5) && (rd32(8) == 4));
}

int TestMonitorCfg(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	int rc = -1;
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);

	rdpContext* context = freerdp_client_context_new(&entry);
	if (!context)
		return -1;
	if (!freerdp_settings_set_uint32(context->settings, FreeRDP_DesktopWidth, 1280) ||
	    !freerdp_settings_set_uint32(context->settings, FreeRDP_DesktopHeight, 720) ||
	    !freerdp_settings_set_bool(context->settings, FreeRDP_Fullscreen, FALSE) ||
	    !freerdp_settings_set_bool(context->settings, FreeRDP_UseMultimon, FALSE))
		goto fail;

	PDVC_PLUGIN_ENTRY pluginEntry = WINPR_FUNC_PTR_CAST(
	    freerdp_channels_load_static_addin_entry(MONITORCFG_CHANNEL_NAME, nullptr, nullptr,
	                                             FREERDP_ADDIN_CHANNEL_DYNAMIC),
	    PDVC_PLUGIN_ENTRY);

	test_entry_points ep = WINPR_C_ARRAY_INIT;
	ep.iface.RegisterPlugin = test_register_plugin;
	ep.iface.GetPlugin = test_get_plugin;
	ep.iface.GetPluginData = test_get_plugin_data;
	ep.iface.GetRdpSettings = test_get_rdp_settings;
	ep.iface.GetRdpContext = test_get_rdp_context;
	ep.context = context;

	if (!pluginEntry || (pluginEntry(&ep.iface) != CHANNEL_RC_OK) || !ep.plugin ||
	    !ep.plugin->pInterface)
		goto fail;

	{
		IWTSPlugin* plugin = ep.plugin;
		MonitorCfgClientContext* mc = (MonitorCfgClientContext*)plugin->pInterface;

		test_channel_manager mgr = WINPR_C_ARRAY_INIT;
		mgr.iface.CreateListener = test_create_listener;
		mgr.iface.DestroyListener = test_destroy_listener;
		mgr.iface.GetChannelId = test_get_channel_id;
		mgr.iface.GetChannelName = test_get_channel_name;
		mgr.iface.FindChannelById = test_find_channel_by_id;

		IWTSVirtualChannel channel = WINPR_C_ARRAY_INIT;
		channel.Write = test_channel_write;
		channel.Close = test_channel_close;

		if ((plugin->Initialize(plugin, &mgr.iface) == CHANNEL_RC_OK) && mgr.listenerCallback)
		{
			/* the server has not opened the channel: the caller is told to use Display Control;
			 * the layout is kept and used once the channel is up */
			DISPLAY_CONTROL_MONITOR_LAYOUT window = WINPR_C_ARRAY_INIT;
			window.Flags = DISPLAY_CONTROL_MONITOR_PRIMARY;
			window.Width = 1280;
			window.Height = 720;
			window.DesktopScaleFactor = 100;
			if (check("layout before the server opens the channel",
			          mc->SendMonitorLayout(mc, 1, &window) == CHANNEL_RC_NOT_OPEN))
			{
				BOOL accept = TRUE;
				IWTSVirtualChannelCallback* callback = nullptr;
				if ((mgr.listenerCallback->OnNewChannelConnection(mgr.listenerCallback, &channel,
				                                                  nullptr, &accept,
				                                                  &callback) == CHANNEL_RC_OK) &&
				    callback)
				{
					if ((callback->OnOpen(callback) == CHANNEL_RC_OK) &&
					    run(callback, mc, context->settings))
						rc = 0;
					(void)callback->OnClose(callback);
				}
			}
		}
		(void)plugin->Terminated(plugin);
	}

fail:
	freerdp_client_context_free(context);
	return rc;
}
