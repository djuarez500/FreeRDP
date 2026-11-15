/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Mouse cursor channel client test
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

/* Drives the channel plugin through a fake channel manager: the capability advertise sent on
 * open, the server confirm, pointer messages as servers send them (hidden, large 32 bpp pointers
 * with and without an AND mask), and messages that must be skipped without closing the channel. */

#include <winpr/crt.h>
#include <winpr/stream.h>

#include <freerdp/addin.h>
#include <freerdp/client.h>
#include <freerdp/client/channels.h>
#include <freerdp/pointer.h>
#include <freerdp/update.h>
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

static BYTE written[64] = WINPR_C_ARRAY_INIT;
static size_t writtenLength = 0;
static size_t writes = 0;

static size_t systemPointers = 0;
static UINT32 lastSystemType = 0;
static size_t largePointers = 0;
static POINTER_LARGE_UPDATE lastLarge = WINPR_C_ARRAY_INIT;

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
	return "Microsoft::Windows::RDS::MouseCursor";
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

static BOOL test_pointer_system(WINPR_ATTR_UNUSED rdpContext* context,
                                const POINTER_SYSTEM_UPDATE* pointer)
{
	systemPointers++;
	lastSystemType = pointer->type;
	return TRUE;
}

static BOOL test_pointer_large(WINPR_ATTR_UNUSED rdpContext* context,
                               const POINTER_LARGE_UPDATE* pointer)
{
	largePointers++;
	lastLarge = *pointer;
	lastLarge.xorMaskData = nullptr;
	lastLarge.andMaskData = nullptr;
	return TRUE;
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

/* type 3 / update 0x0C: TS_FP_LARGEPOINTERATTRIBUTE with a 32 bpp XOR mask */
static UINT test_large_pointer(IWTSVirtualChannelCallback* callback, UINT16 hotX, UINT16 hotY,
                               UINT16 width, UINT16 height, UINT32 lengthAndMask)
{
	const UINT32 lengthXorMask = 4u * width * height;
	wStream* s = Stream_New(nullptr, 4 + 20 + lengthXorMask + lengthAndMask);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;
	Stream_Write_UINT8(s, 3);    /* type: pointer */
	Stream_Write_UINT8(s, 0x0C); /* large pointer */
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT16(s, 32); /* xorBpp */
	Stream_Write_UINT16(s, 0);  /* cacheIndex */
	Stream_Write_UINT16(s, hotX);
	Stream_Write_UINT16(s, hotY);
	Stream_Write_UINT16(s, width);
	Stream_Write_UINT16(s, height);
	Stream_Write_UINT32(s, lengthAndMask);
	Stream_Write_UINT32(s, lengthXorMask);
	Stream_Zero(s, lengthXorMask + lengthAndMask);
	Stream_SealLength(s);
	const UINT rc = test_receive(callback, Stream_Buffer(s), Stream_Length(s));
	Stream_Free(s, TRUE);
	return rc;
}

static BOOL check(const char* what, BOOL ok)
{
	if (!ok)
		(void)fprintf(stderr, "TestMouseCursor: %s failed\n", what);
	return ok;
}

static BOOL run(IWTSVirtualChannelCallback* callback)
{
	/* the capability advertise is sent when the channel opens */
	static const BYTE caps[] = { 0x01, 0x00, 0x00, 0x00, 0x43, 0x41, 0x50, 0x53,
		                         0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00 };
	if (!check("caps advertise", (writes == 1) && (writtenLength == sizeof(caps)) &&
	                                 (memcmp(written, caps, sizeof(caps)) == 0)))
		return FALSE;

	/* pointer messages are taken before the confirm, as servers send them */
	static const BYTE hidden[] = { 0x03, 0x05, 0x00, 0x00 };
	if (!check("hidden before confirm",
	           (test_receive(callback, hidden, sizeof(hidden)) == CHANNEL_RC_OK) &&
	               (systemPointers == 1) && (lastSystemType == SYSPTR_NULL)))
		return FALSE;

	static const BYTE confirm[] = { 0x02, 0x00, 0x00, 0x00, 0x43, 0x41, 0x50, 0x53,
		                            0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00 };
	if (!check("caps confirm",
	           (test_receive(callback, confirm, sizeof(confirm)) == CHANNEL_RC_OK) &&
	               (writes == 1)))
		return FALSE;

	/* 32x32 without AND mask, as sent for most shapes */
	if (!check("large pointer, no AND mask",
	           (test_large_pointer(callback, 6, 0, 32, 32, 0) == CHANNEL_RC_OK) &&
	               (largePointers == 1) && (lastLarge.xorBpp == 32) && (lastLarge.hotSpotX == 6) &&
	               (lastLarge.hotSpotY == 0) && (lastLarge.width == 32) &&
	               (lastLarge.height == 32) && (lastLarge.lengthAndMask == 0) &&
	               (lastLarge.lengthXorMask == 4096)))
		return FALSE;

	/* 32x32 with a 1 bpp AND mask (text cursor) */
	if (!check("large pointer, AND mask",
	           (test_large_pointer(callback, 8, 9, 32, 32, 128) == CHANNEL_RC_OK) &&
	               (largePointers == 2) && (lastLarge.hotSpotX == 8) && (lastLarge.hotSpotY == 9) &&
	               (lastLarge.lengthAndMask == 128)))
		return FALSE;

	/* 41x39, an odd size */
	if (!check("large pointer, 41x39",
	           (test_large_pointer(callback, 3, 11, 41, 39, 0) == CHANNEL_RC_OK) &&
	               (largePointers == 3) && (lastLarge.width == 41) && (lastLarge.height == 39) &&
	               (lastLarge.lengthXorMask == 6396)))
		return FALSE;

	/* truncated large pointer: rejected, the channel stays open */
	static const BYTE truncated[] = { 0x03, 0x0C, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
		                              0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x20, 0x00 };
	if (!check("truncated pointer",
	           (test_receive(callback, truncated, sizeof(truncated)) == CHANNEL_RC_OK) &&
	               (largePointers == 3)))
		return FALSE;

	/* unknown type and a message shorter than the header: ignored */
	static const BYTE unknown[] = { 0x7F, 0x00, 0x00, 0x00, 0x01, 0x02 };
	static const BYTE shortMsg[] = { 0x03, 0x05 };
	if (!check("unknown and short messages",
	           (test_receive(callback, unknown, sizeof(unknown)) == CHANNEL_RC_OK) &&
	               (test_receive(callback, shortMsg, sizeof(shortMsg)) == CHANNEL_RC_OK) &&
	               (systemPointers == 1) && (largePointers == 3) && (writes == 1)))
		return FALSE;

	/* the default pointer still works afterwards */
	static const BYTE def[] = { 0x03, 0x06, 0x00, 0x00 };
	return check("default pointer", (test_receive(callback, def, sizeof(def)) == CHANNEL_RC_OK) &&
	                                    (systemPointers == 2) &&
	                                    (lastSystemType == SYSPTR_DEFAULT));
}

int TestMouseCursor(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	int rc = -1;
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);

	rdpContext* context = freerdp_client_context_new(&entry);
	if (!context || !context->update || !context->update->pointer)
		goto fail;

	context->update->pointer->PointerSystem = test_pointer_system;
	context->update->pointer->PointerLarge = test_pointer_large;

	PDVC_PLUGIN_ENTRY pluginEntry =
	    WINPR_FUNC_PTR_CAST(freerdp_channels_load_static_addin_entry(
	                            "mousecursor", nullptr, nullptr, FREERDP_ADDIN_CHANNEL_DYNAMIC),
	                        PDVC_PLUGIN_ENTRY);

	test_entry_points ep = WINPR_C_ARRAY_INIT;
	ep.iface.RegisterPlugin = test_register_plugin;
	ep.iface.GetPlugin = test_get_plugin;
	ep.iface.GetPluginData = test_get_plugin_data;
	ep.iface.GetRdpSettings = test_get_rdp_settings;
	ep.iface.GetRdpContext = test_get_rdp_context;
	ep.context = context;

	if (!pluginEntry || (pluginEntry(&ep.iface) != CHANNEL_RC_OK) || !ep.plugin)
		goto fail;

	{
		IWTSPlugin* plugin = ep.plugin;
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
			BOOL accept = TRUE;
			IWTSVirtualChannelCallback* callback = nullptr;
			if ((mgr.listenerCallback->OnNewChannelConnection(mgr.listenerCallback, &channel,
			                                                  nullptr, &accept,
			                                                  &callback) == CHANNEL_RC_OK) &&
			    callback)
			{
				if ((callback->OnOpen(callback) == CHANNEL_RC_OK) && run(callback))
					rc = 0;
				(void)callback->OnClose(callback);
			}
		}
		(void)plugin->Terminated(plugin);
	}

fail:
	freerdp_client_context_free(context);
	return rc;
}
