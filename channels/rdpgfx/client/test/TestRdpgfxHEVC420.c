/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Unit Test
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

/* HEVC420 surface commands through the rdpgfx client channel: only accepted after the server
 * confirmed RDPGFX_CAPS_FLAG_HEVC_ENABLE, the NAL size table is checked and dropped. HEVC444
 * has the same layout and also needs RDPGFX_CAPS_FLAG_HEVC_I444 in RDPGFX_CAPVERSION_115. */

#include <winpr/crt.h>
#include <winpr/stream.h>

#include <freerdp/addin.h>
#include <freerdp/client.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/rdpgfx.h>
#include <freerdp/channels/rdpgfx.h>
#include <freerdp/codec/zgfx.h>
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

/* what the last surface command delivered */
static size_t surfaceCommands = 0;
static UINT32 lastCodecId = 0;
static UINT32 lastRects = 0;
static UINT32 lastLength = 0;
static BYTE lastData[64] = WINPR_C_ARRAY_INIT;
static BOOL emptyDestRect = FALSE;
static size_t capsAdvertised = 0;

static UINT test_register_plugin(IDRDYNVC_ENTRY_POINTS* pEntryPoints,
                                 WINPR_ATTR_UNUSED const char* name, IWTSPlugin* pPlugin)
{
	test_entry_points* ep = (test_entry_points*)pEntryPoints;
	ep->plugin = pPlugin;
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
	return RDPGFX_DVC_CHANNEL_NAME;
}

static IWTSVirtualChannel* test_find_channel_by_id(WINPR_ATTR_UNUSED IWTSVirtualChannelManager* mgr,
                                                   WINPR_ATTR_UNUSED UINT32 ChannelId)
{
	return nullptr;
}

static UINT test_channel_write(WINPR_ATTR_UNUSED IWTSVirtualChannel* pChannel, ULONG cbSize,
                               const BYTE* pBuffer, WINPR_ATTR_UNUSED void* pReserved)
{
	/* count the capability advertisements the client sends */
	if (pBuffer && (cbSize >= 2) &&
	    ((pBuffer[0] | ((UINT16)pBuffer[1] << 8)) == RDPGFX_CMDID_CAPSADVERTISE))
		capsAdvertised++;
	return CHANNEL_RC_OK;
}

static UINT test_channel_close(WINPR_ATTR_UNUSED IWTSVirtualChannel* pChannel)
{
	return CHANNEL_RC_OK;
}

static UINT test_surface_command(WINPR_ATTR_UNUSED RdpgfxClientContext* context,
                                 const RDPGFX_SURFACE_COMMAND* cmd)
{
	surfaceCommands++;
	lastCodecId = cmd->codecId;
	lastRects = 0;
	lastLength = 0;

	const RDPGFX_HEVC_BITMAP_STREAM* bs = (const RDPGFX_HEVC_BITMAP_STREAM*)cmd->extra;
	if (bs)
	{
		lastRects = bs->meta.numRegionRects;
		lastLength = bs->length;
		memcpy(lastData, bs->data, MIN(bs->length, sizeof(lastData)));
	}
	return CHANNEL_RC_OK;
}

/* deliver one RDPGFX PDU, wrapped into an uncompressed ZGFX segment */
static UINT test_send_pdu(IWTSVirtualChannelCallback* callback, UINT16 cmdId, const BYTE* body,
                          size_t length)
{
	wStream* s = Stream_New(nullptr, 2 + RDPGFX_HEADER_SIZE + length);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT8(s, ZGFX_SEGMENTED_SINGLE);
	Stream_Write_UINT8(s, ZGFX_PACKET_COMPR_TYPE_RDP8);
	Stream_Write_UINT16(s, cmdId);
	Stream_Write_UINT16(s, 0); /* flags */
	Stream_Write_UINT32(s, (UINT32)(RDPGFX_HEADER_SIZE + length));
	Stream_Write(s, body, length);
	Stream_SealLength(s);
	Stream_ResetPosition(s);

	const UINT rc = callback->OnDataReceived(callback, s);
	Stream_Free(s, TRUE);
	return rc;
}

static UINT test_caps_confirm(IWTSVirtualChannelCallback* callback, UINT32 version, UINT32 flags)
{
	BYTE body[12] = WINPR_C_ARRAY_INIT;
	wStream sbuffer = WINPR_C_ARRAY_INIT;
	wStream* s = Stream_StaticInit(&sbuffer, body, sizeof(body));
	Stream_Write_UINT32(s, version);
	Stream_Write_UINT32(s, 4); /* capsDataLength */
	Stream_Write_UINT32(s, flags);
	return test_send_pdu(callback, RDPGFX_CMDID_CAPSCONFIRM, body, sizeof(body));
}

/* WIRE_TO_SURFACE_1 with HEVC420 or HEVC444 bitmap data: metablock with one rectangle, a NAL
 * size table claiming cbNalSizes bytes and the sizes given, the frameAttributes byte if not
 * negative, then the NAL units */
static UINT test_hevc(IWTSVirtualChannelCallback* callback, UINT16 codecId, UINT32 cbNalSizes,
                      const UINT32* sizes, size_t nsizes, const BYTE* nals, size_t nalLength,
                      BOOL truncateMeta, int frameAttributes)
{
	wStream* s = Stream_New(nullptr, 64 + nsizes * 4 + nalLength);
	if (!s)
		return CHANNEL_RC_NO_MEMORY;

	/* RDPGFX_WIRE_TO_SURFACE_PDU_1, bitmapDataLength patched below */
	Stream_Write_UINT16(s, 0);                         /* surfaceId */
	Stream_Write_UINT16(s, codecId);                   /* codecId */
	Stream_Write_UINT8(s, GFX_PIXEL_FORMAT_XRGB_8888); /* pixelFormat */
	Stream_Write_UINT16(s, 0);                         /* destRect.left */
	Stream_Write_UINT16(s, 0);                         /* destRect.top */
	Stream_Write_UINT16(s, emptyDestRect ? 0 : 64);    /* destRect.right */
	Stream_Write_UINT16(s, emptyDestRect ? 0 : 64);    /* destRect.bottom */
	const size_t lengthPos = Stream_GetPosition(s);
	Stream_Write_UINT32(s, 0); /* bitmapDataLength */
	const size_t dataPos = Stream_GetPosition(s);

	/* RDPGFX_H264_METABLOCK */
	Stream_Write_UINT32(s, 1); /* numRegionRects */
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT16(s, 64);
	if (!truncateMeta)
	{
		Stream_Write_UINT16(s, 64);
		Stream_Write_UINT8(s, 22);  /* qpVal */
		Stream_Write_UINT8(s, 100); /* qualityVal */

		Stream_Write_UINT32(s, cbNalSizes);
		for (size_t x = 0; x < nsizes; x++)
			Stream_Write_UINT32(s, sizes[x]);
		if (frameAttributes >= 0)
			Stream_Write_UINT8(s, (BYTE)frameAttributes);
		Stream_Write(s, nals, nalLength);
	}

	const size_t end = Stream_GetPosition(s);
	Stream_SetPosition(s, lengthPos);
	Stream_Write_UINT32(s, (UINT32)(end - dataPos));
	Stream_SetPosition(s, end);

	const UINT rc = test_send_pdu(callback, RDPGFX_CMDID_WIRETOSURFACE_1, Stream_Buffer(s),
	                              Stream_GetPosition(s));
	Stream_Free(s, TRUE);
	return rc;
}

static UINT test_hevc420(IWTSVirtualChannelCallback* callback, UINT32 cbNalSizes,
                         const UINT32* sizes, size_t nsizes, const BYTE* nals, size_t nalLength,
                         BOOL truncateMeta, int frameAttributes)
{
	return test_hevc(callback, RDPGFX_CODECID_HEVC420, cbNalSizes, sizes, nsizes, nals, nalLength,
	                 truncateMeta, frameAttributes);
}

/* an access unit delimiter and a (fake) slice, the channel does not decode them */
static const BYTE nals[] = { 0x00, 0x00, 0x00, 0x01, 0x46, 0x01, 0x50, 0x00, 0x00,
	                         0x00, 0x01, 0x02, 0x01, 0xAA, 0xBB, 0xCC, 0xDD };

static BOOL expect(const char* what, UINT rc, BOOL ok, size_t commands)
{
	if (((rc == CHANNEL_RC_OK) != ok) || (surfaceCommands != commands))
	{
		(void)fprintf(
		    stderr, "[%s] rc=%" PRIu32 " surface commands %" PRIuz ", expected %s and %" PRIuz "\n",
		    what, rc, surfaceCommands, ok ? "success" : "failure", commands);
		return FALSE;
	}
	return TRUE;
}

/* HEVC444: only after RDPGFX_CAPS_FLAG_HEVC_I444 and RDPGFX_CAPS_FLAG_HEVC_ENABLE were
 * confirmed in RDPGFX_CAPVERSION_115, same layout as HEVC420 */
static BOOL run_hevc444(IWTSVirtualChannelCallback* callback, size_t commands)
{
	const UINT32 valid[] = { 7, 10 };
	const struct
	{
		const char* what;
		UINT32 version;
		UINT32 flags;
	} rejected[] = {
		{ "HEVC444 with HEVC 4:2:0 confirmed", RDPGFX_CAPVERSION_115,
		  RDPGFX_CAPS_FLAG_HEVC_ENABLE },
		{ "HEVC444 without HEVC_ENABLE", RDPGFX_CAPVERSION_115, RDPGFX_CAPS_FLAG_HEVC_I444 },
		{ "HEVC444 with RDPGFX_CAPVERSION_113", RDPGFX_CAPVERSION_113,
		  RDPGFX_CAPS_FLAG_HEVC_ENABLE | RDPGFX_CAPS_FLAG_HEVC_I444 },
	};

	for (size_t x = 0; x < ARRAYSIZE(rejected); x++)
	{
		if (test_caps_confirm(callback, rejected[x].version, rejected[x].flags) != CHANNEL_RC_OK)
			return FALSE;
		if (!expect(rejected[x].what,
		            test_hevc(callback, RDPGFX_CODECID_HEVC444, 8, valid, 2, nals, sizeof(nals),
		                      FALSE, 0x01),
		            FALSE, commands))
			return FALSE;
	}

	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_115,
	                      RDPGFX_CAPS_FLAG_HEVC_ENABLE | RDPGFX_CAPS_FLAG_HEVC_I444) !=
	    CHANNEL_RC_OK)
		return FALSE;
	if (!expect("HEVC444 confirmed",
	            test_hevc(callback, RDPGFX_CODECID_HEVC444, 8, valid, 2, nals, sizeof(nals), FALSE,
	                      0x01),
	            TRUE, commands + 1))
		return FALSE;
	if ((lastCodecId != RDPGFX_CODECID_HEVC444) || (lastRects != 1) ||
	    (lastLength != sizeof(nals)) || (memcmp(lastData, nals, sizeof(nals)) != 0))
	{
		(void)fprintf(stderr,
		              "[HEVC444] unexpected codec %" PRIu32 ", rects %" PRIu32 ", length %" PRIu32
		              "\n",
		              lastCodecId, lastRects, lastLength);
		return FALSE;
	}

	/* HEVC 4:2:0 stays valid with 4:4:4 confirmed, the server may switch */
	return expect("HEVC420 with HEVC444 confirmed",
	              test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, 0x01), TRUE,
	              commands + 2);
}

static BOOL run(IWTSVirtualChannelCallback* callback)
{
	const UINT32 valid[] = { 7, 10 };
	const UINT32 wrongSum[] = { 7, 11 };

	/* not confirmed by the server: rejected */
	if (!expect("unconfirmed", test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, -1),
	            FALSE, 0))
		return FALSE;

	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_112, RDPGFX_CAPS_FLAG_HEVC_ENABLE) !=
	    CHANNEL_RC_OK)
		return FALSE;

	/* valid: the surface command gets the Annex B data without the table */
	if (!expect("valid", test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, -1), TRUE,
	            1))
		return FALSE;
	if ((lastCodecId != RDPGFX_CODECID_HEVC420) || (lastRects != 1) ||
	    (lastLength != sizeof(nals)) || (memcmp(lastData, nals, sizeof(nals)) != 0))
	{
		(void)fprintf(
		    stderr, "[valid] unexpected codec %" PRIu32 ", rects %" PRIu32 ", length %" PRIu32 "\n",
		    lastCodecId, lastRects, lastLength);
		return FALSE;
	}

	/* the table holds at most 512 NAL unit sizes (2048 bytes) */
	UINT32 ones[513] = WINPR_C_ARRAY_INIT;
	BYTE bytes[513] = WINPR_C_ARRAY_INIT;
	for (size_t x = 0; x < ARRAYSIZE(ones); x++)
		ones[x] = 1;
	if (!expect("512 NAL units", test_hevc420(callback, 2048, ones, 512, bytes, 512, FALSE, -1),
	            TRUE, 2))
		return FALSE;

	/* malformed: never reach the surface command */
	if (!expect("513 NAL units", test_hevc420(callback, 2052, ones, 513, bytes, 513, FALSE, -1),
	            FALSE, 2))
		return FALSE;
	if (!expect("empty table and no data",
	            test_hevc420(callback, 0, nullptr, 0, nullptr, 0, FALSE, -1), FALSE, 2))
		return FALSE;
	if (!expect("table length not a multiple of 4",
	            test_hevc420(callback, 6, valid, 2, nals, sizeof(nals), FALSE, -1), FALSE, 2))
		return FALSE;
	if (!expect("sizes do not add up",
	            test_hevc420(callback, 8, wrongSum, 2, nals, sizeof(nals), FALSE, -1), FALSE, 2))
		return FALSE;
	if (!expect("table longer than the data",
	            test_hevc420(callback, 64, valid, 2, nals, sizeof(nals), FALSE, -1), FALSE, 2))
		return FALSE;
	if (!expect("truncated metablock", test_hevc420(callback, 0, nullptr, 0, nullptr, 0, TRUE, -1),
	            FALSE, 2))
		return FALSE;

	/* a server confirming another version must not get HEVC420 accepted */
	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_111, RDPGFX_CAPS_FLAG_HEVC_ENABLE) !=
	    CHANNEL_RC_OK)
		return FALSE;
	if (!expect("confirmed with RDPGFX_CAPVERSION_111",
	            test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, -1), FALSE, 2))
		return FALSE;

	/* RDPGFX_CAPVERSION_113 and RDPGFX_CAPVERSION_115: frameAttributes follows the table */
	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_115, RDPGFX_CAPS_FLAG_HEVC_ENABLE) !=
	    CHANNEL_RC_OK)
		return FALSE;
	if (!expect("RDPGFX_CAPVERSION_115 with frameAttributes",
	            test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, 0x01), TRUE, 3))
		return FALSE;
	if ((lastLength != sizeof(nals)) || (memcmp(lastData, nals, sizeof(nals)) != 0))
	{
		(void)fprintf(stderr, "[RDPGFX_CAPVERSION_115] unexpected length %" PRIu32 "\n",
		              lastLength);
		return FALSE;
	}
	if (!expect("RDPGFX_CAPVERSION_115 without frameAttributes",
	            test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, -1), FALSE, 3))
		return FALSE;

	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_113, RDPGFX_CAPS_FLAG_HEVC_ENABLE) !=
	    CHANNEL_RC_OK)
		return FALSE;
	if (!expect("RDPGFX_CAPVERSION_113 with frameAttributes",
	            test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, 0x00), TRUE, 4))
		return FALSE;

	/* the update regions are in the metablock, the destRect may be all zero */
	emptyDestRect = TRUE;
	const BOOL rc = expect("empty destRect",
	                       test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, 0x00), TRUE, 5);
	emptyDestRect = FALSE;
	if (!rc)
		return FALSE;

	/* diagnostic information carries no graphics and must not end the channel */
	const BYTE diagnostic[] = { 0x00, 0x00, 0x04, 0x00, 'T', 0x00, 'S', 0x00 };
	if (!expect("diagnostic information",
	            test_send_pdu(callback, RDPGFX_CMDID_UNUSED_0014, diagnostic, sizeof(diagnostic)),
	            TRUE, 5))
		return FALSE;

	/* a caps reset is answered with a new caps advertise, the server then confirms again */
	const size_t advertised = capsAdvertised;
	if (!expect("caps reset", test_send_pdu(callback, RDPGFX_CMDID_CAPSRESET, diagnostic, 0), TRUE,
	            5))
		return FALSE;
	if (capsAdvertised != advertised + 1)
	{
		(void)fprintf(stderr, "caps reset: expected one new caps advertise, got %" PRIuz "\n",
		              capsAdvertised - advertised);
		return FALSE;
	}
	if (test_caps_confirm(callback, RDPGFX_CAPVERSION_115, RDPGFX_CAPS_FLAG_HEVC_ENABLE) !=
	    CHANNEL_RC_OK)
		return FALSE;
	if (!expect("frame after caps reset",
	            test_hevc420(callback, 8, valid, 2, nals, sizeof(nals), FALSE, 0x01), TRUE, 6))
		return FALSE;

	return run_hevc444(callback, 6);
}

int TestRdpgfxHEVC420(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	int rc = -1;
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpContext);

	rdpContext* context = freerdp_client_context_new(&entry);
	if (!context)
		return -1;

	PDVC_PLUGIN_ENTRY pluginEntry = WINPR_FUNC_PTR_CAST(
	    freerdp_channels_load_static_addin_entry(RDPGFX_CHANNEL_NAME, nullptr, nullptr,
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
		RdpgfxClientContext* gfx = (RdpgfxClientContext*)plugin->pInterface;
		gfx->SurfaceCommand = test_surface_command;

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
				/* frees the channel callback */
				(void)callback->OnClose(callback);
			}
		}

		/* frees the plugin */
		(void)plugin->Terminated(plugin);
	}

fail:
	freerdp_client_context_free(context);
	return rc;
}
