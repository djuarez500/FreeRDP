/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Unit Test
 *
 * Copyright 2026 Armin Novak <anovak@thincast.com>
 * Copyright 2026 Thincast Technologies GmbH
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

#include <winpr/winpr.h>
#include <freerdp/utils/gfx.h>
#include <freerdp/channels/rdpgfx.h>

static bool test(uint32_t flags, size_t bufferlen)
{
	char* buffer = calloc(bufferlen + 10, 1);
	WINPR_ASSERT(buffer);

	const char* val = rdpgfx_caps_flags_str(flags, buffer, bufferlen);
	const size_t len = strnlen(buffer, bufferlen);
	size_t vlen = 0;
	if (val)
		vlen = strnlen(val, bufferlen);
	printf("0x%" PRIx32 " [%" PRIu32 "]: %s\n", flags, bufferlen, buffer);
	free(buffer);
	if (!val)
		return false;
	if (len != vlen)
		return false;
	if (bufferlen > 0)
	{
		if (len >= bufferlen)
			return false;
	}
	return true;
}

static bool test_names(void)
{
	char buffer[128] = WINPR_C_ARRAY_INIT;
	const char* val = rdpgfx_caps_flags_str(
	    RDPGFX_CAPS_FLAG_SMALL_CACHE | RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE, buffer, sizeof(buffer));
	const char expect[] = "{SMALL_CACHE|SCALEDMAP_DISABLE}[0x00000082]";
	printf("%s\n", buffer);
	if (!val || (strcmp(buffer, expect) != 0))
		return false;

	const char* flag = rdpgfx_caps_flag_str(RDPGFX_CAPS_FLAG_THINCLIENT);
	return flag && (strcmp(flag, "THINCLIENT") == 0);
}

int TestGdiGfx(WINPR_ATTR_UNUSED int argc, WINPR_ATTR_UNUSED char* argv[])
{
	if (!test_names())
		return -1;
	if (!test(0, 0))
		return -1;
	if (!test(0, 128))
		return -1;
	if (!test(UINT32_MAX, 0))
		return -1;
	if (!test(UINT32_MAX, 64))
		return -1;
	if (!test(UINT32_MAX, 128))
		return -1;
	if (!test(UINT32_MAX, 384))
		return -1;

	uint32_t mask = 0xaaaaaaaa;
	if (!test(mask, 0))
		return -1;
	if (!test(mask, 64))
		return -1;
	if (!test(mask, 128))
		return -1;
	if (!test(mask, 384))
		return -1;
	return 0;
}
