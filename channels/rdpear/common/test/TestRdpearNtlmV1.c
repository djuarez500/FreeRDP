/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * [MS-RDPEAR] NTLM CalculateNtResponse (0x203) and CalculateUserSessionKeyNt (0x204) servicing
 * test
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

#include <krb5.h>

#include <winpr/crt.h>
#include <winpr/nt.h>
#include <winpr/stream.h>
#include <winpr/asn1.h>
#include <winpr/credssp.h>

#include "rdpear-common/rdpear_common.h"
#include "rdpear-common/rdpear_kerb.h"
#include "rdpear-common/rdpear_ntlm.h"

/* The request arms of a real NTLMv1 second hop (a target with LmCompatibilityLevel 2), captured on
 * the wire: the bytes following the two callId UINT16s. CalculateNtResponse carries the server
 * challenge and the forwarded NTLM secret (MSV1_0_REMOTE_ENCRYPTED_SECRETS, a 48-byte sealed
 * blob); CalculateUserSessionKeyNt follows it with the NT response that call returned and the
 * same secret. */
static const BYTE calculateNtResponseArm[] = {
	0x04, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0xc5, 0x84, 0x86, 0xb7, 0x0c, 0xd5, 0x59,
	0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x30, 0x00, 0x00, 0x00, 0xb7, 0xce, 0x2d, 0x8b,
	0xef, 0x55, 0x43, 0x71, 0x54, 0x37, 0xf6, 0x34, 0x09, 0xd6, 0x25, 0xd6, 0xfd, 0xe5, 0xf3,
	0x8b, 0x7a, 0x86, 0x12, 0x3c, 0x3d, 0x6c, 0xab, 0x42, 0x00, 0x00, 0x00, 0x00, 0x17, 0x74,
	0x85, 0x8e, 0xba, 0xf8, 0x3e, 0x45, 0xbf, 0x9e, 0x4e, 0xa7, 0x21, 0x71, 0x80, 0x30
};

static const BYTE calculateUserSessionKeyNtArm[] = {
	0x04, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0xe7, 0xa3, 0xbc, 0xbf, 0x73, 0xd4, 0xbf,
	0x77, 0x23, 0xd5, 0xa3, 0x5c, 0xb3, 0xb0, 0x22, 0x66, 0x42, 0x37, 0x8e, 0xf9, 0x97, 0x03,
	0x22, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x30, 0x00, 0x00, 0x00, 0xb7, 0xce, 0x2d,
	0x8b, 0xef, 0x55, 0x43, 0x71, 0x54, 0x37, 0xf6, 0x34, 0x09, 0xd6, 0x25, 0xd6, 0xfd, 0xe5,
	0xf3, 0x8b, 0x7a, 0x86, 0x12, 0x3c, 0x3d, 0x6c, 0xab, 0x42, 0x00, 0x00, 0x00, 0x00, 0x17,
	0x74, 0x85, 0x8e, 0xba, 0xf8, 0x3e, 0x45, 0xbf, 0x9e, 0x4e, 0xa7, 0x21, 0x71, 0x80, 0x30
};

static const BYTE challenge[8] = { 0xc5, 0x84, 0x86, 0xb7, 0x0c, 0xd5, 0x59, 0xfa };
static const BYTE sealedHead[4] = { 0xb7, 0xce, 0x2d, 0x8b };
#define SEALED_LENGTH 48

static const BYTE key[16] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
	                          0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
static const BYTE owf[RDPEAR_NTOWF_LENGTH] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

/* Service one captured request end to end (decode, handler, encode, free), with its forwarded
 * secret resealed under the test key (the key it was captured with is gone), and return the
 * reply's Status and the fixed-size result that follows it. */
static BOOL service_call(UINT16 callId, const BYTE* capturedArm, size_t armLen, BOOL withKey,
                         UINT32* pstatus, BYTE* result, size_t resultLen)
{
	BOOL rc = FALSE;
	krb5_context krb = NULL;
	SecBuffer sealed = { 0 };
	BYTE* arm = NULL;
	wStream* payload = NULL;
	wStream* request = NULL;
	wStream* response = NULL;

	arm = malloc(armLen);
	if (!arm)
		goto out;
	memcpy(arm, capturedArm, armLen);
	size_t at = 0;
	for (; at + SEALED_LENGTH <= armLen; at++)
	{
		if (memcmp(&arm[at], sealedHead, sizeof(sealedHead)) == 0)
			break;
	}
	if ((at + SEALED_LENGTH > armLen) ||
	    !winpr_ntlm_rguard_secrets_seal(key, sizeof(key), owf, sizeof(owf), &sealed) ||
	    (sealed.cbBuffer != SEALED_LENGTH))
	{
		(void)fprintf(stderr, "failed to reseal the forwarded secret\n");
		goto out;
	}
	memcpy(&arm[at], sealed.pvBuffer, SEALED_LENGTH);

	/* [MS-RDPEAR] payload: 16-byte header, then the type serialized NtlmCredIsoRemoteInput */
	const size_t objectLen = (8 + armLen + 7) & ~(size_t)7;
	payload = Stream_New(NULL, 32 + objectLen);
	if (!payload)
		goto out;
	Stream_Write_UINT32(payload, 1);
	Stream_Zero(payload, 12);
	Stream_Write_UINT32(payload, 0x00081001); /* common header: version 1, little-endian, 8 */
	Stream_Write_UINT32(payload, 0xcccccccc);
	Stream_Write_UINT32(payload, (UINT32)objectLen); /* private header */
	Stream_Write_UINT32(payload, 0);
	Stream_Write_UINT32(payload, 0x00020000); /* top-level referent */
	Stream_Write_UINT16(payload, callId);     /* CallId */
	Stream_Write_UINT16(payload, callId);     /* union arm */
	Stream_Write(payload, arm, armLen);
	Stream_Zero(payload, objectLen - 8 - armLen);

	request = rdpear_encodePayload(RDPEAR_PACKAGE_NTLM, payload);
	if (!request || (krb5_init_context(&krb) != 0))
		goto out;

	response = rdpear_kerb_service(krb, withKey ? key : NULL, withKey ? sizeof(key) : 0,
	                               Stream_Buffer(request), Stream_GetPosition(request));
	if (!response)
	{
		(void)fprintf(stderr, "rdpear_kerb_service returned NULL\n");
		goto out;
	}

	/* the reply: SEQUENCE { [1] package, [2] payload } */
	wStream envelope = { 0 };
	Stream_StaticConstInit(&envelope, Stream_Buffer(response), Stream_GetPosition(response));
	WinPrAsn1Decoder dec = WinPrAsn1Decoder_init();
	WinPrAsn1Decoder seq = WinPrAsn1Decoder_init();
	WinPrAsn1Decoder_Init(&dec, WINPR_ASN1_DER, &envelope);
	WinPrAsn1_OctetString package = { 0 };
	WinPrAsn1_OctetString reply = { 0 };
	BOOL error = FALSE;
	if (!WinPrAsn1DecReadSequence(&dec, &seq) ||
	    !WinPrAsn1DecReadContextualOctetString(&seq, 1, &error, &package, FALSE) ||
	    !WinPrAsn1DecReadContextualOctetString(&seq, 2, &error, &reply, FALSE))
	{
		(void)fprintf(stderr, "malformed reply envelope\n");
		goto out;
	}

	/* the type serialized NtlmCredIsoRemoteOutput, past the 16-byte payload header and the NDR
	 * common and private headers: the top-level referent, CallId, Status, the union arm, then the
	 * NT_RESPONSE or USER_SESSION_KEY */
	wStream rbuffer = { 0 };
	wStream* rs = Stream_StaticConstInit(&rbuffer, reply.data, reply.len);
	if (Stream_GetRemainingLength(rs) < 32 + 14 + resultLen)
	{
		(void)fprintf(stderr, "reply too short (%" PRIuz " bytes)\n", reply.len);
		goto out;
	}

	UINT16 replyCallId = 0;
	Stream_Seek(rs, 32);                 /* payload, NDR common and private headers */
	Stream_Seek(rs, 4);                  /* top-level referent */
	Stream_Read_UINT16(rs, replyCallId); /* CallId */
	Stream_Seek(rs, 2);                  /* padding */
	Stream_Read_UINT32(rs, *pstatus);    /* Status */
	Stream_Seek(rs, 2);                  /* union arm; the byte arrays need no alignment */
	Stream_Read(rs, result, resultLen);
	if (replyCallId != callId)
	{
		(void)fprintf(stderr, "unexpected reply callId 0x%04" PRIx16 "\n", replyCallId);
		goto out;
	}

	rc = TRUE;
out:
	Stream_Free(response, TRUE);
	Stream_Free(request, TRUE);
	Stream_Free(payload, TRUE);
	sspi_SecBufferFree(&sealed);
	free(arm);
	if (krb)
		krb5_free_context(krb);
	return rc;
}

static int test_calculate_nt_response(void)
{
	UINT32 status = 0;
	BYTE response[RDPEAR_NT_RESPONSE_LENGTH] = { 0 };
	BYTE expected[RDPEAR_NT_RESPONSE_LENGTH] = { 0 };

	if (!service_call(RemoteCallNtlmCalculateNtResponse, calculateNtResponseArm,
	                  sizeof(calculateNtResponseArm), TRUE, &status, response, sizeof(response)) ||
	    !rdpear_ntlm_v1_response(owf, challenge, expected))
		return -1;

	if ((status != 0) || (memcmp(response, expected, sizeof(expected)) != 0))
	{
		(void)fprintf(stderr, "CalculateNtResponse: status=0x%08" PRIx32 " or response mismatch\n",
		              status);
		return -1;
	}
	return 0;
}

static int test_calculate_user_session_key(void)
{
	UINT32 status = 0;
	BYTE sessionKey[RDPEAR_SESSION_KEY_LENGTH] = { 0 };
	BYTE expected[RDPEAR_SESSION_KEY_LENGTH] = { 0 };

	if (!service_call(RemoteCallNtlmCalculateUserSessionKeyNt, calculateUserSessionKeyNtArm,
	                  sizeof(calculateUserSessionKeyNtArm), TRUE, &status, sessionKey,
	                  sizeof(sessionKey)) ||
	    !rdpear_ntlm_v1_user_session_key(owf, expected))
		return -1;

	if ((status != 0) || (memcmp(sessionKey, expected, sizeof(expected)) != 0))
	{
		(void)fprintf(stderr,
		              "CalculateUserSessionKeyNt: status=0x%08" PRIx32 " or session key mismatch\n",
		              status);
		return -1;
	}
	return 0;
}

/* Without the sealing key (no NTLM credential was forwarded) the call is not supported. */
static int test_no_key(void)
{
	UINT32 status = 0;
	BYTE response[RDPEAR_NT_RESPONSE_LENGTH] = { 0 };

	if (!service_call(RemoteCallNtlmCalculateNtResponse, calculateNtResponseArm,
	                  sizeof(calculateNtResponseArm), FALSE, &status, response, sizeof(response)))
		return -1;

	if (status != (UINT32)STATUS_NOT_SUPPORTED)
	{
		(void)fprintf(stderr, "no key: unexpected status 0x%08" PRIx32 "\n", status);
		return -1;
	}
	return 0;
}

int TestRdpearNtlmV1(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (test_calculate_nt_response() != 0)
		return -1;
	if (test_calculate_user_session_key() != 0)
		return -1;
	if (test_no_key() != 0)
		return -1;
	return 0;
}
