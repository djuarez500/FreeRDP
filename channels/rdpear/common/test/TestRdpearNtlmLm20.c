/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * [MS-RDPEAR] NTLM Lm20GetNtlm3ChallengeResponse (0x202) parse and servicing test
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
#include <winpr/string.h>
#include <winpr/stream.h>
#include <winpr/asn1.h>
#include <winpr/credssp.h>

#include <winpr/ndr.h>
#include "rdpear-common/rdpear_common.h"
#include "rdpear-common/rdpear_kerb.h"
#include "rdpear-common/rdpear_ntlm.h"

/* The request arm of a real redirected MSV1_0 Lm20GetNtlm3ChallengeResponse (callId 0x202),
 * captured on the wire (the bytes following the two callId UINT16s). It carries the forwarded
 * NTLM secret (EncryptedSecrets, 48-byte sealed blob), UserName "Administrator", LogonDomainName
 * "DOMAIN", the server target-info as ServerName, and the 8-byte server challenge. */
static const BYTE lm20RequestArm[] = {
	0x04, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x14, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x02, 0x00,
	0x4b, 0x66, 0x76, 0x47, 0xe4, 0x28, 0xbc, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x30, 0x00, 0x00, 0x00,
	0xdc, 0xe8, 0x04, 0x48, 0xb6, 0xeb, 0xd2, 0xfc, 0xa8, 0x07, 0x27, 0x0f, 0x46, 0x67, 0xc4, 0x62,
	0x53, 0x49, 0xd2, 0x45, 0xc3, 0xdf, 0x67, 0x86, 0x36, 0x71, 0xff, 0xbd, 0x00, 0x00, 0x00, 0x00,
	0xb7, 0x99, 0x99, 0xf8, 0x4d, 0x94, 0xa7, 0xe9, 0x7e, 0xc1, 0xe4, 0xa1, 0x99, 0xd7, 0x07, 0xa8,
	0x1a, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0d, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00,
	0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x00, 0x00,
	0x0c, 0x00, 0x0e, 0x00, 0x18, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00,
	0xfc, 0x00, 0xfc, 0x00, 0x20, 0x00, 0x02, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00,
	0x49, 0x00, 0x4e, 0x00, 0x01, 0x00, 0x10, 0x00, 0x57, 0x00, 0x53, 0x00, 0x32, 0x00, 0x30, 0x00,
	0x32, 0x00, 0x32, 0x00, 0x44, 0x00, 0x43, 0x00, 0x04, 0x00, 0x14, 0x00, 0x44, 0x00, 0x4f, 0x00,
	0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2e, 0x00, 0x54, 0x00, 0x4d, 0x00, 0x50, 0x00,
	0x03, 0x00, 0x26, 0x00, 0x57, 0x00, 0x53, 0x00, 0x32, 0x00, 0x30, 0x00, 0x32, 0x00, 0x32, 0x00,
	0x44, 0x00, 0x43, 0x00, 0x2e, 0x00, 0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00,
	0x4e, 0x00, 0x2e, 0x00, 0x54, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x05, 0x00, 0x14, 0x00, 0x44, 0x00,
	0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2e, 0x00, 0x54, 0x00, 0x4d, 0x00,
	0x50, 0x00, 0x07, 0x00, 0x08, 0x00, 0x9e, 0x96, 0x34, 0xbe, 0xc6, 0x59, 0xdd, 0x01, 0x06, 0x00,
	0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x66, 0x97, 0xf8, 0xba, 0x24, 0x04,
	0x6d, 0x50, 0x8d, 0xd1, 0xbd, 0x2e, 0x1b, 0xcb, 0x9a, 0x46, 0x27, 0xb1, 0x0b, 0x70, 0xd4, 0xfa,
	0xbe, 0x0b, 0x17, 0xd2, 0xf6, 0xcf, 0x48, 0xb6, 0xdb, 0xa7, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x1a, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x32, 0x00, 0x30, 0x00,
	0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00
};

static BOOL wcharEquals(const WCHAR* buffer, UINT32 count, const char* expected)
{
	const size_t expLen = strlen(expected);
	if (count != expLen)
		return FALSE;
	for (size_t i = 0; i < expLen; i++)
	{
		if (buffer[i] != (WCHAR)expected[i])
			return FALSE;
	}
	return TRUE;
}

static int test_parse(void)
{
	int rc = -1;
	WinPrNdrDecoder* decoder = winpr_ndr_decoder_new(FALSE, 1);
	Lm20GetNtlm3ChallengeResponseReq req = { 0 };
	wStream staticStream = { 0 };
	wStream* s = Stream_StaticConstInit(&staticStream, lm20RequestArm, sizeof(lm20RequestArm));

	if (!decoder)
		return -1;

	if (!ndr_decoder_read_Lm20GetNtlm3ChallengeResponseReq(decoder, s, NULL, &req) ||
	    !winpr_ndr_decoder_treat_deferreds(decoder, s))
	{
		(void)fprintf(stderr, "failed to parse the 0x202 request arm\n");
		goto out;
	}

	const BYTE challengeExp[8] = { 0x4b, 0x66, 0x76, 0x47, 0xe4, 0x28, 0xbc, 0xfd };
	if (memcmp(req.ChallengeToClient, challengeExp, sizeof(challengeExp)) != 0)
	{
		(void)fprintf(stderr, "ChallengeToClient mismatch\n");
		goto out;
	}

	if (!req.Credential || (req.Credential->reservedSize.count != 48))
	{
		(void)fprintf(stderr, "EncryptedSecrets length mismatch\n");
		goto out;
	}
	const BYTE sealedHeadExp[4] = { 0xdc, 0xe8, 0x04, 0x48 };
	if (memcmp(req.Credential->reserved6, sealedHeadExp, sizeof(sealedHeadExp)) != 0)
	{
		(void)fprintf(stderr, "EncryptedSecrets content mismatch\n");
		goto out;
	}

	if (!req.UserName ||
	    !wcharEquals(req.UserName->Buffer, req.UserName->strLength, "Administrator"))
	{
		(void)fprintf(stderr, "UserName mismatch\n");
		goto out;
	}
	if (!req.LogonDomainName ||
	    !wcharEquals(req.LogonDomainName->Buffer, req.LogonDomainName->strLength, "DOMAIN"))
	{
		(void)fprintf(stderr, "LogonDomainName mismatch\n");
		goto out;
	}

	if (!req.ServerName || (req.ServerName->lenHints.length != 252))
	{
		(void)fprintf(stderr, "ServerName length mismatch\n");
		goto out;
	}

	/* The server MsvAvTimestamp (AvId 7) must be reachable in the target info. */
	const BYTE* ts = NULL;
	UINT16 tsLen = 0;
	const BYTE tsExp[8] = { 0x9e, 0x96, 0x34, 0xbe, 0xc6, 0x59, 0xdd, 0x01 };
	if (!rdpear_ntlm_av_find((const BYTE*)req.ServerName->Buffer, req.ServerName->lenHints.length,
	                         0x0007, &ts, &tsLen) ||
	    (tsLen != sizeof(tsExp)) || (memcmp(ts, tsExp, sizeof(tsExp)) != 0))
	{
		(void)fprintf(stderr, "MsvAvTimestamp not found/mismatch\n");
		goto out;
	}

	rc = 0;
out:
	ndr_destroy_Lm20GetNtlm3ChallengeResponseReq(NULL, &req);
	winpr_ndr_decoder_destroy(&decoder);
	return rc;
}

static int test_build_temp(void)
{
	/* [MS-NLMP] 4.2.4: time 0, client challenge 0xaa..aa, Domain/Server target info. */
	const BYTE clientChallenge[8] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	const BYTE timestamp[8] = { 0 };
	const BYTE targetInfo[] = { 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d,
		                        0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x01, 0x00,
		                        0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76,
		                        0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const BYTE tempExp[] = { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                     0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		                     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00,
		                     0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00,
		                     0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
		                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE* temp = NULL;
	size_t tempLen = 0;
	int rc = -1;

	if (!rdpear_ntlm_v2_build_temp(timestamp, clientChallenge, targetInfo, sizeof(targetInfo),
	                               &temp, &tempLen))
	{
		(void)fprintf(stderr, "build_temp failed\n");
		return -1;
	}

	if ((tempLen != sizeof(tempExp)) || (memcmp(temp, tempExp, tempLen) != 0))
		(void)fprintf(stderr, "temp mismatch (len=%" PRIuz ")\n", tempLen);
	else
		rc = 0;

	free(temp);
	return rc;
}

static void toWchar(const char* src, WCHAR* dst, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = (WCHAR)src[i];
}

/* Service the captured request end to end (decode, handler, encode, free), with its forwarded
 * secret resealed under a test key, and check the NTLMv2 response in the reply. */
static int test_service(void)
{
	const BYTE key[16] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
		                   0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
	const BYTE owf[RDPEAR_NTOWF_LENGTH] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
	const BYTE sealedHead[4] = { 0xdc, 0xe8, 0x04, 0x48 };
	const BYTE challenge[8] = { 0x4b, 0x66, 0x76, 0x47, 0xe4, 0x28, 0xbc, 0xfd };
	const BYTE timestamp[8] = { 0x9e, 0x96, 0x34, 0xbe, 0xc6, 0x59, 0xdd, 0x01 };
	const size_t sealedLen = 48;

	int rc = -1;
	krb5_context krb = NULL;
	SecBuffer sealed = { 0 };
	wStream* payload = NULL;
	wStream* request = NULL;
	wStream* response = NULL;
	BYTE arm[sizeof(lm20RequestArm)] = { 0 };

	/* reseal the forwarded secret: the key it was captured with is gone */
	memcpy(arm, lm20RequestArm, sizeof(arm));
	size_t at = 0;
	for (; at + sealedLen <= sizeof(arm); at++)
	{
		if (memcmp(&arm[at], sealedHead, sizeof(sealedHead)) == 0)
			break;
	}
	if ((at + sealedLen > sizeof(arm)) ||
	    !winpr_ntlm_rguard_secrets_seal(key, sizeof(key), owf, sizeof(owf), &sealed) ||
	    (sealed.cbBuffer != sealedLen))
	{
		(void)fprintf(stderr, "failed to reseal the forwarded secret\n");
		goto out;
	}
	memcpy(&arm[at], sealed.pvBuffer, sealedLen);

	/* [MS-RDPEAR] payload: 16-byte header, then the type serialized NtlmCredIsoRemoteInput */
	const size_t objectLen = (8 + sizeof(arm) + 7) & ~(size_t)7;
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
	Stream_Write_UINT16(payload, RemoteCallNtlmLm20GetNtlm3ChallengeResponse); /* CallId */
	Stream_Write_UINT16(payload, RemoteCallNtlmLm20GetNtlm3ChallengeResponse); /* union arm */
	Stream_Write(payload, arm, sizeof(arm));
	Stream_Zero(payload, objectLen - 8 - sizeof(arm));

	request = rdpear_encodePayload(RDPEAR_PACKAGE_NTLM, payload);
	if (!request || (krb5_init_context(&krb) != 0))
		goto out;

	response = rdpear_kerb_service(krb, key, sizeof(key), Stream_Buffer(request),
	                               Stream_GetPosition(request));
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
	 * common and private headers: the top-level referent, CallId, Status, the union arm, then
	 * Lm20GetNtlm3ChallengeResponseResp (Ntlm3ResponseLength, Ntlm3Response, Lm3Response,
	 * UserSessionKey, LmSessionKey) and the deferred Ntlm3Response array */
	wStream rbuffer = { 0 };
	wStream* rs = Stream_StaticConstInit(&rbuffer, reply.data, reply.len);
	if (Stream_GetRemainingLength(rs) < 32 + 76)
	{
		(void)fprintf(stderr, "reply too short (%" PRIuz " bytes)\n", reply.len);
		goto out;
	}

	UINT16 callId = 0;
	UINT32 status = 0;
	UINT16 ntLen = 0;
	UINT32 maxCount = 0;
	BYTE sessionKey[16] = { 0 };
	Stream_Seek(rs, 32);                             /* payload, NDR common and private headers */
	Stream_Seek(rs, 4);                              /* top-level referent */
	Stream_Read_UINT16(rs, callId);                  /* CallId */
	Stream_Seek(rs, 2);                              /* padding */
	Stream_Read_UINT32(rs, status);                  /* Status */
	Stream_Seek(rs, 4);                              /* union arm, padding */
	Stream_Read_UINT16(rs, ntLen);                   /* Ntlm3ResponseLength */
	Stream_Seek(rs, 2);                              /* padding */
	Stream_Seek(rs, 4);                              /* Ntlm3Response referent */
	Stream_Seek(rs, 24);                             /* Lm3Response */
	Stream_Read(rs, sessionKey, sizeof(sessionKey)); /* UserSessionKey */
	Stream_Seek(rs, 8);                              /* LmSessionKey */
	Stream_Read_UINT32(rs, maxCount);                /* Ntlm3Response conformance */
	if ((callId != RemoteCallNtlmLm20GetNtlm3ChallengeResponse) || (status != 0) ||
	    (ntLen <= 16 + 28) || (maxCount != ntLen) || (Stream_GetRemainingLength(rs) < ntLen))
	{
		(void)fprintf(stderr,
		              "unexpected reply: callId=0x%04" PRIx16 " status=0x%08" PRIx32
		              " length=%" PRIu16 " count=%" PRIu32 "\n",
		              callId, status, ntLen, maxCount);
		goto out;
	}

	/* Ntlm3Response: NTProofStr, then the temp; the temp must carry the server timestamp
	 * ([MS-NLMP] 2.2.2.7: after RespType, HiRespType, Reserved1 and Reserved2) */
	BYTE ntProofIn[16] = { 0 };
	BYTE tempTimestamp[8] = { 0 };
	Stream_Read(rs, ntProofIn, sizeof(ntProofIn));
	const BYTE* temp = Stream_ConstPointer(rs);
	Stream_Seek(rs, 8);
	Stream_Read(rs, tempTimestamp, sizeof(tempTimestamp));
	if (memcmp(tempTimestamp, timestamp, sizeof(timestamp)) != 0)
	{
		(void)fprintf(stderr, "the temp does not carry the server timestamp\n");
		goto out;
	}

	/* recompute NTProofStr and the session base key from the reply's own temp */
	WCHAR user[13] = { 0 };
	WCHAR domain[6] = { 0 };
	toWchar("Administrator", user, ARRAYSIZE(user));
	toWchar("DOMAIN", domain, ARRAYSIZE(domain));
	BYTE ntowfv2[RDPEAR_NTOWF_LENGTH] = { 0 };
	BYTE proof[16] = { 0 };
	BYTE baseKey[16] = { 0 };
	if (!rdpear_ntowf_v2(owf, user, ARRAYSIZE(user), domain, ARRAYSIZE(domain), ntowfv2) ||
	    !rdpear_ntlm_v2_response(ntowfv2, challenge, temp, ntLen - 16u, proof, baseKey))
		goto out;
	if ((memcmp(proof, ntProofIn, sizeof(proof)) != 0) ||
	    (memcmp(baseKey, sessionKey, sizeof(baseKey)) != 0))
	{
		(void)fprintf(stderr, "NTProofStr or UserSessionKey mismatch\n");
		goto out;
	}

	rc = 0;
out:
	Stream_Free(response, TRUE);
	Stream_Free(request, TRUE);
	Stream_Free(payload, TRUE);
	sspi_SecBufferFree(&sealed);
	if (krb)
		krb5_free_context(krb);
	return rc;
}

int TestRdpearNtlmLm20(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (test_parse() != 0)
		return -1;
	if (test_build_temp() != 0)
		return -1;
	if (test_service() != 0)
		return -1;
	return 0;
}
