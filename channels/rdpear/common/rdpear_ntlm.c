/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * [MS-RDPEAR] NTLM redirected-call computations
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

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/crypto.h>

#include "rdpear-common/rdpear_ntlm.h"

/* Expand a 7-byte block into an 8-byte DES key (7 bits of key per byte + a (ignored) parity bit),
 * per [MS-NLMP] 6 / the classic LM/NTLM key schedule. */
static void des_key_from_7(const BYTE in[7], BYTE out[8])
{
	out[0] = (BYTE)(in[0] & 0xFE);
	out[1] = (BYTE)(((in[0] << 7) | (in[1] >> 1)) & 0xFE);
	out[2] = (BYTE)(((in[1] << 6) | (in[2] >> 2)) & 0xFE);
	out[3] = (BYTE)(((in[2] << 5) | (in[3] >> 3)) & 0xFE);
	out[4] = (BYTE)(((in[3] << 4) | (in[4] >> 4)) & 0xFE);
	out[5] = (BYTE)(((in[4] << 3) | (in[5] >> 5)) & 0xFE);
	out[6] = (BYTE)(((in[5] << 2) | (in[6] >> 6)) & 0xFE);
	out[7] = (BYTE)((in[6] << 1) & 0xFE);
}

/* DES-ECB encrypt an 8-byte block with a 7-byte key (expanded to 8).
 *
 * Single DES is in OpenSSL 3's legacy provider (often not loaded), so compute it as triple DES
 * with all three keys equal: EDE3(K,K,K) = E_K(D_K(E_K(x))) = E_K(x). DES-EDE3 is in the default
 * provider, matching how NTLM elsewhere avoids the legacy single-DES. */
static BOOL desl_block(const BYTE key7[7], const BYTE data[8], BYTE out[8])
{
	BYTE key8[8] = { 0 };
	des_key_from_7(key7, key8);

	BYTE key24[24] = { 0 };
	memcpy(&key24[0], key8, 8);
	memcpy(&key24[8], key8, 8);
	memcpy(&key24[16], key8, 8);

	WINPR_CIPHER_CTX* ctx =
	    winpr_Cipher_NewEx(WINPR_CIPHER_DES_EDE3_ECB, WINPR_ENCRYPT, key24, sizeof(key24), NULL, 0);
	if (!ctx)
		return FALSE;

	BOOL rc = FALSE;
	size_t olen = 8;
	if (winpr_Cipher_Update(ctx, data, 8, out, &olen))
		rc = (olen == 8);
	winpr_Cipher_Free(ctx);
	return rc;
}

/* DESL(K[16], D[8]) = DES(K[0:7],D) || DES(K[7:14],D) || DES(K[14:16]+5*0,D). */
static BOOL desl(const BYTE key[RDPEAR_NTOWF_LENGTH], const BYTE data[8],
                 BYTE out[RDPEAR_NT_RESPONSE_LENGTH])
{
	BYTE k3[7] = { 0 };
	k3[0] = key[14];
	k3[1] = key[15];
	return desl_block(&key[0], data, &out[0]) && desl_block(&key[7], data, &out[8]) &&
	       desl_block(k3, data, &out[16]);
}

BOOL rdpear_ntowf_v1(const WCHAR* password, size_t passwordLen, BYTE out[RDPEAR_NTOWF_LENGTH])
{
	if (!password && (passwordLen != 0))
		return FALSE;
	if (passwordLen > INT_MAX / sizeof(WCHAR))
		return FALSE;
	return winpr_Digest(WINPR_MD_MD4, password, passwordLen * sizeof(WCHAR), out,
	                    RDPEAR_NTOWF_LENGTH);
}

BOOL rdpear_ntowf_v2(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH], const WCHAR* user, size_t userLen,
                     const WCHAR* domain, size_t domainLen, BYTE out[RDPEAR_NTOWF_LENGTH])
{
	BOOL rc = FALSE;
	WCHAR* buffer = NULL;

	if (!ntowfv1 || (!user && (userLen != 0)) || (!domain && (domainLen != 0)))
		return FALSE;
	if ((userLen > (SIZE_MAX / sizeof(WCHAR)) - domainLen - 1))
		return FALSE;

	/* HMAC-MD5(NTOWFv1, ToUpper(user) || domain) as UTF-16LE */
	const size_t count = userLen + domainLen;
	buffer = (WCHAR*)calloc(count + 1, sizeof(WCHAR));
	if (!buffer)
		return FALSE;

	for (size_t i = 0; i < userLen; i++)
	{
		WCHAR c = user[i];
		if ((c >= L'a') && (c <= L'z'))
			c = (WCHAR)(c - L'a' + L'A');
		buffer[i] = c;
	}
	if (domainLen > 0)
		memcpy(&buffer[userLen], domain, domainLen * sizeof(WCHAR));

	rc = winpr_HMAC(WINPR_MD_MD5, ntowfv1, RDPEAR_NTOWF_LENGTH, (const BYTE*)buffer,
	                count * sizeof(WCHAR), out, RDPEAR_NTOWF_LENGTH);

	free(buffer);
	return rc;
}

BOOL rdpear_ntlm_v1_response(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH], const BYTE challenge[8],
                             BYTE out[RDPEAR_NT_RESPONSE_LENGTH])
{
	if (!ntowfv1 || !challenge || !out)
		return FALSE;
	return desl(ntowfv1, challenge, out);
}

BOOL rdpear_ntlm_v1_user_session_key(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH],
                                     BYTE out[RDPEAR_SESSION_KEY_LENGTH])
{
	if (!ntowfv1 || !out)
		return FALSE;
	/* The NTLMv1 user session key is MD4 of the NT OWF. */
	return winpr_Digest(WINPR_MD_MD4, ntowfv1, RDPEAR_NTOWF_LENGTH, out, RDPEAR_SESSION_KEY_LENGTH);
}

BOOL rdpear_ntlm_v2_response(const BYTE ntowfv2[RDPEAR_NTOWF_LENGTH], const BYTE challenge[8],
                             const BYTE* blob, size_t blobLen, BYTE ntProof[16],
                             BYTE sessionBaseKey[16])
{
	BOOL rc = FALSE;
	WINPR_HMAC_CTX* hmac = NULL;

	if (!ntowfv2 || !challenge || (!blob && (blobLen != 0)) || !ntProof || !sessionBaseKey)
		return FALSE;

	/* NTProofStr = HMAC-MD5(NTOWFv2, serverChallenge || blob) */
	hmac = winpr_HMAC_New();
	if (!hmac)
		return FALSE;
	if (!winpr_HMAC_Init(hmac, WINPR_MD_MD5, ntowfv2, RDPEAR_NTOWF_LENGTH))
		goto out;
	if (!winpr_HMAC_Update(hmac, challenge, 8))
		goto out;
	if ((blobLen > 0) && !winpr_HMAC_Update(hmac, blob, blobLen))
		goto out;
	if (!winpr_HMAC_Final(hmac, ntProof, 16))
		goto out;

	/* SessionBaseKey = HMAC-MD5(NTOWFv2, NTProofStr) */
	if (!winpr_HMAC(WINPR_MD_MD5, ntowfv2, RDPEAR_NTOWF_LENGTH, ntProof, 16, sessionBaseKey, 16))
		goto out;

	rc = TRUE;
out:
	winpr_HMAC_Free(hmac);
	return rc;
}

BOOL rdpear_ntlm_av_find(const BYTE* avPairs, size_t len, UINT16 avId, const BYTE** pvalue,
                         UINT16* pvalueLen)
{
	if (!avPairs || !pvalue || !pvalueLen)
		return FALSE;

	size_t off = 0;
	while (off + 4 <= len)
	{
		const UINT16 id = (UINT16)(avPairs[off] | ((UINT16)avPairs[off + 1] << 8));
		const UINT16 l = (UINT16)(avPairs[off + 2] | ((UINT16)avPairs[off + 3] << 8));
		off += 4;

		if (id == 0 /* MsvAvEOL */)
			break;
		if (off + l > len)
			return FALSE;
		if (id == avId)
		{
			*pvalue = &avPairs[off];
			*pvalueLen = l;
			return TRUE;
		}
		off += l;
	}
	return FALSE;
}

BOOL rdpear_ntlm_v2_build_temp(const BYTE timestamp[8], const BYTE clientChallenge[8],
                               const BYTE* targetInfo, size_t targetInfoLen, BYTE** ptemp,
                               size_t* ptempLen)
{
	/* 1 + 1 + Z(6) + 8 + 8 + Z(4) + targetInfo + Z(4) = 32 + targetInfoLen */
	if (!timestamp || !clientChallenge || (!targetInfo && (targetInfoLen != 0)) || !ptemp ||
	    !ptempLen)
		return FALSE;
	if (targetInfoLen > SIZE_MAX - 32)
		return FALSE;

	const size_t tempLen = 32 + targetInfoLen;
	BYTE* temp = (BYTE*)calloc(1, tempLen);
	if (!temp)
		return FALSE;

	size_t o = 0;
	temp[o++] = 0x01; /* RespType */
	temp[o++] = 0x01; /* HiRespType */
	o += 6;           /* Reserved1(2) + Reserved2(4) == Z(6) */
	memcpy(&temp[o], timestamp, 8);
	o += 8;
	memcpy(&temp[o], clientChallenge, 8);
	o += 8;
	o += 4; /* Z(4) */
	if (targetInfoLen > 0)
		memcpy(&temp[o], targetInfo, targetInfoLen);
	/* trailing Z(4) at o + targetInfoLen is left zero by calloc */

	*ptemp = temp;
	*ptempLen = tempLen;
	return TRUE;
}
