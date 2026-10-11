/**
 * WinPR: Windows Portable Runtime
 * Remote Credential Guard NTLM supplemental secrets (AES-GCM seal)
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

#include <winpr/config.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/crypto.h>
#include <winpr/credssp.h>

#include "../../log.h"

#define TAG WINPR_TAG("sspi.CredSSP.ntlm_rguard")

#define RGUARD_TAG_LEN 16u
#define RGUARD_NONCE_LEN 12u
/* [tag(16)][nonce(12)][reserved(4)] header precedes the ciphertext. */
#define RGUARD_HEADER_LEN WINPR_NTLM_RGUARD_SEAL_OVERHEAD

static WINPR_CIPHER_TYPE rguard_cipher_for_key(size_t keyLen)
{
	switch (keyLen)
	{
		case 16:
			return WINPR_CIPHER_AES_128_GCM;
		case 32:
			return WINPR_CIPHER_AES_256_GCM;
		default:
			return WINPR_CIPHER_NONE;
	}
}

BOOL winpr_ntlm_rguard_secrets_seal(const BYTE* key, size_t keyLen, const BYTE* plaintext,
                                    size_t plaintextLen, SecBuffer* output)
{
	BOOL rc = FALSE;
	WINPR_CIPHER_CTX* ctx = NULL;
	BYTE nonce[RGUARD_NONCE_LEN] = { 0 };

	if (!key || !output || (!plaintext && (plaintextLen != 0)))
		return FALSE;

	const WINPR_CIPHER_TYPE cipher = rguard_cipher_for_key(keyLen);
	if (cipher == WINPR_CIPHER_NONE)
	{
		WLog_ERR(TAG, "unsupported key length %" PRIuz, keyLen);
		return FALSE;
	}

	if (plaintextLen > UINT32_MAX - RGUARD_HEADER_LEN)
		return FALSE;

	if (winpr_RAND(nonce, sizeof(nonce)) != 0)
		return FALSE;

	if (!sspi_SecBufferAlloc(output, (ULONG)(RGUARD_HEADER_LEN + plaintextLen)))
		return FALSE;

	BYTE* blob = output->pvBuffer;

	ctx = winpr_Cipher_NewEx(cipher, WINPR_ENCRYPT, key, keyLen, nonce, sizeof(nonce));
	if (!ctx)
		goto fail;

	size_t olen = plaintextLen;
	if (plaintextLen > 0)
	{
		if (!winpr_Cipher_Update(ctx, plaintext, plaintextLen, blob + RGUARD_HEADER_LEN, &olen))
			goto fail;
	}

	size_t flen = 0;
	if (!winpr_Cipher_Final(ctx, blob + RGUARD_HEADER_LEN + olen, &flen))
		goto fail;

	if (!winpr_Cipher_GetTag(ctx, blob, RGUARD_TAG_LEN))
		goto fail;

	/* [tag(16)][nonce(12)][reserved(4) == 0][ciphertext] */
	memcpy(blob + RGUARD_TAG_LEN, nonce, sizeof(nonce));

	rc = TRUE;

fail:
	winpr_Cipher_Free(ctx);
	if (!rc)
		sspi_SecBufferFree(output);
	return rc;
}

BOOL winpr_ntlm_rguard_secrets_unseal(const BYTE* key, size_t keyLen, const BYTE* blob,
                                      size_t blobLen, SecBuffer* output)
{
	BOOL rc = FALSE;
	WINPR_CIPHER_CTX* ctx = NULL;

	if (!key || !blob || !output || (blobLen < RGUARD_HEADER_LEN))
		return FALSE;

	const WINPR_CIPHER_TYPE cipher = rguard_cipher_for_key(keyLen);
	if (cipher == WINPR_CIPHER_NONE)
	{
		WLog_ERR(TAG, "unsupported key length %" PRIuz, keyLen);
		return FALSE;
	}

	const BYTE* tag = blob;
	const BYTE* nonce = blob + RGUARD_TAG_LEN;
	const BYTE* ciphertext = blob + RGUARD_HEADER_LEN;
	const size_t ciphertextLen = blobLen - RGUARD_HEADER_LEN;

	if (!sspi_SecBufferAlloc(output, (ULONG)(ciphertextLen ? ciphertextLen : 1)))
		return FALSE;
	output->cbBuffer = (ULONG)ciphertextLen;

	ctx = winpr_Cipher_NewEx(cipher, WINPR_DECRYPT, key, keyLen, nonce, RGUARD_NONCE_LEN);
	if (!ctx)
		goto fail;

	if (!winpr_Cipher_SetTag(ctx, tag, RGUARD_TAG_LEN))
		goto fail;

	size_t olen = ciphertextLen;
	if (ciphertextLen > 0)
	{
		if (!winpr_Cipher_Update(ctx, ciphertext, ciphertextLen, output->pvBuffer, &olen))
			goto fail;
	}

	size_t flen = 0;
	/* GCM tag verification happens here: a tampered blob or wrong key fails Final. */
	if (!winpr_Cipher_Final(ctx, (BYTE*)output->pvBuffer + olen, &flen))
		goto fail;

	output->cbBuffer = (ULONG)(olen + flen);
	rc = TRUE;

fail:
	winpr_Cipher_Free(ctx);
	if (!rc)
		sspi_SecBufferFree(output);
	return rc;
}

/* MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL wire layout (see [MS-RDPEAR]/tspkg BuildRemoteCred):
 *   UINT32 Version (= 0xffff0002), UINT32 Flags, BYTE CredentialKey[16], UINT32 CredentialKeyType,
 *   UINT32 Reserved, UINT32 EncryptedCredsSize, BYTE EncryptedCreds[]. */
#define RGUARD_SUPP_CREDKEY_LEN 16u
#define RGUARD_SUPP_HEADER_LEN (4u + 4u + RGUARD_SUPP_CREDKEY_LEN + 4u + 4u + 4u)

BOOL winpr_ntlm_rguard_build_supplemental(const BYTE* secret, size_t secretLen, const BYTE* key,
                                          size_t keyLen, SecBuffer* credBuffer)
{
	BOOL rc = FALSE;
	SecBuffer sealed = { 0 };

	if (!secret || !key || !credBuffer)
		return FALSE;

	if (!winpr_ntlm_rguard_secrets_seal(key, keyLen, secret, secretLen, &sealed))
		return FALSE;

	if (sealed.cbBuffer > UINT32_MAX - RGUARD_SUPP_HEADER_LEN)
		goto out;

	if (!sspi_SecBufferAlloc(credBuffer, RGUARD_SUPP_HEADER_LEN + sealed.cbBuffer))
		goto out;

	wStream sbuffer = { 0 };
	wStream* s = Stream_StaticInit(&sbuffer, credBuffer->pvBuffer, credBuffer->cbBuffer);
	Stream_Write_UINT32(s, WINPR_MSV1_0_REMOTE_SUPPLEMENTAL_VERSION); /* Version */
	Stream_Write_UINT32(s, 0);                                        /* Flags */
	Stream_Zero(s, RGUARD_SUPP_CREDKEY_LEN);           /* CredentialKey (kept client-side) */
	Stream_Write_UINT32(s, 0);                         /* CredentialKeyType */
	Stream_Write_UINT32(s, 0);                         /* Reserved */
	Stream_Write_UINT32(s, sealed.cbBuffer);           /* EncryptedCredsSize */
	Stream_Write(s, sealed.pvBuffer, sealed.cbBuffer); /* EncryptedCreds */

	rc = TRUE;

out:
	sspi_SecBufferFree(&sealed);
	if (!rc)
		sspi_SecBufferFree(credBuffer);
	return rc;
}
