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

#ifndef FREERDP_CHANNEL_RDPEAR_NTLM_H
#define FREERDP_CHANNEL_RDPEAR_NTLM_H

#include <winpr/wtypes.h>
#include <winpr/crypto.h>
#include <freerdp/api.h>

#define RDPEAR_NTOWF_LENGTH 16u
#define RDPEAR_NT_RESPONSE_LENGTH 24u
#define RDPEAR_SESSION_KEY_LENGTH 16u

#ifdef __cplusplus
extern "C"
{
#endif

	/** @brief NTLMv1 NT one-way function: MD4 of the UTF-16LE password. */
	WINPR_ATTR_NODISCARD
	FREERDP_LOCAL BOOL rdpear_ntowf_v1(const WCHAR* password, size_t passwordLen,
	                                   BYTE out[RDPEAR_NTOWF_LENGTH]);

	/** @brief NTLMv2 one-way function: HMAC-MD5(NTOWFv1, upper(user) || domain), UTF-16LE. */
	WINPR_ATTR_NODISCARD
	FREERDP_LOCAL BOOL rdpear_ntowf_v2(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH], const WCHAR* user,
	                                   size_t userLen, const WCHAR* domain, size_t domainLen,
	                                   BYTE out[RDPEAR_NTOWF_LENGTH]);

	/** @brief NTLMv1 NT response: DESL(NTOWFv1, serverChallenge[8]) -> 24 bytes. */
	WINPR_ATTR_NODISCARD
	FREERDP_LOCAL BOOL rdpear_ntlm_v1_response(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH],
	                                           const BYTE challenge[8],
	                                           BYTE out[RDPEAR_NT_RESPONSE_LENGTH]);

	/** @brief NTLMv1 user session key: MD4(NTOWFv1) -> 16 bytes. */
	WINPR_ATTR_NODISCARD
	FREERDP_LOCAL BOOL rdpear_ntlm_v1_user_session_key(const BYTE ntowfv1[RDPEAR_NTOWF_LENGTH],
	                                                   BYTE out[RDPEAR_SESSION_KEY_LENGTH]);

	/** @brief NTLMv2 NTProofStr and session base key.
	 *
	 * ntProof = HMAC-MD5(NTOWFv2, serverChallenge || clientBlob); sessionBaseKey =
	 * HMAC-MD5(NTOWFv2, ntProof). The full NtChallengeResponse is ntProof || clientBlob.
	 *
	 * @param ntowfv2 the NTLMv2 OWF
	 * @param challenge the 8-byte server challenge
	 * @param blob the client "temp" blob (NTLMv2_CLIENT_CHALLENGE and target info)
	 * @param blobLen the blob length
	 * @param ntProof receives the 16-byte NTProofStr
	 * @param sessionBaseKey receives the 16-byte session base key
	 */
	WINPR_ATTR_NODISCARD
	FREERDP_LOCAL BOOL rdpear_ntlm_v2_response(const BYTE ntowfv2[RDPEAR_NTOWF_LENGTH],
	                                           const BYTE challenge[8], const BYTE* blob,
	                                           size_t blobLen, BYTE ntProof[16],
	                                           BYTE sessionBaseKey[16]);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_RDPEAR_NTLM_H */
