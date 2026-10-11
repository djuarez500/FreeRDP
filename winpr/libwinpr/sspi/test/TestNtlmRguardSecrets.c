#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/credssp.h>

/* Round-trip, format and tamper tests for the Remote Credential Guard NTLM secret seal
 * (winpr_ntlm_rguard_secrets_seal / _unseal, AES-GCM). */

static BOOL check_roundtrip(const BYTE* key, size_t keyLen, const BYTE* pt, size_t ptLen)
{
	BOOL rc = FALSE;
	SecBuffer sealed = { 0 };
	SecBuffer opened = { 0 };

	if (!winpr_ntlm_rguard_secrets_seal(key, keyLen, pt, ptLen, &sealed))
	{
		(void)fprintf(stderr, "seal failed (keyLen=%" PRIuz ", ptLen=%" PRIuz ")\n", keyLen, ptLen);
		goto out;
	}

	if (sealed.cbBuffer != WINPR_NTLM_RGUARD_SEAL_OVERHEAD + ptLen)
	{
		(void)fprintf(stderr, "sealed size %" PRIu32 " != %" PRIuz "\n", sealed.cbBuffer,
		              WINPR_NTLM_RGUARD_SEAL_OVERHEAD + ptLen);
		goto out;
	}

	if (!winpr_ntlm_rguard_secrets_unseal(key, keyLen, sealed.pvBuffer, sealed.cbBuffer, &opened))
	{
		(void)fprintf(stderr, "unseal failed\n");
		goto out;
	}

	if ((opened.cbBuffer != ptLen) || ((ptLen > 0) && (memcmp(opened.pvBuffer, pt, ptLen) != 0)))
	{
		(void)fprintf(stderr, "round-trip mismatch (ptLen=%" PRIuz ")\n", ptLen);
		goto out;
	}

	/* ciphertext must not equal the plaintext */
	if ((ptLen > 0) &&
	    (memcmp((const BYTE*)sealed.pvBuffer + WINPR_NTLM_RGUARD_SEAL_OVERHEAD, pt, ptLen) == 0))
	{
		(void)fprintf(stderr, "ciphertext equals plaintext\n");
		goto out;
	}

	rc = TRUE;
out:
	sspi_SecBufferFree(&sealed);
	sspi_SecBufferFree(&opened);
	return rc;
}

int TestNtlmRguardSecrets(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	const BYTE key32[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		                     0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
		                     0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0 };
	const BYTE key16[16] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		                     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
	/* a 52-byte secret, the size the MSV1_0 remote secrets carry */
	BYTE secret[52];
	for (size_t i = 0; i < sizeof(secret); i++)
		secret[i] = (BYTE)(i * 7 + 1);

	/* AES-256 and AES-128 round trips, plus an empty and a single-byte secret */
	if (!check_roundtrip(key32, sizeof(key32), secret, sizeof(secret)))
		return -1;
	if (!check_roundtrip(key16, sizeof(key16), secret, sizeof(secret)))
		return -1;
	if (!check_roundtrip(key32, sizeof(key32), secret, 1))
		return -1;
	if (!check_roundtrip(key32, sizeof(key32), secret, 0))
		return -1;

	/* two seals of the same input must differ (fresh nonce) */
	{
		SecBuffer a = { 0 };
		SecBuffer b = { 0 };
		BOOL distinct = FALSE;
		if (winpr_ntlm_rguard_secrets_seal(key32, sizeof(key32), secret, sizeof(secret), &a) &&
		    winpr_ntlm_rguard_secrets_seal(key32, sizeof(key32), secret, sizeof(secret), &b))
		{
			distinct =
			    (a.cbBuffer == b.cbBuffer) && (memcmp(a.pvBuffer, b.pvBuffer, a.cbBuffer) != 0);
		}
		sspi_SecBufferFree(&a);
		sspi_SecBufferFree(&b);
		if (!distinct)
		{
			(void)fprintf(stderr, "two seals of the same input were identical\n");
			return -1;
		}
	}

	/* tamper detection: flipping any byte, or using the wrong key, must fail unseal */
	{
		SecBuffer sealed = { 0 };
		SecBuffer opened = { 0 };
		if (!winpr_ntlm_rguard_secrets_seal(key32, sizeof(key32), secret, sizeof(secret), &sealed))
			return -1;

		((BYTE*)sealed.pvBuffer)[WINPR_NTLM_RGUARD_SEAL_OVERHEAD] ^= 0x01; /* flip a cipher byte */
		if (winpr_ntlm_rguard_secrets_unseal(key32, sizeof(key32), sealed.pvBuffer, sealed.cbBuffer,
		                                     &opened))
		{
			(void)fprintf(stderr, "unseal accepted a tampered blob\n");
			sspi_SecBufferFree(&sealed);
			sspi_SecBufferFree(&opened);
			return -1;
		}
		((BYTE*)sealed.pvBuffer)[WINPR_NTLM_RGUARD_SEAL_OVERHEAD] ^= 0x01; /* restore */

		if (winpr_ntlm_rguard_secrets_unseal(key16, sizeof(key16), sealed.pvBuffer, sealed.cbBuffer,
		                                     &opened))
		{
			(void)fprintf(stderr, "unseal accepted the wrong key\n");
			sspi_SecBufferFree(&sealed);
			sspi_SecBufferFree(&opened);
			return -1;
		}
		sspi_SecBufferFree(&sealed);
		sspi_SecBufferFree(&opened);
	}

	/* a too-short blob must be rejected */
	{
		SecBuffer opened = { 0 };
		BYTE tiny[8] = { 0 };
		if (winpr_ntlm_rguard_secrets_unseal(key32, sizeof(key32), tiny, sizeof(tiny), &opened))
		{
			(void)fprintf(stderr, "unseal accepted a too-short blob\n");
			sspi_SecBufferFree(&opened);
			return -1;
		}
	}

	/* supplemental-cred builder: wire header + EncryptedCreds unseal round-trip */
	{
		const BYTE owf[16] = { 0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
			                   0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52 };
		SecBuffer cred = { 0 };
		SecBuffer opened = { 0 };
		BOOL ok = FALSE;

		if (!winpr_ntlm_rguard_build_supplemental(owf, sizeof(owf), key32, sizeof(key32), &cred))
		{
			(void)fprintf(stderr, "build_supplemental failed\n");
			return -1;
		}
		const BYTE* b = cred.pvBuffer;
		/* Version(4) Flags(4) CredentialKey(16) CredentialKeyType(4) Reserved(4) Size(4) + enc */
		const UINT32 version =
		    b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24);
		const UINT32 encSize =
		    b[32] | ((UINT32)b[33] << 8) | ((UINT32)b[34] << 16) | ((UINT32)b[35] << 24);
		if ((version == 0xffff0002) && (cred.cbBuffer == 36 + encSize) &&
		    winpr_ntlm_rguard_secrets_unseal(key32, sizeof(key32), b + 36, encSize, &opened) &&
		    (opened.cbBuffer == sizeof(owf)) && (memcmp(opened.pvBuffer, owf, sizeof(owf)) == 0))
			ok = TRUE;
		else
			(void)fprintf(stderr, "supplemental cred round-trip failed (ver=0x%08x)\n", version);

		sspi_SecBufferFree(&cred);
		sspi_SecBufferFree(&opened);
		if (!ok)
			return -1;
	}

	return 0;
}
