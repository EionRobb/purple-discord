/*
 *  Discord Plugin for Pidgin
 *  Copyright (C) 2021-2022 Eion Robb
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */



#if defined USE_OPENSSL_CRYPTO && !(defined __APPLE__ || defined __OpenBSD__)
#	undef USE_OPENSSL_CRYPTO
#endif

#if !defined USE_MBEDTLS_CRYPTO && !defined USE_OPENSSL_CRYPTO && !defined USE_NSS_CRYPTO && !defined USE_GCRYPT_CRYPTO
// #	ifdef _WIN32
// #		define USE_WIN32_CRYPTO
// #	else
#		define USE_NSS_CRYPTO
// #	endif
#endif


// Some of this is pinched from the gowhatsapp plugin
// Info from https://gitlab.com/beeper/discord/-/tree/main/remoteauth
//       and https://luna.gitlab.io/discord-unofficial-docs/desktop_remote_auth.html


static void
discord_null_cb() {
}

static void
discord_display_qrcode(PurpleConnection *pc, const gchar *qr_code_raw, const guchar *image_data, gsize image_data_len)
{
    DiscordAccount *da = purple_connection_get_protocol_data(pc);

    PurpleRequestFields *fields = purple_request_fields_new();
    PurpleRequestFieldGroup *group = purple_request_field_group_new(NULL);
    purple_request_fields_add_group(fields, group);

    PurpleRequestField *string_field = purple_request_field_string_new("qr_string", _("QR Code Data"), qr_code_raw, FALSE);
    purple_request_field_group_add_field(group, string_field);
	
    PurpleRequestField *image_field = purple_request_field_image_new("qr_image", _("QR Code Image"), (const gchar *)image_data, image_data_len);
    purple_request_field_group_add_field(group, image_field);

    const gchar *username = purple_account_get_username(da->account);
    gchar *secondary = g_strdup_printf(_("Discord account %s"), username);

    purple_request_fields(
        da->pc, /*handle*/
        _("Logon QR Code"), /*title*/
        _("Please scan this QR code with your phone"), /*primary*/
        secondary, /*secondary*/
        fields, /*fields*/
        _("OK"), G_CALLBACK(discord_null_cb), /*OK*/
        _("Dismiss"), G_CALLBACK(discord_null_cb), /*Cancel*/
        NULL, /*account*/
        username, /*username*/
        NULL, /*conversation*/
        NULL /*data*/
    );
	
	g_free(secondary);
	
}

static gchar *
discord_base64_make_urlsafe(gchar *inout)
{
	//basically - and _ replace + and /
	purple_util_chrreplace(inout, '+', '-');
	purple_util_chrreplace(inout, '/', '_');
	
	int i;
	for(i = strlen(inout) - 1; i >= 0; i--) {
		if(inout[i] == '=') {
			inout[i] = '\0';
		} else {
			break;
		}
	}
	
	return inout;
}



#include <qrencode.h>

// From qrencode/qrenc.c
static gchar * 
qrcode_utf8_output(const QRcode *qrcode)
{
	GString *out = g_string_new(NULL);
	int x, y;
	int realwidth;
	const int margin = 1;
	const char *empty, *lowhalf, *uphalf, *full;

	//empty = " ";
	empty = "\342\200\202";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	realwidth = (qrcode->width + margin * 2);

	/* top margin */
	for (x = 0; x < realwidth; x++) {
		g_string_append(out, full);
	}

	/* data */
	for(y = 0; y < qrcode->width; y += 2) {
		unsigned char *row1, *row2;
		row1 = qrcode->data + y*qrcode->width;
		row2 = row1 + qrcode->width;

		for (x = 0; x < margin; x++) {
			g_string_append(out, full);
		}

		for (x = 0; x < qrcode->width; x++) {
			if(row1[x] & 1) {
				if(y < qrcode->width - 1 && row2[x] & 1) {
					g_string_append(out, empty);
				} else {
					g_string_append(out, lowhalf);
				}
			} else if(y < qrcode->width - 1 && row2[x] & 1) {
				g_string_append(out, uphalf);
			} else {
				g_string_append(out, full);
			}
		}

		for (x = 0; x < margin; x++) {
			g_string_append(out, full);
		}

		g_string_append_c(out, '\n');
	}

	/* bottom margin */
	for (x = 0; x < realwidth; x++) {
		g_string_append(out, full);
	}

	return g_string_free(out, FALSE);;
}

// Based on the PNG output of qrencode/qrenc
static void 
qrcode_tga_fillRow(unsigned char *row, int num, const unsigned char color[])
{
	int i;

	for(i = 0; i < num; i++) {
		memcpy(row, color, 4);
		row += 4;
	}
}


static guchar * 
qrcode_tga_output(const QRcode *qrcode, gsize *out_len)
{
	GString *out = g_string_new(NULL);
	unsigned char *row, *p;
	int x, y, xx, yy;
	int realwidth, rowlen;
	const int margin = 1;
	const int size = 3;
	static unsigned char fg_color[4] = {0, 0, 0, 255};
	static unsigned char bg_color[4] = {255, 255, 255, 255};

	realwidth = (qrcode->width + margin * 2) * size;
	
	// From the telegram-purple plugin, which borrowed from pidgin-opensteamworks plugin
	const unsigned char tga_header[] = {
		// No ID; no color map; uncompressed true color
		0, 0, 2,
		// No color map metadata
		0, 0, 0, 0, 0,
		// No offsets
		0, 0, 0, 0,
		// Dimensions
		realwidth & 0xFF, (realwidth/256) & 0xFF, realwidth & 0xFF, (realwidth/256) & 0xFF,
		// 32 bits per pixel
		32,
		// "Origin in upper left-hand corner"
		32
	};
	g_string_append_len(out, (const gchar *)tga_header, sizeof(tga_header));
	
	rowlen = realwidth * 4;
	row = g_new(unsigned char, rowlen);
	
	if(row == NULL) {
		g_string_free(out, TRUE);
		if (out_len != NULL) {
			*out_len = 0;
		}
		return NULL;
	}

	/* top margin */
	qrcode_tga_fillRow(row, realwidth, bg_color);
	for(y = 0; y < margin * size; y++) {
		g_string_append_len(out, (const gchar *)row, rowlen);
	}

	/* data */
	p = qrcode->data;
	for(y = 0; y < qrcode->width; y++) {
		qrcode_tga_fillRow(row, realwidth, bg_color);
		for(x = 0; x < qrcode->width; x++) {
			for(xx = 0; xx < size; xx++) {
				if(*p & 1) {
					memcpy(&row[((margin + x) * size + xx) * 4], fg_color, 4);
				}
			}
			p++;
		}
		for(yy = 0; yy < size; yy++) {
			g_string_append_len(out, (const gchar *)row, rowlen);
		}
	}
	/* bottom margin */
	qrcode_tga_fillRow(row, realwidth, bg_color);
	for(y = 0; y < margin * size; y++) {
		g_string_append_len(out, (const gchar *)row, rowlen);
	}

	if (out_len != NULL) {
		*out_len = out->len;
	}
	return (guchar *)g_string_free(out, FALSE);
}

static const guchar *
discord_sha256(guchar *data, gsize len)
{
	GChecksum *hash;
	static unsigned char sha256Hash[32];
	gsize sha256HashLen = sizeof(sha256Hash);
	
	hash = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(hash, data, len);
	g_checksum_get_digest(hash, (guchar *)sha256Hash, &sha256HashLen);
	g_checksum_free(hash);
	
	return sha256Hash;
}

#ifdef USE_NSS_CRYPTO

#include <nss.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11pub.h>
#include <secdert.h>
#include <nssb64.h>


gboolean
discord_qrauth_generate_keys(DiscordAccount *da)
{
	SECKEYPrivateKey *prvKey = 0;
	SECKEYPublicKey *pubKey = 0;
	PK11SlotInfo *slot = 0;
	PK11RSAGenParams rsaParams;

	rsaParams.keySizeInBits = 2048;
	rsaParams.pe = 0x10001;

	slot = PK11_GetInternalKeySlot();
	if (!slot) { 
		return FALSE; 
	}

	prvKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaParams, &pubKey, PR_FALSE, PR_FALSE, 0);

	if (slot) {
		PK11_FreeSlot(slot);
	}

	if (!prvKey) { 
		return FALSE; 
	}

	//store in DiscordAccount
	g_dataset_set_data(da, "pubkey", pubKey);
	g_dataset_set_data(da, "prvkey", prvKey);

	return TRUE;
}

void
discord_qrauth_free_keys(DiscordAccount *da)
{
	SECKEYPublicKey *pubKey = g_dataset_get_data(da, "pubkey");
	SECKEYPrivateKey *prvKey = g_dataset_get_data(da, "prvkey");
	
	if (pubKey) {
		SECKEY_DestroyPublicKey(pubKey);
		g_dataset_remove_data(da, "pubkey");
	}
	if (prvKey) {
		SECKEY_DestroyPrivateKey(prvKey);
		g_dataset_remove_data(da, "prvkey");
	}
}

gchar *
discord_qrauth_get_pubkey_base64(DiscordAccount *da)
{
	SECKEYPublicKey *pubKey = g_dataset_get_data(da, "pubkey");
	if (!pubKey) {
		return NULL;
	}

	SECItem *cert_der = PK11_DEREncodePublicKey(pubKey);
	
	// gchar *b64crt = NSSBase64_EncodeItem(NULL, NULL, 0, cert_der);
	// purple_str_strip_char(b64crt, '\n');
	// purple_str_strip_char(b64crt, '\r');
	
	gchar *b64crt = g_base64_encode(cert_der->data, cert_der->len);
	
	SECITEM_FreeItem(cert_der, PR_TRUE);
	
	
	return b64crt;
}

guchar *
discord_qrauth_generate_proof(DiscordAccount *da, const gchar *encrypted_nonce, gsize *proof_len)
{
	SECKEYPublicKey *pubKey = g_dataset_get_data(da, "pubkey");
	SECKEYPrivateKey *prvKey = g_dataset_get_data(da, "prvkey");
	SECStatus rv = 0;
	unsigned char *out;
	unsigned int outlen;
	gsize nonce_len;
	guchar *nonce;
	
	if (!pubKey || !prvKey) {
		return NULL;
	}
	
	nonce = g_base64_decode(encrypted_nonce, &nonce_len);
	
	out = g_new0(unsigned char, 20480);
	rv = PK11_PubDecryptRaw(prvKey, out, &outlen, 20480, nonce, nonce_len);
	if (rv != SECSuccess)
	{
		purple_debug_error("discord", "Decrypt with Private Key failed (err %d)\n", rv);
		if (proof_len != NULL) {
			*proof_len = 0;
		}
		return FALSE;
	}
	
	if (proof_len != NULL) {
		*proof_len = outlen;
	}
	return out;
}

#elif defined USE_GCRYPT_CRYPTO

#include <gcrypt.h>
#include <string.h>

// The following functions steam_util_str_hex2bytes, steam_crypt_rsa_enc and steam_encrypt_password
// (originally steam_crypt_rsa_enc_str) have been taken directly from steam-util.c and steam-crypt.c
// from the bitlbee-steam source code. The original files are released under the GNU General Public
// License version 2 and can be found at https://github.com/jgeboski/bitlbee-steam.
// All credit goes to the original author of bitlbee-steam, James Geboski <jgeboski@gmail.com>.

GByteArray *
steam_util_str_hex2bytes(const gchar *str)
{
  GByteArray *ret;
  gboolean    hax;
  gsize       size;
  gchar       val;
  guint       i;
  guint       d;

  g_return_val_if_fail(str != NULL, NULL);

  size = strlen(str);
  hax  = (size % 2) != 0;

  ret = g_byte_array_new();
  g_byte_array_set_size(ret, (size + 1) / 2);
  memset(ret->data, 0, ret->len);

  for (d = i = 0; i < size; i++, hax = !hax) {
    val = g_ascii_xdigit_value(str[i]);

    if (val < 0) {
      g_byte_array_free(ret, TRUE);
      return NULL;
    }

    if (hax)
      ret->data[d++] |= val & 0x0F;
    else
      ret->data[d] |= (val << 4) & 0xF0;
  }

  return ret;
}

GByteArray *
steam_crypt_rsa_enc(const GByteArray *mod, const GByteArray *exp, const GByteArray *bytes)
{
  GByteArray   *ret;
  gcry_mpi_t    mmpi;
  gcry_mpi_t    empi;
  gcry_mpi_t    dmpi;
  gcry_sexp_t   kata;
  gcry_sexp_t   data;
  gcry_sexp_t   cata;
  gcry_error_t  res;
  gsize         size;

  g_return_val_if_fail(mod   != NULL, NULL);
  g_return_val_if_fail(exp   != NULL, NULL);
  g_return_val_if_fail(bytes != NULL, NULL);

  mmpi = empi = dmpi = NULL;
  kata = data = cata = NULL;
  ret  = NULL;

  res  = gcry_mpi_scan(&mmpi, GCRYMPI_FMT_USG, mod->data, mod->len, NULL);
  res |= gcry_mpi_scan(&empi, GCRYMPI_FMT_USG, exp->data, exp->len, NULL);
  res |= gcry_mpi_scan(&dmpi, GCRYMPI_FMT_USG, bytes->data, bytes->len, NULL);

  if (G_LIKELY(res == 0)) {
    res  = gcry_sexp_build(&kata, NULL, "(public-key(rsa(n %m)(e %m)))", mmpi, empi);
    res |= gcry_sexp_build(&data, NULL, "(data(flags pkcs1)(value %m))", dmpi);

    if (G_LIKELY(res == 0)) {
      res = gcry_pk_encrypt(&cata, data, kata);

      if (G_LIKELY(res == 0)) {
        gcry_sexp_release(data);
        data = gcry_sexp_find_token(cata, "a", 0);

        if (G_LIKELY(data != NULL)) {
          gcry_mpi_release(dmpi);
          dmpi = gcry_sexp_nth_mpi(data, 1, GCRYMPI_FMT_USG);

          if (G_LIKELY(dmpi != NULL)) {
            ret = g_byte_array_new();
            g_byte_array_set_size(ret, mod->len);

            gcry_mpi_print(GCRYMPI_FMT_USG, ret->data, ret->len, &size, dmpi);

            g_warn_if_fail(size <= mod->len);
            g_byte_array_set_size(ret, size);
          } else {
            g_warn_if_reached();
          }
        } else {
          g_warn_if_reached();
        }
      }
    }
  }

  gcry_sexp_release(cata);
  gcry_sexp_release(data);
  gcry_sexp_release(kata);

  gcry_mpi_release(dmpi);
  gcry_mpi_release(empi);
  gcry_mpi_release(mmpi);

  return ret;
}

gchar *
steam_encrypt_password(const gchar *mod, const gchar *exp, const gchar *str)
{
  GByteArray *bytes;
  GByteArray *mytes;
  GByteArray *eytes;
  GByteArray *enc;
  gchar      *ret;

  g_return_val_if_fail(mod != NULL, NULL);
  g_return_val_if_fail(exp != NULL, NULL);
  g_return_val_if_fail(str != NULL, NULL);

  mytes = steam_util_str_hex2bytes(mod);

  if (G_UNLIKELY(mytes == NULL))
    return NULL;

  eytes = steam_util_str_hex2bytes(exp);

  if (G_UNLIKELY(eytes == NULL)) {
    g_byte_array_free(mytes, TRUE);
    return NULL;
  }

  bytes = g_byte_array_new();
  g_byte_array_append(bytes, (guint8*) str, strlen(str));
  enc = steam_crypt_rsa_enc(mytes, eytes, bytes);

  g_byte_array_free(bytes, TRUE);
  g_byte_array_free(eytes, TRUE);
  g_byte_array_free(mytes, TRUE);

  if (G_UNLIKELY(enc == NULL))
    return NULL;

  ret = g_base64_encode(enc->data, enc->len);
  g_byte_array_free(enc, TRUE);

  return ret;
}

#elif defined USE_MBEDTLS_CRYPTO

#include "mbedtls/config.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

gchar *
steam_encrypt_password(const gchar *modulus_str, const gchar *exponent_str, const gchar *password)
{
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	int ret;
	guchar *encrypted_password;
	gchar *output;

	// Init entropy context
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {
		purple_debug_error("steam", "failed to init entropy context, error=%d\n", ret);
		return NULL;
	}

	// Init mbedtls rsa
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	// Read modulus
	ret = mbedtls_mpi_read_string(&rsa.N, 16, modulus_str);
	if (ret != 0) {
		purple_debug_error("steam", "modulus parsing failed, error=%d\n", ret);
		return NULL;
	}

	// Read exponent
	ret = mbedtls_mpi_read_string(&rsa.E, 16, exponent_str);
	if (ret != 0) {
		purple_debug_error("steam", "exponent parsing failed, error=%d\n", ret);
		return NULL;
	}

	// Set RSA key length
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

	// Allocate space for encrypted password
	encrypted_password = g_new0(guchar, rsa.len);

	ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, strlen(password), (unsigned char*)password, encrypted_password);

	if (ret != 0) {
		purple_debug_error("steam", "password encryption failed, error=%d\n", ret);
		g_free(encrypted_password);
		return NULL;
	}

	output = purple_base64_encode(encrypted_password, (int)rsa.len);
	g_free(encrypted_password);

	return output;
}

#elif defined USE_WIN32_CRYPTO

#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS
#include <wincrypt.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <security.h>

gchar *
steam_encrypt_password(const gchar *modulus_str, const gchar *exponent_str, const gchar *password)
{
	DWORD cchModulus = (DWORD)strlen(modulus_str);
	int i;
	BYTE *pbBuffer = 0;
	BYTE *pKeyBlob = 0;
	HCRYPTKEY phKey = 0;
	HCRYPTPROV hCSP = 0;
	
	// convert hex string to byte array
	DWORD cbLen = 0, dwSkip = 0, dwFlags = 0;
	if (!CryptStringToBinaryA(modulus_str, cchModulus, CRYPT_STRING_HEX, NULL, &cbLen, &dwSkip, &dwFlags))
	{
		purple_debug_error("steam", "password encryption failed, cant get length of modulus, error=%d\n", GetLastError());
		return NULL;
	}
	
	// allocate a new buffer.
	pbBuffer = (BYTE*)malloc(cbLen);
	if (!CryptStringToBinaryA(modulus_str, cchModulus, CRYPT_STRING_HEX, pbBuffer, &cbLen, &dwSkip, &dwFlags))
	{
		purple_debug_error("steam", "password encryption failed, cant get modulus, error=%d\n", GetLastError());
		free(pbBuffer);
		return NULL;
	}
	
	// reverse byte array
	for (i = 0; i < (int)(cbLen / 2); ++i)
	{
		BYTE temp = pbBuffer[cbLen - i - 1];
		pbBuffer[cbLen - i - 1] = pbBuffer[i];
		pbBuffer[i] = temp;
	}
	
	if (!CryptAcquireContext(&hCSP, NULL, NULL, PROV_RSA_AES, CRYPT_SILENT) &&
			!CryptAcquireContext(&hCSP, NULL, NULL, PROV_RSA_AES, CRYPT_SILENT | CRYPT_NEWKEYSET))
	{
		purple_debug_error("steam", "password encryption failed, cant get a crypt context, error=%d\n", GetLastError());
		free(pbBuffer);
		return NULL;
	}
	
	// Move the key into the key container.
	DWORD cbKeyBlob = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + cbLen;
	pKeyBlob = (BYTE*)malloc(cbKeyBlob);
	
	// Fill in the data.
	PUBLICKEYSTRUC *pPublicKey = (PUBLICKEYSTRUC*)pKeyBlob;
	pPublicKey->bType = PUBLICKEYBLOB;
	pPublicKey->bVersion = CUR_BLOB_VERSION;  // Always use this value.
	pPublicKey->reserved = 0;                 // Must be zero.
	pPublicKey->aiKeyAlg = CALG_RSA_KEYX;     // RSA public-key key exchange.
	
	// The next block of data is the RSAPUBKEY structure.
	RSAPUBKEY *pRsaPubKey = (RSAPUBKEY*)(pKeyBlob + sizeof(PUBLICKEYSTRUC));
	pRsaPubKey->magic = 0x31415352; // RSA1 // Use public key
	pRsaPubKey->bitlen = cbLen * 8;  // Number of bits in the modulus.
	//pRsaPubKey->pubexp = 0x10001; // "010001" // Exponent.
	pRsaPubKey->pubexp = strtol(exponent_str, NULL, 16);
	
	// Copy the modulus into the blob. Put the modulus directly after the
	// RSAPUBKEY structure in the blob.
	BYTE *pKey = (BYTE*)(((BYTE *)pRsaPubKey) + sizeof(RSAPUBKEY));
	memcpy(pKey, pbBuffer, cbLen);
	
	// Now import public key       
	if (!CryptImportKey(hCSP, pKeyBlob, cbKeyBlob, 0, 0, &phKey))
	{
		purple_debug_error("steam", "password encryption failed, couldnt create key, error=%d\n", GetLastError());
		
		free(pKeyBlob);
		free(pbBuffer);
		CryptReleaseContext(hCSP, 0);
		
		return NULL;
	}
	
	DWORD dataSize = strlen(password);
	DWORD encryptedSize = dataSize;
	
	// get length of encrypted data
	if (!CryptEncrypt(phKey, 0, TRUE, 0, NULL, &encryptedSize, 0))
	{
		gint errorno = GetLastError();
		purple_debug_error("steam", "password encryption failed, couldnt get length of RSA, error=%d %s\n", errorno, g_win32_error_message(errorno));
		
		free(pKeyBlob);
		free(pbBuffer);
		CryptDestroyKey(phKey);
		CryptReleaseContext(hCSP, 0);
		
		return NULL;
	}
	
	BYTE *encryptedData = g_new0(BYTE, encryptedSize);
	
	// encrypt password
	memcpy(encryptedData, password, dataSize);
	if (!CryptEncrypt(phKey, 0, TRUE, 0, encryptedData, &dataSize, encryptedSize))
	{
		purple_debug_error("steam", "password encryption failed, couldnt RSA the thing, error=%d\n", GetLastError());
		
		free(pKeyBlob);
		free(pbBuffer);
		CryptDestroyKey(phKey);
		CryptReleaseContext(hCSP, 0);
		
		return NULL;
	}
	
	// reverse byte array again
	for (i = 0; i < (int)(encryptedSize / 2); ++i)
	{
		BYTE temp = encryptedData[encryptedSize - i - 1];
		encryptedData[encryptedSize - i - 1] = encryptedData[i];
		encryptedData[i] = temp;
	}
	
	free(pKeyBlob);
	CryptDestroyKey(phKey);
	free(pbBuffer);
	CryptReleaseContext(hCSP, 0);
	
	gchar *ret = g_base64_encode(encryptedData, encryptedSize/2);
	g_free(encryptedData);
	return ret;
}

#elif defined USE_OPENSSL_CRYPTO

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

gchar *
steam_encrypt_password(const gchar *modulus_str, const gchar *exponent_str, const gchar *password)
{
	BIGNUM *bn_modulus;
	BIGNUM *bn_exponent;
	RSA *rsa;
	gchar *output = NULL;
	guchar *encrypted;
	int rv;
	
	ERR_load_crypto_strings();
	
	bn_modulus = BN_new();
	rv = BN_hex2bn(&bn_modulus, modulus_str);
	if (rv == 0)
	{
		purple_debug_error("steam", "modulus hext to bignum parse failed\n");
		BN_free(bn_modulus);
		return NULL;
	}
	
	bn_exponent = BN_new();
	rv = BN_hex2bn(&bn_exponent, exponent_str);
	if (rv == 0)
	{
		purple_debug_error("steam", "exponent hex to bignum parse failed\n");
		BN_clear_free(bn_modulus);
		BN_clear_free(bn_exponent);
		return NULL;
	}
	
	rsa = RSA_new();
	if (rsa == NULL)
	{
		purple_debug_error("steam", "RSA structure allocation failed\n");
		BN_free(bn_modulus);
		BN_free(bn_exponent);
		return NULL;
	}
	BN_free(rsa->n);
	rsa->n = bn_modulus;
	BN_free(rsa->e);
	rsa->e = bn_exponent;
	
	encrypted = g_new0(guchar, RSA_size(rsa));
	rv = RSA_public_encrypt((int)(strlen(password)),
                          (const unsigned char *)password,
                          encrypted,
                          rsa,
                          RSA_PKCS1_PADDING);
	if (rv < 0)
	{
		unsigned long error_num = ERR_get_error();
		char *error_str = ERR_error_string(error_num, NULL);
		purple_debug_error("steam", "%s", error_str);
		RSA_free(rsa);
		g_free(encrypted);
		return NULL;
	}
	
	output = purple_base64_encode(encrypted, RSA_size(rsa));
	
	// Cleanup
	RSA_free(rsa);
	ERR_free_strings();
	g_free(encrypted);
	
	return output;
}

#endif
