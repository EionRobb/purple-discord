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
discord_display_qrcode(PurpleConnection *pc, const gchar *qr_code_raw, const gchar *qrcode_utf8, const guchar *image_data, gsize image_data_len)
{
    DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleRequestUiOps *ui_ops = purple_request_get_ui_ops();
	
	if (!ui_ops->request_fields) {
		// The UI hasn't implemented the func we want, just output as a message instead
		
		gchar *msg_out;
		gpointer img_data = g_memdup2(image_data, image_data_len);
		int img_id = purple_imgstore_add_with_id(img_data, image_data_len, NULL);

		if (img_id >= 0) {
			msg_out = g_strdup_printf("%s: <img id=\"%u\" src=\"purple-image:%u\" alt=\"%s\"/><br />%s", _("Please scan this QR code with your phone"), img_id, img_id, qr_code_raw, qrcode_utf8);
		} else {
			msg_out = g_strdup_printf("%s: %s<br />%s", _("Please scan this QR code with your phone"), qr_code_raw, qrcode_utf8);
		}
		
		purple_serv_got_im(pc, _("Logon QR Code"), msg_out, 0, time(NULL));
		
		g_free(msg_out);
		return;
	}

    PurpleRequestFields *fields = purple_request_fields_new();
    PurpleRequestFieldGroup *group = purple_request_field_group_new(NULL);
    purple_request_fields_add_group(fields, group);

	PurpleRequestField *field;
    field = purple_request_field_string_new("qr_string", _("QR Code Data"), qr_code_raw, FALSE);
	purple_request_field_string_set_editable(field, FALSE);
    purple_request_field_group_add_field(group, field);
	
    field = purple_request_field_image_new("qr_image", _("QR Code Image"), (const gchar *)image_data, image_data_len);
	purple_request_field_image_set_scale(field, 2, 2);
    purple_request_field_group_add_field(group, field);
	
	field = purple_request_field_string_new("qr_code", _("QR Code Data"), qrcode_utf8, TRUE);
	purple_request_field_string_set_editable(field, FALSE);
    purple_request_field_group_add_field(group, field);

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

	empty = "\342\200\202";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	realwidth = (qrcode->width + margin * 2);

	/* top margin */
	for (x = 0; x < realwidth; x++) {
		g_string_append(out, full);
	}
	g_string_append_c(out, '\n');

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
discord_qrauth_decrypt(DiscordAccount *da, const gchar *encrypted_nonce, gsize *proof_len)
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

	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	oaep_params.source = CKZ_DATA_SPECIFIED;
	oaep_params.pSourceData = NULL;
	oaep_params.ulSourceDataLen = 0;
	oaep_params.mgf = CKG_MGF1_SHA256;
	oaep_params.hashAlg = CKM_SHA256;
	
	SECItem param;
	param.type = siBuffer;
	param.data = (unsigned char*) &oaep_params;
	param.len = sizeof(oaep_params);
	
	out = g_new0(unsigned char, 20480);
	rv = PK11_PrivDecrypt(prvKey, CKM_RSA_PKCS_OAEP, &param, out, &outlen, 20480, nonce, nonce_len);
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

// TODO

#elif defined USE_MBEDTLS_CRYPTO

#include "mbedtls/config.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


// TODO

#elif defined USE_WIN32_CRYPTO

#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS
#include <wincrypt.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <security.h>

// TODO

#elif defined USE_OPENSSL_CRYPTO

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

// TODO

#endif
