/*
 *   Discord plugin for libpurple
 *   Copyright (C) 2016-2017  Eion Robb
 *   Copyright (C) 2017 Alyssa Rosenzweig
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _JSON_COMPAT_H_
#define _JSON_COMPAT_H_

#include <string.h>
#include <json-glib/json-glib.h>

// Suppress overzealous json-glib 'critical errors'
#define json_object_has_member(JSON_OBJECT, MEMBER) \
	(JSON_OBJECT ? json_object_has_member(JSON_OBJECT, MEMBER) : FALSE)
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)

#define json_array_get_length(JSON_ARRAY) \
	(JSON_ARRAY ? json_array_get_length(JSON_ARRAY) : 0)

static inline gchar *
json_object_to_string(JsonObject *obj)
{
	JsonNode *node;
	gchar *str;
	JsonGenerator *generator;

	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, obj);

	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, NULL);
	g_object_unref(generator);
	json_node_free(node);

	return str;
}

#if !defined(JSON_CHECK_VERSION) || !JSON_CHECK_VERSION(0, 11, 2)
static inline gint
json_compat_parse_hex4(const gchar *p)
{
	gint val = 0;
	gint i;

	for (i = 0; i < 4; i++) {
		gint digit = g_ascii_xdigit_value(p[i]);

		if (digit < 0) {
			return -1;
		}
		val = (val << 4) | digit;
	}

	return val;
}

/*
 * Returns a copy of data with every \uXXXX escape of a UTF-16 surrogate replaced by the UTF-8
 * bytes of the character it encodes (U+FFFD for an unpaired half), or NULL if there are none.
 * Raw UTF-8 is valid inside JSON strings, and json-glib < 0.11.2 reads it without aborting.
 */
static inline gchar *
json_compat_fix_surrogate_escapes(const gchar *data, gsize length, gsize *fixed_length)
{
	GString *fixed = NULL;
	gsize copied = 0;
	gsize i = 0;

	while (i < length) {
		gint high, low;
		gunichar ch;
		gsize escape_length;

		if (data[i] != '\\') {
			i++;
			continue;
		}

		/* Skip other escapes whole, so the "u" in "\\u" is not taken for an escape */
		if (i + 1 >= length || data[i + 1] != 'u' || i + 6 > length) {
			i += 2;
			continue;
		}

		high = json_compat_parse_hex4(data + i + 2);
		if (high < 0xD800 || high > 0xDFFF) {
			i += 6;
			continue;
		}

		ch = 0xFFFD;
		escape_length = 6;

		if (high < 0xDC00 && i + 12 <= length && data[i + 6] == '\\' && data[i + 7] == 'u') {
			low = json_compat_parse_hex4(data + i + 8);

			if (low >= 0xDC00 && low <= 0xDFFF) {
				ch = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
				escape_length = 12;
			}
		}

		if (fixed == NULL) {
			fixed = g_string_sized_new(length);
		}
		g_string_append_len(fixed, data + copied, i - copied);
		g_string_append_unichar(fixed, ch);

		i += escape_length;
		copied = i;
	}

	if (fixed == NULL) {
		return NULL;
	}

	g_string_append_len(fixed, data + copied, length - copied);
	*fixed_length = fixed->len;

	return g_string_free(fixed, FALSE);
}

static inline gboolean
json_compat_parser_load_from_data(JsonParser *parser, const gchar *data, gssize length, GError **error)
{
	gchar *fixed;
	gsize fixed_length = 0;
	gboolean result;

	if (data == NULL) {
		return (json_parser_load_from_data)(parser, data, length, error);
	}

	if (length < 0) {
		length = (gssize) strlen(data);
	}

	fixed = json_compat_fix_surrogate_escapes(data, (gsize) length, &fixed_length);
	if (fixed == NULL) {
		return (json_parser_load_from_data)(parser, data, length, error);
	}

	result = (json_parser_load_from_data)(parser, fixed, (gssize) fixed_length, error);
	g_free(fixed);

	return result;
}

#define json_parser_load_from_data json_compat_parser_load_from_data
#endif /* JSON_CHECK_VERSION(0, 11, 2) */

//just in case we optimize...
#define g_hash_table_insert_int64(a, b, c) g_hash_table_insert((a), &(b), (c))
#define g_hash_table_replace_int64(a, b, c) g_hash_table_replace((a), &(b), (c))
#define g_hash_table_steal_int64(a, b) g_hash_table_steal((a), &(b))
#define g_hash_table_lookup_int64(a, b) g_hash_table_lookup((a), &(b))
#define g_hash_table_remove_int64(a, b) g_hash_table_remove((a), &(b))
#define g_hash_table_contains_int64(a, b) g_hash_table_contains((a), &(b))
#define g_hash_table_lookup_extended_int64(a, b, c, d) g_hash_table_lookup_extended((a), &(b), (c), (d))

#endif /* _JSON_COMPAT_H_ */
