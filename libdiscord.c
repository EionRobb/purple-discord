/*
 *   Discord plugin for libpurple
 *   Copyright (C) 2016  Eion Robb
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
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Glib
#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

static gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}
static guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);
	
	hash = g_str_hash(lower_str);
	g_free(lower_str);
	
	return hash;
}


// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <json-glib/json-glib.h>
// Supress overzealous json-glib 'critical errors'
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



static gchar *
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


#include <purple.h>
#if PURPLE_VERSION_CHECK(3, 0, 0)
#include <http.h>
#endif

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define DISCORD_PLUGIN_ID "prpl-eionrobb-discord"
#ifndef DISCORD_PLUGIN_VERSION
#define DISCORD_PLUGIN_VERSION "0.1"
#endif
#define DISCORD_PLUGIN_WEBSITE "https://github.com/EionRobb/discord-libpurple"

#define DISCORD_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define DISCORD_BUFFER_DEFAULT_SIZE 40960

#define DISCORD_API_SERVER           "discordapp.com"
#define DISCORD_GATEWAY_SERVER       "gateway.discord.gg"
#define DISCORD_GATEWAY_PORT         443
#define DISCORD_GATEWAY_SERVER_PATH  "/?encoding=json&v=6"


// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_connection_error                 purple_connection_error_reason
#define purple_connection_get_protocol          purple_connection_get_prpl
#define PURPLE_CONNECTION_CONNECTING       PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED        PURPLE_CONNECTED
#define PURPLE_CONNECTION_FLAG_HTML        PURPLE_CONNECTION_HTML
#define PURPLE_CONNECTION_FLAG_NO_BGCOLOR  PURPLE_CONNECTION_NO_BGCOLOR
#define PURPLE_CONNECTION_FLAG_NO_FONTSIZE PURPLE_CONNECTION_NO_FONTSIZE
#define PURPLE_CONNECTION_FLAG_NO_IMAGES   PURPLE_CONNECTION_NO_IMAGES
#define purple_connection_set_flags(pc, f)      ((pc)->flags = (f))
#define purple_connection_get_flags(pc)         ((pc)->flags)
#define purple_blist_find_group        purple_find_group
#define purple_protocol_action_get_connection(action)  ((PurpleConnection *) (action)->context)
#define purple_protocol_action_new                     purple_plugin_action_new
#define purple_protocol_get_id                         purple_plugin_get_id
#define PurpleProtocolAction                           PurplePluginAction
#define PurpleProtocolChatEntry  struct proto_chat_entry
#define PurpleChatConversation             PurpleConvChat
#define PurpleIMConversation               PurpleConvIm
#define purple_conversations_find_chat_with_account(id, account) \
		PURPLE_CONV_CHAT(purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, id, account))
#define purple_chat_conversation_has_left     purple_conv_chat_has_left
#define PurpleConversationUpdateType          PurpleConvUpdateType
#define PURPLE_CONVERSATION_UPDATE_UNSEEN     PURPLE_CONV_UPDATE_UNSEEN
#define PURPLE_IS_IM_CONVERSATION(conv)       (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
#define PURPLE_IS_CHAT_CONVERSATION(conv)     (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
#define PURPLE_CONVERSATION(chatorim)         (chatorim == NULL ? NULL : chatorim->conv)
#define PURPLE_IM_CONVERSATION(conv)          PURPLE_CONV_IM(conv)
#define PURPLE_CHAT_CONVERSATION(conv)        PURPLE_CONV_CHAT(conv)
#define purple_conversation_present_error     purple_conv_present_error
#define purple_serv_got_joined_chat(pc, id, name)  PURPLE_CONV_CHAT(serv_got_joined_chat(pc, id, name))
#define purple_conversations_find_chat(pc, id)  PURPLE_CONV_CHAT(purple_find_chat(pc, id))
#define purple_serv_got_chat_in                    serv_got_chat_in
#define purple_chat_conversation_add_user     purple_conv_chat_add_user
#define purple_chat_conversation_add_users    purple_conv_chat_add_users
#define purple_chat_conversation_remove_user  purple_conv_chat_remove_user
#define purple_chat_conversation_get_topic    purple_conv_chat_get_topic
#define purple_chat_conversation_set_topic    purple_conv_chat_set_topic
#define PurpleChatUserFlags  PurpleConvChatBuddyFlags
#define PURPLE_CHAT_USER_NONE     PURPLE_CBFLAGS_NONE
#define PURPLE_CHAT_USER_OP       PURPLE_CBFLAGS_OP
#define PURPLE_CHAT_USER_FOUNDER  PURPLE_CBFLAGS_FOUNDER
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PURPLE_CHAT_USER_AWAY     PURPLE_CBFLAGS_AWAY
#define PURPLE_CHAT_USER_HALFOP   PURPLE_CBFLAGS_HALFOP
#define PURPLE_CHAT_USER_VOICE    PURPLE_CBFLAGS_VOICE
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PurpleChatUser  PurpleConvChatBuddy
static inline PurpleChatUser *
purple_chat_conversation_find_user(PurpleChatConversation *chat, const char *name)
{
	PurpleChatUser *cb = purple_conv_chat_cb_find(chat, name);
	
	if (cb != NULL) {
		g_dataset_set_data(cb, "chat", chat);
	}
	
	return cb;
}
#define purple_chat_user_get_flags(cb)     purple_conv_chat_user_get_flags(g_dataset_get_data((cb), "chat"), (cb)->name)
#define purple_chat_user_set_flags(cb, f)  purple_conv_chat_user_set_flags(g_dataset_get_data((cb), "chat"), (cb)->name, (f))
#define purple_chat_user_set_alias(cb, a)  (g_free((cb)->alias), (cb)->alias = g_strdup(a))
#define PurpleIMTypingState	PurpleTypingState
#define PURPLE_IM_NOT_TYPING	PURPLE_NOT_TYPING
#define PURPLE_IM_TYPING	PURPLE_TYPING
#define PURPLE_IM_TYPED		PURPLE_TYPED
#define purple_conversation_get_connection      purple_conversation_get_gc
#define purple_conversation_write_system_message(conv, message, flags)  purple_conversation_write((conv), NULL, (message), ((flags) | PURPLE_MESSAGE_SYSTEM), time(NULL))
#define purple_chat_conversation_get_id         purple_conv_chat_get_id
#define PURPLE_CMD_FLAG_PROTOCOL_ONLY  PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_IS_BUDDY                PURPLE_BLIST_NODE_IS_BUDDY
#define PURPLE_IS_CHAT                 PURPLE_BLIST_NODE_IS_CHAT
#define purple_chat_get_name_only      purple_chat_get_name
#define purple_blist_find_buddy        purple_find_buddy
#define purple_serv_got_alias                      serv_got_alias
#define purple_account_set_private_alias    purple_account_set_alias
#define purple_account_get_private_alias    purple_account_get_alias
#define purple_protocol_got_user_status		purple_prpl_got_user_status
#define purple_protocol_got_user_idle       purple_prpl_got_user_idle
#define purple_serv_got_im                         serv_got_im
#define purple_serv_got_typing                     serv_got_typing
#define purple_conversations_find_im_with_account(name, account)  \
		PURPLE_CONV_IM(purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account))
#define purple_im_conversation_new(account, from) PURPLE_CONV_IM(purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from))
#define PurpleMessage  PurpleConvMessage
#define purple_message_set_time(msg, time)  ((msg)->when = (time))
#define purple_conversation_write_message(conv, msg)  purple_conversation_write(conv, msg->who, msg->what, msg->flags, msg->when)
static inline PurpleMessage *
purple_message_new_outgoing(const gchar *who, const gchar *contents, PurpleMessageFlags flags)
{
	PurpleMessage *message = g_new0(PurpleMessage, 1);
	
	message->who = g_strdup(who);
	message->what = g_strdup(contents);
	message->flags = flags;
	message->when = time(NULL);
	
	return message;
}
static inline void
purple_message_destroy(PurpleMessage *message)
{
	g_free(message->who);
	g_free(message->what);
	g_free(message);
}

#define purple_message_get_recipient(message)  (message->who)
#define purple_message_get_contents(message)   (message->what)
#if	!PURPLE_VERSION_CHECK(2, 12, 0)
#	define PURPLE_MESSAGE_REMOTE_SEND  0x10000
#endif

#define purple_account_privacy_deny_add     purple_privacy_deny_add
#define purple_account_privacy_deny_remove  purple_privacy_deny_remove
#define PurpleHttpConnection  PurpleUtilFetchUrlData
#define purple_buddy_set_name  purple_blist_rename_buddy
#define purple_request_cpar_from_connection(a)  purple_connection_get_account(a), NULL, NULL

#else
// Purple3 helper functions
#define purple_conversation_set_data(conv, key, value)  g_object_set_data(G_OBJECT(conv), key, value)
#define purple_conversation_get_data(conv, key)         g_object_get_data(G_OBJECT(conv), key)
#define purple_message_destroy          g_object_unref
#define purple_chat_user_set_alias(cb, alias)  g_object_set((cb), "alias", (alias), NULL)
#define purple_chat_get_alias(chat)  g_object_get_data(G_OBJECT(chat), "alias")
#define purple_protocol_action_get_connection(action)  ((action)->connection)
#define PURPLE_TYPE_STRING  G_TYPE_STRING
//TODO remove this when dx adds this to the PurpleMessageFlags enum
#define PURPLE_MESSAGE_REMOTE_SEND  0x10000
#endif

static GRegex *channel_mentions_regex = NULL;

typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	gchar *self_user_id;
	gchar *self_username;
	
	gint64 last_message_timestamp;
	gint64 last_load_last_message_timestamp;
	
	gchar *token;
	gchar *session_id;
	gchar *mfa_ticket;
	
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	gint64 seq; //incrementing counter
	guint heartbeat_timeout;
	
	GHashTable *one_to_ones;      // A store of known room_id's -> username's
	GHashTable *one_to_ones_rev;  // A store of known usernames's -> room_id's
	GHashTable *group_chats;      // A store of known multi-user room_id's -> room name's
	GHashTable *group_chats_rev;  // A store of known multi-user room name's -> room_id's
	GHashTable *sent_message_ids; // A store of message id's that we generated from this instance
	GHashTable *result_callbacks; // Result ID -> Callback function
	GHashTable *usernames_to_ids; // username -> user id
	GHashTable *ids_to_usernames; // user id -> username
	GHashTable *guilds;           // A store of guild_id -> guild_name AKA Servers
	GQueue *received_message_queue; // A store of the last 10 received message id's for de-dup

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;
	gint roomlist_guild_count;
} DiscordAccount;

typedef void (*DiscordProxyCallbackFunc)(DiscordAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	DiscordAccount *ya;
	DiscordProxyCallbackFunc callback;
	gpointer user_data;
} DiscordProxyConnection;

static gchar *
discord_combine_username(const gchar *username, const gchar *discriminator)
{
	return g_strconcat(username, "#", discriminator, NULL);
}

gchar *
discord_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start && end, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (len > 0) {
		chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
	} else {
		chunk_end = strstr(chunk_start, end);
	}
	g_return_val_if_fail(chunk_end, NULL);
	
	return g_strndup(chunk_start, chunk_end - chunk_start);
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
static void
discord_update_cookies(DiscordAccount *ya, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;
	
	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur))
	{
		cookie_start = cur->data;
		
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}

#else
static void
discord_update_cookies(DiscordAccount *ya, const gchar *headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	int header_len;

	g_return_if_fail(headers != NULL);

	header_len = strlen(headers);

	/* look for the next "Set-Cookie: " */
	/* grab the data up until ';' */
	cookie_start = headers;
	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len)
	{
		cookie_start += 14;
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}
#endif

static void
discord_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
discord_cookies_to_string(DiscordAccount *ya)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ya->cookie_table, (GHFunc)discord_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
discord_response_callback(PurpleHttpConnection *http_conn, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
	const gchar *error_message = purple_http_response_get_error(response);
#else
gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
	const gchar *body;
	gsize body_len;
	DiscordProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	conn->ya->http_conns = g_slist_remove(conn->ya->http_conns, http_conn);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	discord_update_cookies(conn->ya, url_text);
	
	body = g_strstr_len(url_text, len, "\r\n\r\n");
	body = body ? body + 4 : body;
	body_len = len - (body - url_text);
#else
	discord_update_cookies(conn->ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;
#endif
	if (body == NULL && error_message != NULL) {
		//connection error - unersolvable dns name, non existing server
		gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
		purple_connection_error(conn->ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
		g_free(error_msg_formatted);
		g_free(conn);
		return;
	}
	if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
		//purple_debug_error("discord", "Error parsing response: %s\n", body);
		if (conn->callback) {
			JsonNode *dummy_node = json_node_new(JSON_NODE_OBJECT);
			JsonObject *dummy_object = json_object_new();
			
			json_node_set_object(dummy_node, dummy_object);
			json_object_set_string_member(dummy_object, "body", body);
			json_object_set_int_member(dummy_object, "len", body_len);
			g_dataset_set_data(dummy_node, "raw_body", (gpointer) body);
			
			conn->callback(conn->ya, dummy_node, conn->user_data);
			
			g_dataset_destroy(dummy_node);
			json_node_free(dummy_node);
			json_object_unref(dummy_object);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		purple_debug_misc("discord", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}

static void
discord_fetch_url_with_method(DiscordAccount *ya, const gchar *method, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	DiscordProxyConnection *conn;
	gchar *cookies;
	PurpleHttpConnection *http_conn;
	
	account = ya->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(DiscordProxyConnection, 1);
	conn->ya = ya;
	conn->callback = callback;
	conn->user_data = user_data;
	
	cookies = discord_cookies_to_string(ya);
	
	if (method == NULL) {
		method = "GET";
	}
	
	purple_debug_info("discord", "Fetching url %s\n", url);

#if PURPLE_VERSION_CHECK(3, 0, 0)
	
	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_set_method(request, method);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", DISCORD_USERAGENT);
	purple_http_request_header_set(request, "Cookie", cookies);
	if (ya->token) {
		purple_http_request_header_set(request, "Authorization", ya->token);
	}
	
	if (postdata) {
		purple_debug_info("discord", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
	}
	
	http_conn = purple_http_request(ya->pc, request, discord_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL)
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);

#else
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	purple_url_parse(url, &host, &port, &path, &user, &password);
	
	headers = g_string_new(NULL);
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", method, path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", method, url);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " DISCORD_USERAGENT "\r\n");
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);
	if (ya->token) {
		g_string_append_printf(headers, "Authorization: %s\r\n", ya->token);
	}

	if (postdata) {
		purple_debug_info("discord", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
		g_string_append_printf(headers, "Content-Length: %" G_GSIZE_FORMAT "\r\n", strlen(postdata));
		g_string_append(headers, "\r\n");

		g_string_append(headers, postdata);
	} else {
		g_string_append(headers, "\r\n");
	}

	g_free(host);
	g_free(path);
	g_free(user);
	g_free(password);

	http_conn = purple_util_fetch_url_request_len_with_account(ya->account, url, FALSE, DISCORD_USERAGENT, TRUE, headers->str, TRUE, 6553500, discord_response_callback, conn);
	
	if (http_conn != NULL)
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);

	g_string_free(headers, TRUE);
#endif

	g_free(cookies);
}


static void
discord_fetch_url(DiscordAccount *da, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data)
{
	discord_fetch_url_with_method(da, (postdata ? "POST" : "GET"), url, postdata, callback, user_data);
}


static void discord_socket_write_json(DiscordAccount *ya, JsonObject *data);
static GHashTable *discord_chat_info_defaults(PurpleConnection *pc, const char *chatname);
static void discord_mark_room_messages_read(DiscordAccount *ya, const gchar *room_id);



// static gint64 discord_get_room_last_timestamp(DiscordAccount *ya, const gchar *room_id);
// static void discord_set_room_last_timestamp(DiscordAccount *ya, const gchar *room_id, gint64 last_timestamp);

// static gboolean
// discord_have_seen_message_id(DiscordAccount *ya, const gchar *message_id)
// {
	// guint message_hash = g_str_hash(message_id);
	// gpointer message_hash_ptr = GINT_TO_POINTER(message_hash);
	
	// if (g_queue_find(ya->received_message_queue, message_hash_ptr)) {
		// return TRUE;
	// }
	
	// g_queue_push_head(ya->received_message_queue, message_hash_ptr);
	// g_queue_pop_nth(ya->received_message_queue, 10);
	
	// return FALSE;
// }


static void
discord_send_auth(DiscordAccount *da)
{
	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	
	json_object_set_string_member(data, "token", da->token);
	
	if (da->seq && da->session_id) {
		json_object_set_int_member(obj, "op", 6);

		json_object_set_string_member(data, "session_id", da->session_id);
		json_object_set_int_member(data, "seq", da->seq);
	} else {
		JsonObject *properties = json_object_new();
		JsonObject *presence = json_object_new();
		
		json_object_set_int_member(obj, "op", 2);
		
		json_object_set_boolean_member(data, "compress", FALSE);
		json_object_set_int_member(data, "large_threshold", 250);
		
		json_object_set_string_member(properties, "os", 
#if defined(_WIN32)
			"Windows"
#elif defined(__APPLE__)
			"OSX"
#else
			"Linux"
#endif
		);
		json_object_set_string_member(properties, "browser", "Pidgin");
		json_object_set_object_member(data, "properties", properties);
		
		//todo real presense
		json_object_set_string_member(presence, "status", "online");
		json_object_set_object_member(data, "presence", presence);
	}
	
	json_object_set_object_member(obj, "d", data);
	
	discord_socket_write_json(da, obj);
}

static gboolean
discord_send_heartbeat(gpointer userdata)
{
	DiscordAccount *da = userdata;
	JsonObject *obj = json_object_new();
	
	json_object_set_int_member(obj, "op", 1);
	json_object_set_int_member(obj, "d", da->seq);
	
	discord_socket_write_json(da, obj);
	
	return TRUE;
}


void discord_handle_add_new_user(DiscordAccount *ya, JsonObject *obj);

PurpleGroup* discord_get_or_create_default_group();

static void discord_got_relationships(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_private_channels(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_presences(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_avatar(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_get_avatar(DiscordAccount *da, const gchar *username, const gchar *avatar_id);

static const gchar *discord_normalise_room_name(const gchar *guild_name, const gchar *name);


static gboolean
discord_replace_channel(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccount *da = user_data;
	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *channel_id = g_match_info_fetch(match, 1);
	const gchar *channel_name = g_hash_table_lookup(da->group_chats, channel_id);
	
	if (channel_name) {
		//TODO make this a clickable link
		g_string_append_printf(result, "%s", channel_name);
	} else {
		g_string_append(result, match_string);
	}
	
	g_free(channel_id);
	g_free(match_string);

	return FALSE;
}

static void
discord_process_dispatch(DiscordAccount *da, const gchar *type, JsonObject *data)
{
	discord_get_or_create_default_group();

	if (purple_strequal(type, "PRESENCE_UPDATE")) {
		const gchar *user_id = json_object_get_string_member(json_object_get_object_member(data, "user"), "id");
		const gchar *status = json_object_get_string_member(data, "status");
		const gchar *game = json_object_get_string_member(json_object_get_object_member(data, "game"), "name");
		const gchar *username = g_hash_table_lookup(da->ids_to_usernames, user_id);
		gint64 idle_since = json_object_get_int_member(data, "idle_since");
		
		purple_protocol_got_user_status(da->account, username, status, "message", game, NULL);
		purple_protocol_got_user_idle(da->account, username, idle_since ? TRUE : FALSE, 0);
	} else if (purple_strequal(type, "MESSAGE_CREATE")/* || purple_strequal(type, "MESSAGE_UPDATE")*/) { //TODO
		JsonObject *author = json_object_get_object_member(data, "author");
		const gchar *username = json_object_get_string_member(author, "username");
		const gchar *discriminator = json_object_get_string_member(author, "discriminator");
		const gchar *user_id = json_object_get_string_member(author, "id");
		const gchar *channel_id = json_object_get_string_member(data, "channel_id");
		const gchar *content = json_object_get_string_member(data, "content");
		const gchar *timestamp_str = json_object_get_string_member(data, "timestamp");
		time_t timestamp = purple_str_to_time(timestamp_str, FALSE, NULL, NULL, NULL);
		const gchar *nonce = json_object_get_string_member(data, "nonce");
		gchar *escaped_content = purple_markup_escape_text(content, -1);
		JsonArray *attachments = json_object_get_array_member(data, "attachments");
		JsonArray *mentions = json_object_get_array_member(data, "mentions");
		PurpleMessageFlags flags;
		gchar *tmp;
		gint i;
		
		if (!g_hash_table_contains(da->ids_to_usernames, user_id)) {
			g_hash_table_replace(da->usernames_to_ids, discord_combine_username(username, discriminator), g_strdup(user_id));
			g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), discord_combine_username(username, discriminator));
		}
		
		if (purple_strequal(user_id, da->self_user_id)) {
			flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
		} else {
			flags = PURPLE_MESSAGE_RECV;
		}
		
		//Replace <@user_id> and <@!user_id> with usernames
		if (mentions) {
			for (i = json_array_get_length(mentions) - 1; i >= 0; i--) {
				JsonObject *mention_user = json_array_get_object_element(mentions, i);
				const gchar *user_id_replace = json_object_get_string_member(mention_user, "id");
				const gchar *username_replace = json_object_get_string_member(mention_user, "username");
				const gchar *discriminator_replace = json_object_get_string_member(mention_user, "discriminator");
				
				gchar *user_id_replace_str1 = g_strconcat("&lt;@", user_id_replace, "&gt;", NULL);
				gchar *user_id_replace_str2 = g_strconcat("&lt;@!", user_id_replace, "&gt;", NULL);
				gchar *combined_username_replace = discord_combine_username(username_replace, discriminator_replace);
				
				if (purple_strequal(user_id_replace, da->self_user_id)) {
					flags |= PURPLE_MESSAGE_NICK;
				}
				
				//TODO make this a clickable link
				tmp = g_strconcat("@", combined_username_replace, NULL);
				g_free(combined_username_replace); combined_username_replace = tmp;
				
				tmp = purple_strreplace(escaped_content, user_id_replace_str1, combined_username_replace);
				g_free(escaped_content); escaped_content = tmp;
				
				tmp = purple_strreplace(escaped_content, user_id_replace_str2, combined_username_replace);
				g_free(escaped_content); escaped_content = tmp;
				
				g_free(combined_username_replace);
				g_free(user_id_replace_str1);
				g_free(user_id_replace_str2);
			}
		}
		
		//Replace <#channel_id> with channel names
		tmp = g_regex_replace_eval(channel_mentions_regex, escaped_content, -1, 0, 0, discord_replace_channel, da, NULL);
		if (tmp != NULL) {
			g_free(escaped_content);
			escaped_content = tmp;
		}
		
		if (g_hash_table_contains(da->one_to_ones, channel_id)) {
			//private message
			
			if (purple_strequal(user_id, da->self_user_id)) {
				if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
					PurpleConversation *conv;
					PurpleIMConversation *imconv;
					PurpleMessage *msg;
					
					username = g_hash_table_lookup(da->one_to_ones, channel_id);
					imconv = purple_conversations_find_im_with_account(username, da->account);
					if (imconv == NULL)
					{
						imconv = purple_im_conversation_new(da->account, username);
					}
					conv = PURPLE_CONVERSATION(imconv);
					
					if (escaped_content && *escaped_content) {
						msg = purple_message_new_outgoing(username, escaped_content, flags);
						purple_message_set_time(msg, timestamp);
						purple_conversation_write_message(conv, msg);
						purple_message_destroy(msg);
					}
					
					if (attachments) {
						for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
							JsonObject *attachment = json_array_get_object_element(attachments, i);
							const gchar *url = json_object_get_string_member(attachment, "url");
							
							msg = purple_message_new_outgoing(username, url, flags);
							purple_message_set_time(msg, timestamp);
							purple_conversation_write_message(conv, msg);
							purple_message_destroy(msg);
						}
					}
				}
			} else {
				gchar *merged_username = discord_combine_username(username, discriminator);
				
				if (escaped_content && *escaped_content) {
					purple_serv_got_im(da->pc, merged_username, escaped_content, flags, timestamp);
				}
				
				if (attachments) {
					for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
						JsonObject *attachment = json_array_get_object_element(attachments, i);
						const gchar *url = json_object_get_string_member(attachment, "url");
						
						purple_serv_got_im(da->pc, merged_username, url, flags, timestamp);
					}
				}
				
				g_free(merged_username);
			}
			
		} else if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
			gchar *merged_username = discord_combine_username(username, discriminator);
			
			if (escaped_content && *escaped_content) {
				purple_serv_got_chat_in(da->pc, g_str_hash(channel_id), merged_username, flags, escaped_content, timestamp);
			}
			
			if (attachments) {
				for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
					JsonObject *attachment = json_array_get_object_element(attachments, i);
					const gchar *url = json_object_get_string_member(attachment, "url");
					
					purple_serv_got_chat_in(da->pc, g_str_hash(channel_id), merged_username, flags, url, timestamp);
				}
			}
			
			g_free(merged_username);
		}
		g_free(escaped_content);
	} else if (purple_strequal(type, "TYPING_START")) {
		const gchar *channel_id = json_object_get_string_member(data, "channel_id");
		const gchar *user_id = json_object_get_string_member(data, "user_id");
		const gchar *username = g_hash_table_lookup(da->ids_to_usernames, user_id);
		
		if (g_hash_table_contains(da->group_chats, channel_id)) {
			// This is a group conversation
			PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(g_hash_table_lookup(da->group_chats, channel_id), da->account);
			if (chatconv == NULL) {
				chatconv = purple_conversations_find_chat_with_account(channel_id, da->account);
			}
			if (chatconv != NULL) {
				PurpleChatUser *cb = purple_chat_conversation_find_user(chatconv, username);
				PurpleChatUserFlags cbflags;

				if (cb == NULL) {
					// Getting notified about a buddy we dont know about yet
					//TODO add buddy
					return;
				}
				cbflags = purple_chat_user_get_flags(cb);
				
				//if (is_typing)
					cbflags |= PURPLE_CHAT_USER_TYPING;
				//else //TODO
				//	cbflags &= ~PURPLE_CHAT_USER_TYPING;
				
				purple_chat_user_set_flags(cb, cbflags);
			}
		} else {
			purple_serv_got_typing(da->pc, username, 10, PURPLE_IM_TYPING);
			
		}
		
	} else if (purple_strequal(type, "CHANNEL_CREATE")) {
		const gchar *channel_id = json_object_get_string_member(data, "id");
		gint64 channel_type = json_object_get_int_member(data, "type");
		
		if (channel_type == 1) {
			JsonObject *first_recipient = json_array_get_object_element(json_object_get_array_member(data, "recipients"), 0);
			
			if (first_recipient != NULL) {
				const gchar *user_id = json_object_get_string_member(first_recipient, "id");
				const gchar *username = json_object_get_string_member(first_recipient, "username");
				const gchar *discriminator = json_object_get_string_member(first_recipient, "discriminator");
				
				g_hash_table_replace(da->one_to_ones, g_strdup(channel_id), discord_combine_username(username, discriminator));
				g_hash_table_replace(da->one_to_ones_rev, discord_combine_username(username, discriminator), g_strdup(channel_id));
				
				g_hash_table_replace(da->usernames_to_ids, discord_combine_username(username, discriminator), g_strdup(user_id));
				g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), discord_combine_username(username, discriminator));
			}
			
		} else {
			const gchar *name = json_object_get_string_member(data, "name");
			
			if (name != NULL) {
				const gchar *guild_id = json_object_get_string_member(data, "guild_id");
				const gchar *guild_name = g_hash_table_lookup(da->guilds, guild_id);
				const gchar *channel_name = discord_normalise_room_name(guild_name, name);
				
				g_hash_table_replace(da->group_chats, g_strdup(channel_id), g_strdup(channel_name));
				g_hash_table_replace(da->group_chats_rev, g_strdup(channel_name), g_strdup(channel_id));
			} else {
				g_hash_table_replace(da->group_chats, g_strdup(channel_id), NULL);
			}
		}
	} else if (purple_strequal(type, "CHANNEL_UPDATE")) {
		const gchar *channel_id = json_object_get_string_member(data, "id");
		gint64 channel_type = json_object_get_int_member(data, "type");
		
		if ((channel_type == 0 && json_object_has_member(data, "topic")) ||
				channel_type == 3) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, g_str_hash(channel_id));
			if (chatconv) {
				purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(data, (channel_type == 1 ? "topic" : "name")));
			}
		}
	} else if (purple_strequal(type, "RELATIONSHIP_ADD")) {
		JsonObject *user = json_object_get_object_member(data, "user");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *discriminator = json_object_get_string_member(user, "discriminator");
		const gchar *user_id = json_object_get_string_member(user, "id");
		gint64 user_type = json_object_get_int_member(data, "type");
		gchar *merged_username = discord_combine_username(username, discriminator);
		
		g_hash_table_replace(da->usernames_to_ids, g_strdup(merged_username), g_strdup(user_id));
		g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), g_strdup(merged_username));
		
		if (user_type == 3) {
			//request add
		} else if (user_type == 1) {
			const gchar *avatar_id = json_object_get_string_member(user, "avatar");
			PurpleBuddy *buddy = purple_blist_find_buddy(da->account, merged_username);
			
			if (buddy == NULL) {
				buddy = purple_buddy_new(da->account, merged_username, username);
				purple_blist_add_buddy(buddy, NULL, discord_get_or_create_default_group(), NULL);
			}
			
			discord_get_avatar(da, user_id, avatar_id);
		}
		
		g_free(merged_username);
	} else if (purple_strequal(type, "RELATIONSHIP_REMOVE")) {
		const gchar *user_id = json_object_get_string_member(data, "id");
		gchar *username = g_strdup(g_hash_table_lookup(da->ids_to_usernames, user_id));
		
		if (username != NULL) {
			PurpleBuddy *buddy = purple_blist_find_buddy(da->account, username);
			purple_blist_remove_buddy(buddy);
			
			g_hash_table_remove(da->one_to_ones, g_hash_table_lookup(da->one_to_ones_rev, username));
			g_hash_table_remove(da->one_to_ones_rev, username);
			
			g_hash_table_remove(da->usernames_to_ids, username);
			g_hash_table_remove(da->ids_to_usernames, user_id);
			
		}
		
		g_free(username);
	} else if (purple_strequal(type, "READY")) {
		JsonObject *self_user = json_object_get_object_member(data, "user");
		g_free(da->self_user_id); da->self_user_id = g_strdup(json_object_get_string_member(self_user, "id"));
		if (!purple_account_get_private_alias(da->account)) {
			purple_account_set_private_alias(da->account, json_object_get_string_member(self_user, "username"));
		}
		g_free(da->self_username); da->self_username = discord_combine_username(json_object_get_string_member(self_user, "username"), json_object_get_string_member(self_user, "discriminator"));
		purple_connection_set_display_name(da->pc, da->self_username);
		g_hash_table_replace(da->usernames_to_ids, g_strdup(da->self_username), g_strdup(da->self_user_id));
		g_hash_table_replace(da->ids_to_usernames, g_strdup(da->self_user_id), g_strdup(da->self_username));
		
		
		g_free(da->session_id); da->session_id = g_strdup(json_object_get_string_member(data, "session_id"));
		
		discord_got_relationships(da, json_object_get_member(data, "relationships"), NULL);
		discord_got_private_channels(da, json_object_get_member(data, "private_channels"), NULL);
		discord_got_presences(da, json_object_get_member(data, "presences"), NULL);
		discord_got_guilds(da, json_object_get_member(data, "guilds"), NULL);
		
	} else {
		purple_debug_info("discord", "Unhandled message type '%s'\n", type);
	}
		
	
}

PurpleGroup* discord_get_or_create_default_group() {
    PurpleGroup *discord_group = NULL;
	
	discord_group = purple_blist_find_group(_("Discord"));
	if (!discord_group)
	{
		discord_group = purple_group_new(_("Discord"));
		purple_blist_add_group(discord_group, NULL);
	}
	
    return discord_group;
}


static const gchar *
discord_normalise_room_name(const gchar *guild_name, const gchar *name)
{
	gchar *channel_name = g_strconcat(guild_name, "#", name, NULL);
	static gchar *old_name = NULL;
	
	g_free(old_name);
	old_name = g_ascii_strdown(channel_name, -1);
	purple_util_chrreplace(old_name, ' ', '_');
	
	return old_name;
}

static void
discord_roomlist_got_list(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	PurpleRoomlist *roomlist = user_data;
	JsonArray *channels = json_node_get_array(node);
	guint i, len = json_array_get_length(channels);
	PurpleRoomlistRoom *guild_category = NULL;
			
	for (i = 0; i < len; i++) {
		JsonObject *channel = json_array_get_object_element(channels, i);
		const gchar *id = json_object_get_string_member(channel, "id");
		const gchar *name = json_object_get_string_member(channel, "name");
		const gint64 type = json_object_get_int_member(channel, "type");
		const gchar *type_str;
		const gchar *guild_name;
		const gchar *channel_name;
		PurpleRoomlistRoom *room;

		if (i == 0) {
			const gchar *guild_id = json_object_get_string_member(channel, "guild_id");
			guild_name = g_hash_table_lookup(da->guilds, guild_id);
			guild_category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, guild_name, NULL);
			purple_roomlist_room_add(roomlist, guild_category);
		}
		
		channel_name = discord_normalise_room_name(guild_name, name);
		
		g_hash_table_replace(da->group_chats, g_strdup(id), g_strdup(channel_name));
		g_hash_table_replace(da->group_chats_rev, g_strdup(channel_name), g_strdup(id));
		
		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, channel_name, guild_category);
		
		purple_roomlist_room_add_field(roomlist, room, id);
		purple_roomlist_room_add_field(roomlist, room, name);
		switch(type) {
			case 0: type_str = "Text"; break;
			case 1: type_str = "Private"; break;
			case 2: type_str = "Voice"; break;
			case 4: type_str = "Private Group"; break;
			default: type_str = "Unknown"; break;
		}
		purple_roomlist_room_add_field(roomlist, room, type_str);
		
		purple_roomlist_room_add(roomlist, room);
	}
	
	//Only after last guild
	da->roomlist_guild_count--;
	if (da->roomlist_guild_count <= 0) {
		purple_roomlist_set_in_progress(roomlist, FALSE);
	}
}

static gchar *
discord_roomlist_serialize(PurpleRoomlistRoom *room) {
	const gchar *channel_name = purple_roomlist_room_get_name(room);
	PurpleRoomlistRoom *guild_category;
	const gchar *guild_name;
	GList *fields;
	const gchar *id;
	const gchar *name;
	
	if (channel_name && *channel_name) {
		return g_strdup(channel_name);
	}
	
	guild_category = purple_roomlist_room_get_parent(room);
	guild_name = purple_roomlist_room_get_name(guild_category);
	fields = purple_roomlist_room_get_fields(room);
	id = (const gchar *) fields->data;
	name = (const gchar *) fields->next->data;
	
	if (name && *name) {
		return g_strdup(discord_normalise_room_name(guild_name, name));
	} else {
		return g_strdup(id);
	}
}

PurpleRoomlist *
discord_roomlist_get_list(PurpleConnection *pc)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;
	GList *guilds = NULL;
	
	roomlist = purple_roomlist_new(da->account);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "id", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Room Type"), "type", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);
	
	//Loop through guilds and request all channels
	for(guilds = g_hash_table_get_keys(da->guilds); guilds; guilds = guilds->next)
	{
		const gchar *guild_id = guilds->data;
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/guilds/%s/channels", purple_url_encode(guild_id));
		discord_fetch_url(da, url, NULL, discord_roomlist_got_list, roomlist);
		g_free(url);
		
		da->roomlist_guild_count++;
	}
	
	return roomlist;
}


void
discord_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	DiscordAccount *ya = purple_connection_get_protocol_data(pc);
	const gchar *status_id = purple_status_get_id(status);
	
	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	
	if (g_str_has_prefix(status_id, "set-")) {
		status_id = &status_id[4];
	}
	
	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status_id);
	json_object_set_object_member(obj, "d", data);
	
	discord_socket_write_json(ya, obj);
}

void
discord_set_idle(PurpleConnection *pc, int idle_time)
{
	DiscordAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	const gchar *status = "idle";
	gint64 since = (time(NULL) - idle_time) * 1000;
	
	if (idle_time < 20) {
		status = "online";
		since = 0;
	}
	
	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status);
	json_object_set_int_member(data, "since", since);
	json_object_set_object_member(obj, "d", data);
	
	discord_socket_write_json(ya, obj);
}

static void discord_start_socket(DiscordAccount *ya);

static void
discord_restart_channel(DiscordAccount *da)
{
	purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTING);
	discord_start_socket(da);
}

static void
discord_build_groups_from_blist(DiscordAccount *ya)
{
	PurpleBlistNode *node;
	
	for (node = purple_blist_get_root();
	     node != NULL;
		 node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_CHAT(node)) {
			const gchar *channel_id;
			const gchar *name;
			PurpleChat *chat = PURPLE_CHAT(node);
			if (purple_chat_get_account(chat) != ya->account) {
				continue;
			}
			
			name = purple_chat_get_name(chat);
			channel_id = purple_blist_node_get_string(node, "channel_id");
			if (name == NULL || channel_id == NULL || purple_strequal(name, channel_id)) {
				GHashTable *components = purple_chat_get_components(chat);
				if (components != NULL) {
					if (channel_id == NULL) {
						channel_id = g_hash_table_lookup(components, "id");
					}
					if (name == NULL || purple_strequal(name, channel_id)) {
						name = g_hash_table_lookup(components, "name");
					}
				}
			}
			if (channel_id != NULL) {
				g_hash_table_replace(ya->group_chats, g_strdup(channel_id), name ? g_strdup(name) : NULL);
			}
			if (name != NULL) {
				g_hash_table_replace(ya->group_chats_rev, g_strdup(name), channel_id ? g_strdup(channel_id) : NULL);
			}
		} else if (PURPLE_IS_BUDDY(node)) {
			const gchar *discord_id;
			const gchar *name;
			PurpleBuddy *buddy = PURPLE_BUDDY(node);
			if (purple_buddy_get_account(buddy) != ya->account) {
				continue;
			}
			
			name = purple_buddy_get_name(buddy);
			discord_id = purple_blist_node_get_string(node, "discord_id");
			if (discord_id != NULL) {
				g_hash_table_replace(ya->one_to_ones, g_strdup(discord_id), g_strdup(name));
				g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(discord_id));
			}
		}
	}
}

static guint discord_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, DiscordAccount *ya);
static gulong chat_conversation_typing_signal = 0;
static void discord_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);
static gulong conversation_updated_signal = 0;



static void
discord_got_relationships(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *relationships = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(relationships);
	PurpleGroup *defaultGroup = discord_get_or_create_default_group();

	for (i = len - 1; i >= 0; i--) {
		JsonObject *relation = json_array_get_object_element(relationships, i);
		gint64 type = json_object_get_int_member(relation, "type");
		JsonObject *user = json_object_get_object_member(relation, "user");
		const gchar *user_id = json_object_get_string_member(user, "id");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *discriminator = json_object_get_string_member(user, "discriminator");
		gchar *merged_username = discord_combine_username(username, discriminator);
		
		g_hash_table_replace(da->usernames_to_ids, g_strdup(merged_username), g_strdup(user_id));
		g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), g_strdup(merged_username));

		if (type == 3) {
			// Incoming friend request
		} //type == 4 //Outgoing friend request
		else if (type == 1) {
			PurpleBuddy *buddy = purple_blist_find_buddy(da->account, merged_username);
			if (buddy == NULL) {
				buddy = purple_buddy_new(da->account, merged_username, username);
				purple_blist_add_buddy(buddy, NULL, defaultGroup, NULL);
			}
			
			discord_get_avatar(da, user_id, json_object_get_string_member(user, "avatar"));
		}
		
		g_free(merged_username);
	}
}

static void
discord_got_private_channels(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *private_channels = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(private_channels);

	for (i = len - 1; i >= 0; i--) {
		JsonObject *channel = json_array_get_object_element(private_channels, i);
		JsonArray *recipients = json_object_get_array_member(channel, "recipients");
		const gchar *room_id = json_object_get_string_member(channel, "id");
		gint64 room_type = json_object_get_int_member(channel, "type");
		
		if (room_type == 1) {
			//One-to-one DM
			JsonObject *user = json_array_get_object_element(recipients, 0);
			const gchar *user_id = json_object_get_string_member(user, "id");
			const gchar *username = json_object_get_string_member(user, "username");
			const gchar *discriminator = json_object_get_string_member(user, "discriminator");
			gchar *merged_username = discord_combine_username(username, discriminator);
			
			g_hash_table_replace(da->usernames_to_ids, g_strdup(merged_username), g_strdup(user_id));
			g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), g_strdup(merged_username));
			
			g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(merged_username));
			g_hash_table_replace(da->one_to_ones_rev, g_strdup(merged_username), g_strdup(room_id));
			
			g_free(merged_username);
		} else {
			//Private group DM
			if (!g_hash_table_contains(da->group_chats, room_id)) {
				g_hash_table_replace(da->group_chats, g_strdup(room_id), g_strdup(room_id));
				g_hash_table_replace(da->group_chats_rev, g_strdup(room_id), g_strdup(room_id));
			}
		}
	}
}

static void
discord_got_presences(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *presences = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(presences);

	for (i = len - 1; i >= 0; i--) {
		JsonObject *presence = json_array_get_object_element(presences, i);
		JsonObject *user = json_object_get_object_member(presence, "user");
		const gchar *status = json_object_get_string_member(presence, "status");
		const gchar *user_id = json_object_get_string_member(user, "id");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *discriminator = json_object_get_string_member(user, "discriminator");
		const gchar *game = json_object_get_string_member(presence, "game");
		gchar *merged_username = discord_combine_username(username, discriminator);
		
		g_hash_table_replace(da->usernames_to_ids, g_strdup(merged_username), g_strdup(user_id));
		g_hash_table_replace(da->ids_to_usernames, g_strdup(user_id), g_strdup(merged_username));
		
		purple_protocol_got_user_status(da->account, merged_username, status, "message", game, NULL);
		purple_protocol_got_user_idle(da->account, merged_username, purple_strequal(status, "idle"), 0);
		
		g_free(merged_username);
	}
}

static void
discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *guilds = json_node_get_array(node);
	gint i, j;
	guint len = json_array_get_length(guilds);

	for (i = len - 1; i >= 0; i--) {
		JsonObject *guild = json_array_get_object_element(guilds, i);
		const gchar *id = json_object_get_string_member(guild, "id");
		const gchar *name = json_object_get_string_member(guild, "name");
		JsonArray *channels = json_object_get_array_member(guild, "channels");
		
		g_hash_table_replace(da->guilds, g_strdup(id), g_strdup(name));
		
		for (j = json_array_get_length(channels) - 1; j >= 0; j--) {
			JsonObject *channel = json_array_get_object_element(channels, j);
			const gchar *room_id = json_object_get_string_member(channel, "id");
			const gchar *room_name = json_object_get_string_member(channel, "name");
			const gchar *channel_name = discord_normalise_room_name(name, room_name);
			
			if (!g_hash_table_contains(da->group_chats, room_id)) {
				g_hash_table_replace(da->group_chats, g_strdup(room_id), g_strdup(channel_name));
				g_hash_table_replace(da->group_chats_rev, g_strdup(channel_name), g_strdup(room_id));
			}
		}
	}
	
}

// static void
// discord_get_buddies(DiscordAccount *da)
// {
	// discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships", NULL, discord_got_relationships, NULL);
// }

static void discord_login_response(DiscordAccount *da, JsonNode *node, gpointer user_data);

static void
discord_mfa_text_entry(gpointer user_data, const gchar *code)
{
	DiscordAccount *da = user_data;
	JsonObject *data = json_object_new();
	gchar *str;
	
	json_object_set_string_member(data, "code", code);
	json_object_set_string_member(data, "ticket", da->mfa_ticket);
	
	str = json_object_to_string(data);
	discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/auth/mfa/totp", str, discord_login_response, NULL);
	
	g_free(str);
	json_object_unref(data);
	
	g_free(da->mfa_ticket);
	da->mfa_ticket = NULL;
}

static void
discord_mfa_cancel(gpointer user_data)
{
	DiscordAccount *da = user_data;
	
	purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Cancelled 2FA auth");
}

static void
discord_login_response(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	
	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		
		da->token = g_strdup(json_object_get_string_member(response, "token"));
		
		purple_account_set_string(da->account, "token", da->token);
		
		if (da->token) {
			purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
			discord_start_socket(da);
			//discord_get_buddies(da);
			return;
		}
		
		if (json_object_get_boolean_member(response, "mfa")) {
			g_free(da->mfa_ticket);
			da->mfa_ticket = g_strdup(json_object_get_string_member(response, "ticket"));
			
			purple_request_input(da->pc, _("Two-factor authentication"),
							   _("Enter Discord auth code"),
							   _("You can get this token from your two-factor authentication mobile app."),
							   NULL, FALSE, FALSE, "",
							   _("_Login"), G_CALLBACK(discord_mfa_text_entry),
							   _("_Cancel"), G_CALLBACK(discord_mfa_cancel),
							   purple_request_cpar_from_connection(da->pc),
							   da);
			return;
		}
		
		if (json_object_has_member(response, "email")) {
			// Probably an error about new location
			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "email"));
			return;
		}
		if (json_object_has_member(response, "password")) {
			// Probably an error about bad password
			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "password"));
			return;
		}
	}
	
	purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Bad username/password");
}

void
discord_login(PurpleAccount *account)
{
	DiscordAccount *da;
	PurpleConnection *pc = purple_account_get_connection(account);
	PurpleConnectionFlags pc_flags;
	
	pc_flags = purple_connection_get_flags(pc);
	//pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	purple_connection_set_flags(pc, pc_flags);
	
	da = g_new0(DiscordAccount, 1);
	purple_connection_set_protocol_data(pc, da);
	da->account = account;
	da->pc = pc;
	da->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	
	// da->last_load_last_message_timestamp = purple_account_get_int(account, "last_message_timestamp_high", 0);
	// if (da->last_load_last_message_timestamp != 0) {
		// da->last_load_last_message_timestamp = (da->last_load_last_message_timestamp << 32) | ((guint64) purple_account_get_int(account, "last_message_timestamp_low", 0) & 0xFFFFFFFF);
	// }
	
	da->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->group_chats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->group_chats_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	da->result_callbacks = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->usernames_to_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->ids_to_usernames = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->guilds = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->received_message_queue = g_queue_new();
	
	discord_build_groups_from_blist(da);
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
	
	da->token = g_strdup(purple_account_get_string(account, "token", NULL));
	
	if (da->token) {
		discord_start_socket(da);
		//discord_get_buddies(da);
	} else {
		JsonObject *data = json_object_new();
		gchar *str;
		
		json_object_set_string_member(data, "email", purple_account_get_username(account));
		json_object_set_string_member(data, "password", purple_connection_get_password(da->pc));
		
		str = json_object_to_string(data);
		discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/auth/login", str, discord_login_response, NULL);
		
		g_free(str);
		json_object_unref(data);
	}
	
	
	if (!chat_conversation_typing_signal) {
		chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(discord_conv_send_typing), NULL);
	}
	if (!conversation_updated_signal) {
		conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(discord_mark_conv_seen), NULL);
	}
}


static void 
discord_close(PurpleConnection *pc)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	// PurpleAccount *account;
	
	g_return_if_fail(da != NULL);
	
	purple_timeout_remove(da->heartbeat_timeout);
	
	// account = purple_connection_get_account(pc);
	if (da->websocket != NULL) purple_ssl_close(da->websocket);
	
	g_hash_table_remove_all(da->one_to_ones);
	g_hash_table_unref(da->one_to_ones);
	g_hash_table_remove_all(da->one_to_ones_rev);
	g_hash_table_unref(da->one_to_ones_rev);
	g_hash_table_remove_all(da->group_chats);
	g_hash_table_unref(da->group_chats);
	g_hash_table_remove_all(da->sent_message_ids);
	g_hash_table_unref(da->sent_message_ids);
	g_hash_table_remove_all(da->result_callbacks);
	g_hash_table_unref(da->result_callbacks);
	g_hash_table_remove_all(da->usernames_to_ids);
	g_hash_table_unref(da->usernames_to_ids);
	g_hash_table_remove_all(da->ids_to_usernames);
	g_hash_table_unref(da->ids_to_usernames);
	g_hash_table_remove_all(da->guilds);
	g_hash_table_unref(da->guilds);
	g_queue_free(da->received_message_queue);

	while (da->http_conns) {
#	if !PURPLE_VERSION_CHECK(3, 0, 0)
		purple_util_fetch_url_cancel(da->http_conns->data);
#	else
		purple_http_conn_cancel(da->http_conns->data);
#	endif
		da->http_conns = g_slist_delete_link(da->http_conns, da->http_conns);
	}

	while (da->pending_writes) {
		json_object_unref(da->pending_writes->data);
		da->pending_writes = g_slist_delete_link(da->pending_writes, da->pending_writes);
	}
	
	g_hash_table_destroy(da->cookie_table); da->cookie_table = NULL;
	g_free(da->frame); da->frame = NULL;
	g_free(da->token); da->token = NULL;
	g_free(da->session_id); da->session_id = NULL;
	g_free(da->self_username); da->self_username = NULL;
	g_free(da->self_user_id); da->self_user_id = NULL;
	g_free(da);
}















//static void discord_start_polling(DiscordAccount *ya);

static gboolean
discord_process_frame(DiscordAccount *da, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	JsonObject *obj;
	gint64 opcode;
	
	purple_debug_info("discord", "got frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("discord", "Error parsing response: %s\n", frame);
		return TRUE;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		obj = json_node_get_object(root);
		
		opcode = json_object_get_int_member(obj, "op");
		switch(opcode) {
			case 0: {//Dispatch
				const gchar *type = json_object_get_string_member(obj, "t");
				gint64 seq = json_object_get_int_member(obj, "s");
				
				da->seq = seq;
				discord_process_dispatch(da, type, json_object_get_object_member(obj, "d"));
				
				break;
			}
			case 7: {//Reconnect
				discord_start_socket(da);
				break;
			}
			case 9: {//Invalid session
				da->seq = 0;
				g_free(da->session_id); da->session_id = NULL;
				
				discord_send_auth(da);
				break;
			}
			case 10: {//Hello
				JsonObject *data = json_object_get_object_member(obj, "d");
				gint64 heartbeat_interval = json_object_get_int_member(data, "heartbeat_interval");
				discord_send_auth(da);
				
				purple_timeout_remove(da->heartbeat_timeout);
				if (heartbeat_interval) {
					da->heartbeat_timeout = purple_timeout_add(json_object_get_int_member(data, "heartbeat_interval"), discord_send_heartbeat, da);
				} else {
					da->heartbeat_timeout = 0;
				}
				break;
			}
			case 11: {//Heartbeat ACK
				break;
			}
			default: {
				purple_debug_info("discord", "Unhandled op code %" G_GINT64_FORMAT "\n", opcode);
				break;
			}
		}
	}
	
	g_object_unref(parser);
	return TRUE;
}

static guchar *
discord_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void
discord_socket_write_data(DiscordAccount *ya, guchar *data, gsize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };
	
	if (data_len) {
		purple_debug_info("discord", "sending frame: %*s\n", (int)data_len, data);
	}
	
	data = discord_websocket_mask(mkey, data, data_len);
	
	if (data_len > 125) {
		if (data_len <= G_MAXUINT16) {
			len_size += 2;
		} else {
			len_size += 8;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size + 4);
	
	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;
	
	if (data_len <= 125) {
		full_data[1] = data_len | 0x80;
	} else if (data_len <= G_MAXUINT16) {
		guint16 be_len = GUINT16_TO_BE(data_len);
		full_data[1] = 126 | 0x80;
		memmove(full_data + 2, &be_len, 2);
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127 | 0x80;
		memmove(full_data + 2, &be_len, 8);
	}
	
	memmove(full_data + (1 + len_size), &mkey, 4);
	memmove(full_data + (1 + len_size + 4), data, data_len);
	
	purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
	
	g_free(full_data);
	g_free(data);
}

/* takes ownership of data parameter */
static void
discord_socket_write_json(DiscordAccount *rca, JsonObject *data)
{
	JsonNode *node;
	gchar *str;
	gsize len;
	JsonGenerator *generator;
	
	if (rca->websocket == NULL) {
		if (data != NULL) {
			rca->pending_writes = g_slist_append(rca->pending_writes, data);
		}
		return;
	}
	
	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, data);
	
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, &len);
	g_object_unref(generator);
	json_node_free(node);
	
	discord_socket_write_data(rca, (guchar *)str, len, 0);
	
	g_free(str);
}

static void
discord_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	DiscordAccount *ya = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	
	
	if (G_UNLIKELY(!ya->websocket_header_received)) {
		gint nlbr_count = 0;
		gchar nextchar;
		
		while(nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1)) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}
		
		ya->websocket_header_received = TRUE;
		done_some_reads = TRUE;

		/* flush stuff that we attempted to send before the websocket was ready */
		while (ya->pending_writes) {
			discord_socket_write_json(ya, ya->pending_writes->data);
			ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
		}
	}
	
	while(ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
		if (!ya->frame) {
			if (ya->packet_code != 129) {
				if (ya->packet_code == 136) {
					purple_debug_error("discord", "websocket closed\n");
					
					// Try reconnect
					discord_start_socket(ya);
					
					return;
				} else if (ya->packet_code == 137) {
					// Ping
					gint ping_frame_len;
					length_code = 0;
					purple_ssl_read(conn, &length_code, 1);
					if (length_code <= 125) {
						ping_frame_len = length_code;
					} else if (length_code == 126) {
						guchar len_buf[2];
						purple_ssl_read(conn, len_buf, 2);
						ping_frame_len = (len_buf[0] << 8) + len_buf[1];
					} else if (length_code == 127) {
						purple_ssl_read(conn, &ping_frame_len, 8);
						ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
					}
					if (ping_frame_len) {
						guchar *pong_data = g_new0(guchar, ping_frame_len);
						purple_ssl_read(conn, pong_data, ping_frame_len);

						discord_socket_write_data(ya, pong_data, ping_frame_len, 138);
						g_free(pong_data);
					} else {
						discord_socket_write_data(ya, (guchar *) "", 0, 138);
					}
					return;
				} else if (ya->packet_code == 138) {
					// Pong
					//who cares
					return;
				}
				purple_debug_error("discord", "unknown websocket error %d\n", ya->packet_code);
				return;
			}
			
			length_code = 0;
			purple_ssl_read(conn, &length_code, 1);
			if (length_code <= 125) {
				ya->frame_len = length_code;
			} else if (length_code == 126) {
				guchar len_buf[2];
				purple_ssl_read(conn, len_buf, 2);
				ya->frame_len = (len_buf[0] << 8) + len_buf[1];
			} else if (length_code == 127) {
				purple_ssl_read(conn, &ya->frame_len, 8);
				ya->frame_len = GUINT64_FROM_BE(ya->frame_len);
			}
			//purple_debug_info("discord", "frame_len: %" G_GUINT64_FORMAT "\n", ya->frame_len);
			
			ya->frame = g_new0(gchar, ya->frame_len + 1);
			ya->frame_len_progress = 0;
		}
		
		do {
			read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);
			if (read_len > 0) {
				ya->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ya->frame_len_progress < ya->frame_len);
		done_some_reads = TRUE;
		
		if (ya->frame_len_progress == ya->frame_len) {
			gboolean success = discord_process_frame(ya, ya->frame);
			g_free(ya->frame); ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			
			if (G_UNLIKELY(ya->websocket == NULL || success == FALSE)) {
				return;
			}
		} else {
			return;
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("discord", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

		if (ya->frames_since_reconnect < 2) {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
		} else {
			// Try reconnect
			discord_start_socket(ya);
		}
	}
}

static void
discord_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	DiscordAccount *da = userdata;
	gchar *websocket_header;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	
	purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
	
	purple_ssl_input_add(da->websocket, discord_socket_got_data, da);
	
	websocket_header = g_strdup_printf("GET %s HTTP/1.1\r\n"
							"Host: %s\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							"User-Agent: " DISCORD_USERAGENT "\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", DISCORD_GATEWAY_SERVER_PATH, DISCORD_GATEWAY_SERVER,
							websocket_key);
	
	purple_ssl_write(da->websocket, websocket_header, strlen(websocket_header));
	
	g_free(websocket_header);
}

static void
discord_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	DiscordAccount *da = userdata;
	
	da->websocket = NULL;
	da->websocket_header_received = FALSE;
	
	if (da->frames_since_reconnect < 1) {
		purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Couldn't connect to gateway");
	} else {
		discord_restart_channel(da);
	}
}

static void
discord_start_socket(DiscordAccount *da)
{
	purple_timeout_remove(da->heartbeat_timeout);
	
	//Reset all the old stuff
	if (da->websocket != NULL) {
		purple_ssl_close(da->websocket);
	}
	
	da->websocket = NULL;
	da->websocket_header_received = FALSE;
	g_free(da->frame); da->frame = NULL;
	da->packet_code = 0;
	da->frame_len = 0;
	da->frames_since_reconnect = 0;

	da->websocket = purple_ssl_connect(da->account, DISCORD_GATEWAY_SERVER, DISCORD_GATEWAY_PORT, discord_socket_connected, discord_socket_failed, da);
}






static void
discord_chat_leave_by_room_id(PurpleConnection *pc, const gchar *room_id)
{
	/*DiscordAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *data = json_object_new();
	JsonArray *params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "leaveRoom");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", discord_get_next_id_str(ya));
	
	discord_socket_write_json(ya, data);*/
}

static void
discord_chat_leave(PurpleConnection *pc, int id)
{
	const gchar *room_id = NULL;
	PurpleChatConversation *chatconv;
	
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (room_id == NULL) {
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	
	discord_chat_leave_by_room_id(pc, room_id);
}

static void
discord_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	// DiscordAccount *ya;
	// const gchar *room_id;
	// PurpleChatConversation *chatconv;
	// JsonObject *data = json_object_new();
	
	// ya = purple_connection_get_protocol_data(pc);
	// chatconv = purple_conversations_find_chat(pc, id);
	// room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	// if (room_id == NULL) {
		// room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	// }
	
	// json_object_set_string_member(data, "msg", "InviteGroupMember");
	// json_object_set_string_member(data, "groupId", groupId);
	// json_object_set_int_member(data, "opId", ya->opid++);
	// json_object_set_string_member(data, "userId", who);
	// json_object_set_string_member(data, "memberId", "00000000000FFFFF");
	// json_object_set_string_member(data, "firstName", "");
	// json_object_set_string_member(data, "lastName", "");
	
	// discord_socket_write_json(ya, data);
}

static GList *
discord_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;
	
	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Name");
	pce->identifier = "name";
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Channel ID");
	pce->identifier = "id";
	m = g_list_append(m, pce);
	
	return m;
}

static gboolean
str_is_number(const gchar *str)
{
	gint i = strlen(str) - 1;
	for(; i >= 0; i--) {
		if (!g_ascii_isdigit(str[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static GHashTable *
discord_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	
	if (chatname != NULL)
	{
		if (strchr(chatname, '#')) {
			const gchar *id = g_hash_table_lookup(da->group_chats_rev, chatname);
			g_hash_table_insert(defaults, "name", g_strdup(chatname));
			g_hash_table_insert(defaults, "id", g_strdup(id));
		} else if (str_is_number(chatname)) {
			const gchar *name = g_hash_table_lookup(da->group_chats, chatname);
			g_hash_table_insert(defaults, "id", g_strdup(chatname));
			g_hash_table_insert(defaults, "name", g_strdup(name));
		} else {
			const gchar *id = g_hash_table_lookup(da->group_chats_rev, chatname);
			g_hash_table_insert(defaults, "name", g_strdup(chatname));
			g_hash_table_insert(defaults, "id", g_strdup(id));
		}
	}
	
	return defaults;
}

static gchar *
discord_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL) {
		return NULL;
	}
	
	temp = g_hash_table_lookup(data, "name");
	
	if (temp == NULL) {
		temp = g_hash_table_lookup(data, "id");
	}

	if (temp == NULL) {
		return NULL;
	}

	return g_strdup(temp);
}



/*static void
discord_got_history_of_room(DiscordAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *result = json_node_get_object(node);
	JsonArray *messages = json_object_get_array_member(result, "messages");
	gchar *room_id = user_data;
	gint i, len = json_array_get_length(messages);
	gint64 last_message = discord_get_room_last_timestamp(ya, room_id);
	gint64 rolling_last_message_timestamp = 0;
	
	//latest are first
	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
		JsonObject *ts = json_object_get_object_member(message, "ts");
		gint64 sdate = json_object_get_int_member(ts, "$date");
		
		if (last_message >= sdate) {
			continue;
		}
		
		//rolling_last_message_timestamp = discord_process_room_message(ya, message, NULL);
	}
	
	if (rolling_last_message_timestamp != 0) {
		discord_set_room_last_timestamp(ya, room_id, rolling_last_message_timestamp);
	}
	
	g_free(room_id);
}*/


	// libpurple can't store a 64bit int on a 32bit machine, so convert to something more usable instead (puke)
	//  also needs to work cross platform, in case the accounts.xml is being shared (double puke)

/*static gint64
discord_get_room_last_timestamp(DiscordAccount *ya, const gchar *room_id)
{
	guint64 last_message_timestamp = ya->last_load_last_message_timestamp;
	PurpleBlistNode *blistnode = NULL;
	
	if (g_hash_table_contains(ya->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, g_hash_table_lookup(ya->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ya->account, g_hash_table_lookup(ya->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		gint64 last_room_timestamp = purple_blist_node_get_int(blistnode, "last_message_timestamp_high");
		if (last_room_timestamp != 0) {
			last_room_timestamp = (last_room_timestamp << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_timestamp_low") & 0xFFFFFFFF);
			
			ya->last_message_timestamp = MAX(ya->last_message_timestamp, last_room_timestamp);
			return last_room_timestamp;
		}
	}
	
	return last_message_timestamp;
}

static void
discord_set_room_last_timestamp(DiscordAccount *ya, const gchar *room_id, gint64 last_timestamp)
{
	PurpleBlistNode *blistnode = NULL;
	
	if (last_timestamp <= ya->last_message_timestamp) {
		return;
	}
	
	if (g_hash_table_contains(ya->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, g_hash_table_lookup(ya->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ya->account, g_hash_table_lookup(ya->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		purple_blist_node_set_int(blistnode, "last_message_timestamp_high", last_timestamp >> 32);
		purple_blist_node_set_int(blistnode, "last_message_timestamp_low", last_timestamp & 0xFFFFFFFF);
	}
	
	ya->last_message_timestamp = last_timestamp;	
	purple_account_set_int(ya->account, "last_message_timestamp_high", last_timestamp >> 32);
	purple_account_set_int(ya->account, "last_message_timestamp_low", last_timestamp & 0xFFFFFFFF);
	
}*/



typedef struct {
	DiscordAccount *da;
	gchar *channel_id;
	GList *allowed_roles;
	GList *denied_roles;
} DiscordChannelPermissionLookup;

static void 
discord_got_users_of_room(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordChannelPermissionLookup *lookup = user_data;
	PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, g_str_hash(lookup->channel_id));
	
	if (chatconv != NULL) {
		JsonArray *members = json_node_get_array(node);
		gint i, j;
		guint len = json_array_get_length(members);
		GList *users = NULL, *flags = NULL;
	
		for (i = len - 1; i >= 0; i--) {
			JsonObject *member = json_array_get_object_element(members, i);
			JsonArray *roles = json_object_get_array_member(member, "roles");
			gboolean is_allowed = TRUE;
			
			if (lookup->allowed_roles || lookup->denied_roles) {
				is_allowed = FALSE;
				for (j = json_array_get_length(roles) - 1; j >= 0; j--) {
					const gchar *role = json_array_get_string_element(roles, j);
					
					if (g_list_find_custom(lookup->allowed_roles, role, (GCompareFunc) g_strcmp0) ||
						!g_list_find_custom(lookup->denied_roles, role, (GCompareFunc) g_strcmp0)) {
						//TODO this logic for denied_roles isn't right
						is_allowed = TRUE;
						break;
					}
				}
			}
			
			if (is_allowed) {
				JsonObject *user = json_object_get_object_member(member, "user");
				const gchar *username = json_object_get_string_member(user, "username");
				const gchar *discriminator = json_object_get_string_member(user, "discriminator");
				
				users = g_list_prepend(users, discord_combine_username(username, discriminator));
				flags = g_list_prepend(flags, GINT_TO_POINTER(PURPLE_CHAT_USER_NONE));
			}
		}
	
		purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);
		
		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}
		
		g_list_free(users);
		g_list_free(flags);
	}
	
	g_list_free(lookup->allowed_roles);
	g_list_free(lookup->denied_roles);
	g_free(lookup->channel_id);
	g_free(lookup);
}

static void discord_join_chat(PurpleConnection *pc, GHashTable *chatdata);


static void
discord_got_channel_info(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *channel = json_node_get_object(node);
	const gchar *id = json_object_get_string_member(channel, "id");
	//gint64 channel_type = json_object_get_int_member(channel, "type");
	
	PurpleChatConversation *chatconv;
	
	if (id == NULL) {
		// No permissions?  Should be an error message in json_object_get_string_member(channel, "message")
		return;
	}
	
	chatconv = purple_conversations_find_chat(da->pc, g_str_hash(id));
	
	if (chatconv == NULL) {
		return;
	}
	
	if (json_object_has_member(channel, "topic")) {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "topic"));
	} else {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "name"));
	}
	
	if (json_object_has_member(channel, "recipients")) {
		GString *recipient_names = g_string_new(NULL);
		JsonArray *recipients = json_object_get_array_member(channel, "recipients");
		gint i;
		guint len = json_array_get_length(recipients);
		GList *users = NULL, *flags = NULL;
		
		for (i = len - 1; i >= 0; i--) {
			JsonObject *recipient = json_array_get_object_element(recipients, i);
			const gchar *username = json_object_get_string_member(recipient, "username");
			const gchar *discriminator = json_object_get_string_member(recipient, "discriminator");
			
			users = g_list_prepend(users, discord_combine_username(username, discriminator));
			flags = g_list_prepend(flags, GINT_TO_POINTER(PURPLE_CHAT_USER_NONE));
			
			g_string_append_printf(recipient_names, ", %s", username);
		}
	
		purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);
		
		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}
		
		g_list_free(users);
		g_list_free(flags);
		
		purple_conversation_set_title(PURPLE_CONVERSATION(chatconv), recipient_names->str);
		g_string_free(recipient_names, TRUE);
	} else if (json_object_has_member(channel, "permission_overwrites")) {
		DiscordChannelPermissionLookup *lookup = g_new0(DiscordChannelPermissionLookup, 1);
		// assume default permission is to view rooms
		// look through allow and deny roles for 0x400 - READ_MESSAGES
		
		JsonArray *permissions = json_object_get_array_member(channel, "permission_overwrites");
		gint i;
		guint len = json_array_get_length(permissions);
		gchar *url;
		
		for (i = len - 1; i >= 0; i--) {
			JsonObject *role = json_array_get_object_element(permissions, i);
			const gchar *role_id = json_object_get_string_member(role, "id");
			if (json_object_get_int_member(role, "allow") & 0x400) {
				lookup->allowed_roles = g_list_prepend(lookup->allowed_roles, g_strdup(role_id));
			}
			if (json_object_get_int_member(role, "deny") & 0x400) {
				lookup->denied_roles = g_list_prepend(lookup->denied_roles, g_strdup(role_id));
			}
		}
		
		lookup->da = da;
		lookup->channel_id = g_strdup(id);
		
		url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/guilds/%s/members?limit=1000", purple_url_encode(json_object_get_string_member(channel, "guild_id")));
		discord_fetch_url(da, url, NULL, discord_got_users_of_room, lookup);
		g_free(url);
	}
	
}

static void
discord_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *id;
	gchar *name;
	PurpleChatConversation *chatconv = NULL;
	gchar *url;
	
	id = (gchar *) g_hash_table_lookup(chatdata, "id");
	name = (gchar *) g_hash_table_lookup(chatdata, "name");
	
	if (id == NULL && name == NULL) {
		//What do?
		return;
	}
	
	if (id == NULL) {
		id = g_hash_table_lookup(da->group_chats_rev, name);
	}
	if (name == NULL) {
		name = g_hash_table_lookup(da->group_chats, id);
	}
	
	//TODO use the api look up name info from the id
	if (id == NULL) {
		return;
	}
	
	if (name != NULL) {
		chatconv = purple_conversations_find_chat_with_account(name, da->account);
	}
	if (chatconv == NULL) {
		chatconv = purple_conversations_find_chat_with_account(id, da->account);
	}
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}
	
	chatconv = purple_serv_got_joined_chat(pc, g_str_hash(id), name ? name : id);
	if (id != NULL) {
		purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(id));
	}
	
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));
	
	if (!g_hash_table_contains(da->group_chats, id)) {
		g_hash_table_replace(da->group_chats, g_strdup(id), name ? g_strdup(name) : NULL);
	}
	if (name != NULL && !g_hash_table_contains(da->group_chats_rev, name)) {
		g_hash_table_replace(da->group_chats_rev, g_strdup(name), id ? g_strdup(id) : NULL);
	}
	
	// Get info about the channel
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%s", purple_url_encode(id));
	discord_fetch_url(da, url, NULL, discord_got_channel_info, NULL);
	g_free(url);
	
}

static void
discord_mark_room_messages_read(DiscordAccount *ya, const gchar *room_id)
{
	/*JsonObject *data;
	JsonArray *params;
	
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "readMessages");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", discord_get_next_id_str(ya));
	
	discord_socket_write_json(ya, data);*/
}

static void
discord_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
	PurpleConnection *pc;
	DiscordAccount *ya;
	const gchar *room_id;
	
	if (type != PURPLE_CONVERSATION_UPDATE_UNSEEN)
		return;
	
	pc = purple_conversation_get_connection(conv);
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return;
	
	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), DISCORD_PLUGIN_ID))
		return;
	
	ya = purple_connection_get_protocol_data(pc);
	
	room_id = purple_conversation_get_data(conv, "id");
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
			}
		}
	}
	g_return_if_fail(room_id != NULL);
	
	discord_mark_room_messages_read(ya, room_id);
}

static guint
discord_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, DiscordAccount *ya)
{
	PurpleConnection *pc;
	const gchar *room_id;
	gchar *url;
	
	if(state != PURPLE_IM_TYPING)
		return 0;
	
	pc = ya ? ya->pc : purple_conversation_get_connection(conv);
	
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return 0;
	
	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), DISCORD_PLUGIN_ID))
		return 0;
	
	if (ya == NULL) {
		ya = purple_connection_get_protocol_data(pc);
	}
	
	room_id = purple_conversation_get_data(conv, "id");
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
			}
		}
	}
	g_return_val_if_fail(room_id, -1); //TODO create new conversation for this new person
	
	
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%s/typing", purple_url_encode(room_id));
	discord_fetch_url(ya, url, "", NULL, NULL);
	g_free(url);
	
	return 10;
}

static guint
discord_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
	PurpleConversation *conv;
	
	conv = PURPLE_CONVERSATION(purple_conversations_find_im_with_account(who, purple_connection_get_account(pc)));
	g_return_val_if_fail(conv, -1);
	
	return discord_conv_send_typing(conv, state, NULL);
}

static gint
discord_conversation_send_message(DiscordAccount *da, const gchar *room_id, const gchar *message)
{
	JsonObject *data = json_object_new();
	gchar *url;
	gchar *postdata;
	gchar *nonce;
	gchar *stripped;
	
	nonce = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());
	g_hash_table_insert(da->sent_message_ids, nonce, nonce);
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	
	json_object_set_string_member(data, "content", stripped);
	json_object_set_string_member(data, "nonce", nonce);
	json_object_set_boolean_member(data, "tts", FALSE);
	
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%s/messages", purple_url_encode(room_id));
	postdata = json_object_to_string(data);
	
	discord_fetch_url(da, url, postdata, NULL, NULL);
	
	g_free(stripped);
	g_free(url);
	g_free(postdata);
	json_object_unref(data);
	
	return 1;
}

static gint
discord_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	DiscordAccount *da;
	const gchar *room_id;
	PurpleChatConversation *chatconv;
	gint ret;
	
	da = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (!room_id) {
		// Fix for a race condition around the chat data and serv_got_joined_chat()
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		if (g_hash_table_lookup(da->group_chats_rev, room_id)) {
			// Convert friendly name into id
			room_id = g_hash_table_lookup(da->group_chats_rev, room_id);
		}
		g_return_val_if_fail(room_id, -1);
	}
	g_return_val_if_fail(g_hash_table_contains(da->group_chats, room_id), -1); //TODO rejoin room?
	
	ret = discord_conversation_send_message(da, room_id, message);
	if (ret > 0) {
		purple_serv_got_chat_in(pc, g_str_hash(room_id), da->self_username, PURPLE_MESSAGE_SEND, message, time(NULL));
	}
	
	return ret;
}


static void
discord_created_direct_message_send(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	PurpleMessage *msg = user_data;
	JsonObject *result;
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message;
	const gchar *room_id;
	PurpleBuddy *buddy;
	
	if (node == NULL) {
		purple_conversation_present_error(who, da->account, _("Could not create conversation"));
		purple_message_destroy(msg);
		return;
	}
	result = json_node_get_object(node);
	message = purple_message_get_contents(msg);
	room_id = json_object_get_string_member(result, "id");
	buddy = purple_blist_find_buddy(da->account, who);
	
	if (room_id != NULL && who != NULL) {
		g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(who));
		g_hash_table_replace(da->one_to_ones_rev, g_strdup(who), g_strdup(room_id));
	}
	
	if (buddy != NULL) {
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", room_id);
	}
	
	discord_conversation_send_message(da, room_id, message);
}

static int
discord_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *room_id = g_hash_table_lookup(da->one_to_ones_rev, who);
	
	//Create DM if there isn't one
	if (room_id == NULL) {
		JsonObject *data;
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
		const gchar *user_id = g_hash_table_lookup(da->usernames_to_ids, who);
		gchar *postdata;

		if (user_id != NULL) {
			data = json_object_new();
			json_object_set_string_member(data, "recipient_id", user_id);
			
			postdata = json_object_to_string(data);
			
			discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/users/@me/channels", postdata, discord_created_direct_message_send, msg);
			
			g_free(postdata);
			json_object_unref(data);
			
			return 1;
		} else { 
			return -1;
		}
	}
	
	return discord_conversation_send_message(da, room_id, message);
}


static void
discord_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{	
	//PATCH https:// DISCORD_API_SERVER /api/v6/channels/%s channel
	//{"name":"test","position":1,"topic":"new topic","bitrate":64000,"user_limit":0}
}

typedef struct {
	gchar *username;
	gchar *avatar_id;
} DiscordBuddyAvatar;

static void
discord_got_avatar(DiscordAccount *ya, JsonNode *node, gpointer user_data)
{
	DiscordBuddyAvatar *dba = user_data;
	
	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;
		
		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup(response_str, response_len);
		
		purple_buddy_icons_set_for_user(ya->account, dba->username, response_dup, response_len, dba->avatar_id);
	}
	
	g_free(dba->username);
	g_free(dba->avatar_id);
	g_free(dba);
}

static void
discord_get_avatar(DiscordAccount *da, const gchar *user_id, const gchar *avatar_id)
{
	DiscordBuddyAvatar *dba;
	GString *url;
	const gchar *checksum;
	const gchar *username;

	if (!user_id || !avatar_id || !*user_id || !*avatar_id) {
		return;
	}

	username = g_hash_table_lookup(da->ids_to_usernames, user_id);
	if (username == NULL) {
		return;
	}
	
	checksum = purple_buddy_icons_get_checksum_for_user(purple_blist_find_buddy(da->account, username));
	if (purple_strequal(checksum, avatar_id)) {
		return;
	}
	
	dba = g_new0(DiscordBuddyAvatar, 1);
	dba->username = g_strdup(username);
	dba->avatar_id = g_strdup(avatar_id);
	
	url = g_string_new("https://cdn.discordapp.com/avatars/");
	g_string_append_printf(url, "%s", purple_url_encode(user_id));
	g_string_append_c(url, '/');
	g_string_append_printf(url, "%s", purple_url_encode(avatar_id));
	
	discord_fetch_url(da, url->str, NULL, discord_got_avatar, dba);
	
	g_string_free(url, TRUE);
}

static void
discord_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
, const char *message
#endif
)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	JsonObject *data;
	gchar *postdata;
	gchar **usersplit;
	
	if (!strchr(buddy_name, '#')) {
		purple_blist_remove_buddy(buddy); 
		return;
	}
	
	usersplit = g_strsplit_set(buddy_name, "#", 2);
	data = json_object_new();
	json_object_set_string_member(data, "username", usersplit[0]);
	json_object_set_string_member(data, "discriminator", usersplit[1]);
	
	postdata = json_object_to_string(data);
	
	discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships", postdata, NULL, NULL);
	
	g_free(postdata);
	g_strfreev(usersplit);
	json_object_unref(data);
}

static void
discord_buddy_remove(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	gchar *url;
	const gchar *user_id = g_hash_table_lookup(da->usernames_to_ids, buddy_name);
	
	if (!user_id) {
		return;
	}
	
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%s", user_id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);
}

static void
discord_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	// Do nothing to stop the remove+add behaviour
}

static void
discord_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	// Do nothing to stop the remove+add behaviour
}


static const char *
discord_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "discord";
}

static GList *
discord_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	// We can only set statuses without in-game info
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "set-online", "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "set-idle", "Away", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "set-offline", "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	// Other people can have an in-game display
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, FALSE, FALSE, "message", "In-Game", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "idle", "Away", TRUE, FALSE, FALSE, "message", "In-Game", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline", "Offline", TRUE, FALSE, FALSE, "message", "In-Game", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	return types;
}

static gchar *
discord_status_text(PurpleBuddy *buddy)
{
	const gchar *message = purple_status_get_attr_string(purple_presence_get_active_status(purple_buddy_get_presence(buddy)), "message");
	
	if (message == NULL) {
		return NULL;
	}
	
	return g_markup_printf_escaped(_("Playing %s"), message);
}

const gchar *
discord_list_emblem(PurpleBuddy *buddy)
{
	const gchar *message = purple_status_get_attr_string(purple_presence_get_active_status(purple_buddy_get_presence(buddy)), "message");
	
	if (message != NULL) {
		return "game";
	}
	
	return NULL;
	
	//TODO bot
}

static GHashTable *
discord_get_account_text_table(PurpleAccount *unused)
{
	GHashTable *table;

	table = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(table, "login_label", (gpointer)_("Email address..."));

	return table;
}

static GList *
discord_add_account_options(GList *account_options)
{
	//PurpleAccountOption *option;
	
	//option = purple_account_option_bool_new(N_("Auto-add buddies to the buddy list"), "auto-add-buddy", FALSE);
	//account_options = g_list_append(account_options, option);
	
	return account_options;
}

void
discord_join_server_text(gpointer user_data, const gchar *text)
{
	DiscordAccount *da = user_data;
	gchar *url;
	const gchar *invite_code;
	
	invite_code = strrchr(text, '/');
	if (invite_code == NULL) {
		invite_code = text;
	}
	
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/invite/%s", purple_url_encode(invite_code));
	
	discord_fetch_url(da, url, "", NULL, NULL);
	
	g_free(url);
}

void
discord_join_server(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	
	purple_request_input(pc, _("Join a server"),
					   _("Join a server"),
					   _("Enter the join URL here"),
					   NULL, FALSE, FALSE, "https://discord.gg/ABC123",
					   _("_Search"), G_CALLBACK(discord_join_server_text),
					   _("_Cancel"), NULL,
					   purple_request_cpar_from_connection(pc),
					   da);

}

static GList *
discord_actions(
#if !PURPLE_VERSION_CHECK(3, 0, 0)
PurplePlugin *plugin, gpointer context
#else
PurpleConnection *pc
#endif
)
{
	GList *m = NULL;
	PurpleProtocolAction *act;

	act = purple_protocol_action_new(_("Join a server..."), discord_join_server);
	m = g_list_append(m, act);

	return m;
}

static PurpleCmdRet
discord_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	discord_chat_leave(pc, id);
	
	return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	
	channel_mentions_regex = g_regex_new("&lt;#(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	
	// purple_cmd_register("create", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("create <name>:  Create a new channel"), NULL);
						
	// purple_cmd_register("invite", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("invite <username>:  Invite user to join channel"), NULL);
						
	// purple_cmd_register("join", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("join <name>:  Join a channel"), NULL);
						
	// purple_cmd_register("kick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("kick <username>:  Remove someone from channel"), NULL);
	
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_leave,
						_("leave:  Leave the channel"), NULL);
	
	purple_cmd_register("part", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_leave,
						_("part:  Leave the channel"), NULL);
	
	// purple_cmd_register("me", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("me <action>:  Display action text"), NULL);
	
	// purple_cmd_register("msg", "ss", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("msg <username> <message>:  Direct message someone"), NULL);
	
	// purple_cmd_register("mute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("mute <username>:  Mute someone in channel"), NULL);
	
	// purple_cmd_register("unmute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("unmute <username>:  Un-mute someone in channel"), NULL);
	
	// purple_cmd_register("topic", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						// PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						// DISCORD_PLUGIN_ID, discord_slash_command,
						// _("topic <description>:  Set the channel topic description"), NULL);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);
	
	g_regex_unref(channel_mentions_regex);
	
	return TRUE;
}

// Purple2 Plugin Load Functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	// PurpleAccountOption *option;
	// PurplePluginInfo *info = plugin->info;
	// PurplePluginProtocolInfo *prpl_info = info->extra_info;
	//purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(discord_uri_handler), NULL);
	
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	
	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		//prpl_info->add_buddy_with_invite = discord_add_buddy_with_invite;
	#endif
	
	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	prpl_info->protocol_options = discord_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;
	
	prpl_info->get_account_text_table = discord_get_account_text_table;
	prpl_info->list_emblem = discord_list_emblem;
	prpl_info->status_text = discord_status_text;
	prpl_info->list_icon = discord_list_icon;
	prpl_info->set_status = discord_set_status;
	prpl_info->set_idle = discord_set_idle;
	prpl_info->status_types = discord_status_types;
	prpl_info->chat_info = discord_chat_info;
	prpl_info->chat_info_defaults = discord_chat_info_defaults;
	prpl_info->login = discord_login;
	prpl_info->close = discord_close;
	prpl_info->send_im = discord_send_im;
	prpl_info->send_typing = discord_send_typing;
	prpl_info->join_chat = discord_join_chat;
	prpl_info->get_chat_name = discord_get_chat_name;
	prpl_info->chat_invite = discord_chat_invite;
	prpl_info->chat_send = discord_chat_send;
	prpl_info->set_chat_topic = discord_chat_set_topic;
	prpl_info->add_buddy = discord_add_buddy;
	prpl_info->remove_buddy = discord_buddy_remove;
	prpl_info->group_buddy = discord_fake_group_buddy;
	prpl_info->rename_group = discord_fake_group_rename;
	
	prpl_info->roomlist_get_list = discord_roomlist_get_list;
	prpl_info->roomlist_room_serialize = discord_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,   // type
	NULL,                     // ui_requirement
	0,                        // flags
	NULL,                     // dependencies
	PURPLE_PRIORITY_DEFAULT,  // priority
	DISCORD_PLUGIN_ID,        // id
	"Discord",                // name
	DISCORD_PLUGIN_VERSION,   // version
	"",                       // summary
	"",                       // description
	"Eion Robb <eion@robbmob.com>", // author
	DISCORD_PLUGIN_WEBSITE,   // homepage
	libpurple2_plugin_load,   // load
	libpurple2_plugin_unload, // unload
	NULL,                     // destroy
	NULL,                     // ui_info
	NULL,                     // extra_info
	NULL,                     // prefs_info
	discord_actions,          // actions
	NULL,                     // padding
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(discord, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType discord_protocol_get_type(void);
#define DISCORD_TYPE_PROTOCOL			(discord_protocol_get_type())
#define DISCORD_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), DISCORD_TYPE_PROTOCOL, DiscordProtocol))
#define DISCORD_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), DISCORD_TYPE_PROTOCOL, DiscordProtocolClass))
#define DISCORD_IS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), DISCORD_TYPE_PROTOCOL))
#define DISCORD_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), DISCORD_TYPE_PROTOCOL))
#define DISCORD_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), DISCORD_TYPE_PROTOCOL, DiscordProtocolClass))

typedef struct _DiscordProtocol
{
	PurpleProtocol parent;
} DiscordProtocol;

typedef struct _DiscordProtocolClass
{
	PurpleProtocolClass parent_class;
} DiscordProtocolClass;

static void
discord_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = DISCORD_PLUGIN_ID;
	info->name = "Discord";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	info->account_options = discord_add_account_options(info->account_options);
}

static void
discord_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = discord_login;
	prpl_info->close = discord_close;
	prpl_info->status_types = discord_status_types;
	prpl_info->list_icon = discord_list_icon;
}

static void 
discord_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = discord_send_im;
	prpl_info->send_typing = discord_send_typing;
}

static void 
discord_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = discord_chat_send;
	prpl_info->info = discord_chat_info;
	prpl_info->info_defaults = discord_chat_info_defaults;
	prpl_info->join = discord_join_chat;
	prpl_info->get_name = discord_get_chat_name;
	prpl_info->invite = discord_chat_invite;
	prpl_info->set_topic = discord_chat_set_topic;
}

static void 
discord_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = discord_add_buddy;
	prpl_info->remove_buddy = discord_buddy_remove;
	prpl_info->set_status = discord_set_status;
	prpl_info->set_idle = discord_set_idle;
	prpl_info->group_buddy = discord_fake_group_buddy;
	prpl_info->rename_group = discord_fake_group_rename;
}

static void 
discord_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_account_text_table = discord_get_account_text_table;
	prpl_info->status_text = discord_status_text;
	prpl_info->get_actions = discord_actions;
	prpl_info->list_emblem = discord_list_emblem;
}

static void 
discord_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	prpl_info->get_list = discord_roomlist_get_list;
	prpl_info->room_serialize = discord_roomlist_serialize;
}

static PurpleProtocol *discord_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	DiscordProtocol, discord_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  discord_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  discord_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  discord_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  discord_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  discord_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	discord_protocol_register_type(plugin);
	discord_protocol = purple_protocols_add(DISCORD_TYPE_PROTOCOL, error);
	if (!discord_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(discord_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          DISCORD_PLUGIN_ID,
		"name",        "Discord",
		"version",     DISCORD_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Discord Protocol Plugins."),
		"description", N_("Adds Discord protocol support to libpurple."),
		"website",     DISCORD_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(discord, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
