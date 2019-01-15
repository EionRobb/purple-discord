/*
 *   Discord plugin for libpurple
 *   Copyright (C) 2016  Eion Robb
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
#include <unistd.h>
#endif
#include <errno.h>

#include <zlib.h>
#ifndef z_const
#	define z_const
#endif

#ifdef ENABLE_NLS
#      define GETTEXT_PACKAGE "purple-discord"
#      include <glib/gi18n-lib.h>
#	ifdef _WIN32
#		ifdef LOCALEDIR
#			unset LOCALEDIR
#		endif
#		define LOCALEDIR  wpurple_locale_dir()
#	endif
#else
#      define _(a) (a)
#      define N_(a) (a)
#endif

#include "glib_compat.h"
#include "json_compat.h"
#include "purple_compat.h"

#include "markdown.h"

#define DISCORD_PLUGIN_ID "prpl-eionrobb-discord"
#ifndef DISCORD_PLUGIN_VERSION
#define DISCORD_PLUGIN_VERSION "0.1"
#endif
#define DISCORD_PLUGIN_WEBSITE "https://github.com/EionRobb/discord-libpurple"

#define DISCORD_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define DISCORD_BUFFER_DEFAULT_SIZE 40960

#define DISCORD_API_SERVER "discordapp.com"
#define DISCORD_GATEWAY_SERVER "gateway.discord.gg"
#define DISCORD_GATEWAY_PORT 443
#define DISCORD_GATEWAY_SERVER_PATH "/?encoding=json&v=6"

#define DISCORD_MESSAGE_NORMAL (0)
#define DISCORD_MESSAGE_EDITED (1)
#define DISCORD_MESSAGE_PINNED (2)

#define IGNORE_PRINTS

static GRegex *channel_mentions_regex = NULL;
static GRegex *role_mentions_regex = NULL;
static GRegex *emoji_regex = NULL;
static GRegex *emoji_natural_regex = NULL;
static GRegex *action_star_regex = NULL;
static GRegex *mention_regex = NULL;
static GRegex *natural_mention_regex = NULL;
static GRegex *discord_mention_regex = NULL;

typedef enum {
	USER_ONLINE,
	USER_IDLE,
	USER_OFFLINE,
	USER_DND
} DiscordStatus;

typedef enum {
	CHANNEL_GUILD_TEXT = 0,
	CHANNEL_DM = 1,
	CHANNEL_VOICE = 2,
	CHANNEL_GROUP_DM = 3,
	CHANNEL_GUILD_CATEGORY = 4
} DiscordChannelType;

typedef struct {
	guint64 id;
	gchar *name;
	int color;
	gint64 permissions;
} DiscordGuildRole;

typedef struct {
	guint64 id;
	gint64 deny;
	gint64 allow;
} DiscordPermissionOverride;

typedef struct {
	guint64 id;
	guint64 guild_id;
	gchar *name;
	gchar *topic;
	DiscordChannelType type;
	int position;
	guint64 last_message_id;
	GHashTable *permission_user_overrides;
	GHashTable *permission_role_overrides;
	GList *recipients; /* For group DMs */
} DiscordChannel;

typedef struct {
	guint64 id;
	gchar *name;
	gchar *icon;
	guint64 owner;

	GHashTable *roles;
	GArray *members;		   /* list of member ids */
	GHashTable *nicknames;	 /* id->nick? */
	GHashTable *nicknames_rev; /* reverse */

	GHashTable *channels;
	int afk_timeout;
	const gchar *afk_voice_channel;

	GHashTable *emojis;
} DiscordGuild;

typedef struct {
	guint64 id;
	gchar *nick;
	gchar *joined_at;
	GArray *roles; /* list of ids */
} DiscordGuildMembership;

typedef struct {
	guint64 id;
	gchar *name;
	int discriminator;
	DiscordStatus status;
	gchar *game;
	gchar *avatar;
	GHashTable *guild_memberships;
	gboolean bot;
} DiscordUser;

typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;

	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	guint64 self_user_id;
	gchar *self_username;

	guint64 last_message_id;
	gint64 last_load_last_message_id;

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

	gint64 seq; /* incrementing counter */
	guint heartbeat_timeout;

	GHashTable *one_to_ones;		/* A store of known room_id's -> username's */
	GHashTable *one_to_ones_rev;	/* A store of known usernames's -> room_id's */
	GHashTable *last_message_id_dm; /* A store of known room_id's -> last_message_id's */
	GHashTable *sent_message_ids;   /* A store of message id's that we generated from this instance */
	GHashTable *result_callbacks;   /* Result ID -> Callback function */
	GQueue *received_message_queue; /* A store of the last 10 received message id's for de-dup */

	GHashTable *new_users;
	GHashTable *new_guilds;
	GHashTable *group_dms;			/* A store of known room_id's -> DiscordChannel's */

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;
	gint roomlist_guild_count;
	
	gboolean compress;
	z_stream *zstream;
} DiscordAccount;

typedef struct {
	DiscordAccount *account;
	DiscordGuild *guild;
} DiscordAccountGuild;

static guint64
to_int(const gchar *id)
{
	return id ? g_ascii_strtoull(id, NULL, 10) : 0;
}

static gchar *
from_int(guint64 id)
{
	return g_strdup_printf("%" G_GUINT64_FORMAT, id);
}

/** libpurple requires unique chat id's per conversation.
	we use a hash function to convert the 64bit conversation id
	into a platform-dependent chat id (worst case 32bit).
	previously we used g_int64_hash() from glib, 
	however libpurple requires positive integers */
static gint
discord_chat_hash(guint64 chat_id)
{
	return ABS((gint) chat_id);
}

static void discord_free_guild_membership(gpointer data);
static void discord_free_guild_role(gpointer data);
static void discord_free_channel(gpointer data);
static gboolean discord_permission_is_role(JsonObject *json);

/* creating */

static DiscordUser *
discord_new_user(JsonObject *json)
{
	DiscordUser *user = g_new0(DiscordUser, 1);

	user->id = to_int(json_object_get_string_member(json, "id"));
	user->name = g_strdup(json_object_get_string_member(json, "username"));
	user->discriminator = to_int(json_object_get_string_member(json, "discriminator"));
	user->bot = json_object_get_boolean_member(json, "bot");
	user->avatar = g_strdup(json_object_get_string_member(json, "avatar"));

	user->guild_memberships = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_guild_membership);
	user->status = user->bot ? USER_ONLINE : USER_OFFLINE; /* Is offline the best assumption on a new user? */

	return user;
}

static DiscordGuild *
discord_new_guild(JsonObject *json)
{
	DiscordGuild *guild = g_new0(DiscordGuild, 1);

	guild->id = to_int(json_object_get_string_member(json, "id"));
	guild->name = g_strdup(json_object_get_string_member(json, "name"));
	guild->icon = g_strdup(json_object_get_string_member(json, "icon"));
	guild->owner = to_int(json_object_get_string_member(json, "owner_id"));

	guild->roles = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_guild_role);
	guild->members = g_array_new(TRUE, TRUE, sizeof(guint64));
	guild->nicknames = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	guild->nicknames_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	guild->channels = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_channel);
	guild->afk_timeout = json_object_get_int_member(json, "afk_timeout");
	guild->afk_voice_channel = g_strdup(json_object_get_string_member(json, "afk_channel_id"));

	guild->emojis = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	JsonArray *emojis = json_object_get_array_member(json, "emojis");

	for (int i = json_array_get_length(emojis) - 1; i >= 0; i--) {
		JsonObject *emoji = json_array_get_object_element(emojis, i);

		gchar *id = g_strdup(json_object_get_string_member(emoji, "id"));
		gchar *name = g_strdup(json_object_get_string_member(emoji, "name"));
		g_hash_table_replace(guild->emojis, name, id);
	}

	return guild;
}

static DiscordPermissionOverride *
discord_new_permission_override(JsonObject *json)
{
	DiscordPermissionOverride *permission = g_new0(DiscordPermissionOverride, 1);

	permission->id = to_int(json_object_get_string_member(json, "id"));
	permission->deny = json_object_get_int_member(json, "deny");
	permission->allow = json_object_get_int_member(json, "allow");

	return permission;
}

static DiscordChannel *
discord_new_channel(JsonObject *json)
{
	DiscordChannel *channel = g_new0(DiscordChannel, 1);

	channel->id = to_int(json_object_get_string_member(json, "id"));
	channel->name = g_strdup(json_object_get_string_member(json, "name"));
	channel->topic = g_strdup(json_object_get_string_member(json, "topic"));
	channel->position = json_object_get_int_member(json, "position");
	channel->type = json_object_get_int_member(json, "type");
	channel->last_message_id = to_int(json_object_get_string_member(json, "last_message_id"));

	channel->permission_user_overrides = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	channel->permission_role_overrides = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);

	channel->recipients = NULL;

	return channel;
}

static DiscordGuildMembership *
discord_new_guild_membership(guint64 id, JsonObject *json)
{
	DiscordGuildMembership *guild_membership = g_new0(DiscordGuildMembership, 1);

	guild_membership->id = id;
	guild_membership->nick = g_strdup(json_object_get_string_member(json, "nick"));
	guild_membership->joined_at = g_strdup(json_object_get_string_member(json, "joined_at"));

	guild_membership->roles = g_array_new(TRUE, TRUE, sizeof(guint64));

	return guild_membership;
}

static DiscordGuildRole *
discord_new_guild_role(JsonObject *json)
{
	DiscordGuildRole *guild_role = g_new0(DiscordGuildRole, 1);

	guild_role->id = to_int(json_object_get_string_member(json, "id"));
	guild_role->name = g_strdup(json_object_get_string_member(json, "name"));
	guild_role->color = json_object_get_int_member(json, "color");
	guild_role->permissions = json_object_get_int_member(json, "permissions");

	return guild_role;
}

/* freeing */

static void
discord_free_guild_role(gpointer data)
{
	DiscordGuildRole *guild_role = data;
	g_free(guild_role->name);
	g_free(guild_role);
}

static void
discord_free_guild_membership(gpointer data)
{
	DiscordGuildMembership *guild_membership = data;
	g_free(guild_membership->nick);
	g_free(guild_membership->joined_at);

	g_array_unref(guild_membership->roles);
	g_free(guild_membership);
}

static void
discord_free_user(gpointer data)
{
	DiscordUser *user = data;
	g_free(user->name);
	g_free(user->game);
	g_free(user->avatar);

	g_hash_table_unref(user->guild_memberships);
	g_free(user);
}

static void
discord_free_guild(gpointer data)
{
	DiscordGuild *guild = data;
	g_free(guild->name);
	g_free(guild->icon);

	g_hash_table_unref(guild->roles);
	g_array_unref(guild->members);
	g_hash_table_unref(guild->nicknames);
	g_hash_table_unref(guild->nicknames_rev);
	g_hash_table_unref(guild->channels);
	g_hash_table_unref(guild->emojis);
	g_free(guild);
}

static void
discord_free_channel(gpointer data)
{
	DiscordChannel *channel = data;
	g_free(channel->name);
	g_free(channel->topic);

	g_hash_table_unref(channel->permission_user_overrides);
	g_hash_table_unref(channel->permission_role_overrides);
	g_list_free_full(channel->recipients, g_free);

	g_free(channel);
}

/* updating */

static void
discord_update_status(DiscordUser *user, JsonObject *json)
{
	json_object_get_string_member(json, "id");

	if (json_object_has_member(json, "status")) {
		const gchar *status = json_object_get_string_member(json, "status");

		if (purple_strequal("online", status)) {
			user->status = USER_ONLINE;
		} else if (purple_strequal("idle", status)) {
			user->status = USER_IDLE;
		} else if (purple_strequal("dnd", status)) {
			user->status = USER_DND;
		} else {
			user->status = USER_OFFLINE; /* All else fails probably offline */
		}
	}

	if (json_object_has_member(json, "game")) {
		const gchar *game = json_object_get_string_member(json_object_get_object_member(json, "game"), "name");
		g_free(user->game);
		user->game = g_strdup(game);
	}
}

static DiscordChannel *
discord_add_channel(DiscordGuild *guild, JsonObject *json, guint64 guild_id)
{
	DiscordChannel *channel = discord_new_channel(json);
	channel->guild_id = guild_id;
	g_hash_table_replace_int64(guild->channels, channel->id, channel);
	return channel;
}

static DiscordGuildRole *
discord_add_guild_role(DiscordGuild *guild, JsonObject *json)
{
	DiscordGuildRole *role = discord_new_guild_role(json);
	g_hash_table_replace_int64(guild->roles, role->id, role);
	return role;
}

static DiscordPermissionOverride *
discord_add_permission_override(DiscordChannel *channel, JsonObject *json)
{
	DiscordPermissionOverride *permission_override = discord_new_permission_override(json);
	gboolean is_role = discord_permission_is_role(json);
	GHashTable *overrides = is_role ? channel->permission_role_overrides : channel->permission_user_overrides;
	g_hash_table_replace_int64(overrides, permission_override->id, permission_override);
	return permission_override;
}

/* managing */
static gboolean
discord_permission_is_role(JsonObject *json)
{
	return purple_strequal(json_object_get_string_member(json, "type"), "role");
}

void
discord_dump_int64_hashtable_keys(GHashTable *hash_table)
{
	GHashTableIter iter;
	guint64 *key;
	gpointer value;

	g_hash_table_iter_init(&iter, hash_table);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		purple_debug_info("discord", "%" G_GUINT64_FORMAT, *key);
	}
}

static DiscordUser *
discord_get_user_name(DiscordAccount *da, int discriminator, gchar *name)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, da->new_users);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordUser *user = value;

		if (user->discriminator == discriminator && purple_strequal(user->name, name)) {
			return value;
		}
	}

	return NULL;
}

static DiscordUser *
discord_get_user_fullname(DiscordAccount *da, const gchar *name)
{
	g_return_val_if_fail(name && *name, NULL);
	
	gchar **split_name = g_strsplit(name, "#", 2);
	DiscordUser *user = NULL;
	
	if (split_name != NULL) {
		if (split_name[0] && split_name[1]) {
			user = discord_get_user_name(da, to_int(split_name[1]), split_name[0]);
		}
		
		g_strfreev(split_name);
	}
	
	return user;
}
static DiscordUser *
discord_get_user(DiscordAccount *da, guint64 id)
{
	return g_hash_table_lookup_int64(da->new_users, id);
}

static DiscordUser *
discord_upsert_user(GHashTable *user_table, JsonObject *json)
{
	guint64 *key = NULL, user_id = to_int(json_object_get_string_member(json, "id"));
	DiscordUser *user = NULL;

	if (g_hash_table_lookup_extended_int64(user_table, user_id, (gpointer) &key, (gpointer) &user)) {
		return user;
	} else {
		user = discord_new_user(json);
		g_hash_table_replace_int64(user_table, user->id, user);
		return user;
	}
}

static gchar *
discord_create_fullname(DiscordUser *user)
{
	g_return_val_if_fail(user != NULL, NULL);
	
	return g_strdup_printf("%s#%04d", user->name, user->discriminator);
}

static gchar *
discord_create_fullname_from_id(DiscordAccount *da, guint64 id)
{
	DiscordUser *user = discord_get_user(da, id);

	if (user) {
		return discord_create_fullname(user);
	}

	return NULL;
}

static gchar *discord_create_nickname(DiscordUser *author, DiscordGuild *guild);

static gchar *
discord_alloc_nickname(DiscordUser *user, DiscordGuild *guild, const gchar *suggested_nick)
{
	const gchar *base_nick = suggested_nick ? suggested_nick : user->name;
	gchar *nick = NULL;

	if (base_nick == NULL) {
		return NULL;
	}

	DiscordUser *existing = g_hash_table_lookup(guild->nicknames_rev, base_nick);
	
	if (existing && existing->id != user->id) {
		/* Ambiguous; try with the discriminator */

		nick = g_strdup_printf("%s#%04d", base_nick, user->discriminator);

		existing = g_hash_table_lookup(guild->nicknames_rev, nick);

		if (existing && existing->id != user->id) {
			/* Ambiguous; use the full tag */

			g_free(nick);
			nick = g_strdup_printf("%s (%s#%04d)", base_nick, user->name, user->discriminator);
		}
	}
	
	if (!nick) {
		nick = g_strdup(base_nick);
	}

	g_hash_table_replace_int64(guild->nicknames, user->id, g_strdup(nick));
	g_hash_table_replace(guild->nicknames_rev, g_strdup(nick), g_memdup(&user->id, sizeof(user->id)));

	return nick;
}

static gchar *
discord_create_nickname_from_id(DiscordAccount *da, DiscordGuild *g, guint64 id)
{
	DiscordUser *user = discord_get_user(da, id);

	if (user) {
		return discord_create_nickname(user, g);
	}

	return NULL;
}

static DiscordGuild *
discord_get_guild(DiscordAccount *da, guint64 id)
{
	return g_hash_table_lookup_int64(da->new_guilds, id);
}

static DiscordGuild *
discord_upsert_guild(GHashTable *guild_table, JsonObject *json)
{
	guint64 *key = NULL, guild_id = to_int(json_object_get_string_member(json, "id"));
	DiscordGuild *guild = NULL;

	if (g_hash_table_lookup_extended_int64(guild_table, guild_id, (gpointer) &key, (gpointer) &guild)) {
		return guild;
	} else {
		guild = discord_new_guild(json);
		g_hash_table_replace_int64(guild_table, guild->id, guild);
		return guild;
	}
}

static DiscordChannel *
discord_get_channel_global_int_guild(DiscordAccount *da, guint64 id, DiscordGuild **o_guild)
{
	/* Check for group DM first to avoid iterating guilds */
	DiscordChannel *group_dm = g_hash_table_lookup_int64(da->group_dms, id);
	if(group_dm) return group_dm;

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordGuild *guild = value;

		if (!guild) {
			continue;
		}

		DiscordChannel *channel = g_hash_table_lookup_int64(guild->channels, id);

		if (channel) {
			if (o_guild) {
				*o_guild = guild;
			}

			return channel;
		}
	}

	return NULL;
}

static DiscordChannel *
discord_get_channel_global_int(DiscordAccount *da, guint64 id)
{
	return discord_get_channel_global_int_guild(da, id, NULL);
}

static DiscordChannel *
discord_get_channel_global_name(DiscordAccount *da, const gchar *name)
{
	GHashTableIter guild_iter, channel_iter;
	gpointer key, value;

	g_hash_table_iter_init(&guild_iter, da->new_guilds);

	while (g_hash_table_iter_next(&guild_iter, &key, &value)) {
		DiscordGuild *guild = value;
		g_hash_table_iter_init(&channel_iter, guild->channels);

		while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
			DiscordChannel *channel = value;

			if (purple_strequal(name, channel->name)) {
				return channel;
			}
		}
	}

	return NULL;
}

static DiscordChannel *
discord_get_channel_global(DiscordAccount *da, const gchar *id)
{
	return discord_get_channel_global_int(da, to_int(id));
}
/* debug */

#define discord_print_append(L, B, R, M, D) \
	g_string_printf((R), (M), (D));         \
	discord_print_append_row((L), (B), (R));

#ifndef IGNORE_PRINTS
static void
discord_print_append_row(int level, GString *buffer, GString *row)
{
	for (int i = 0; i < level; i++) {
		g_string_prepend_c(row, '\t');
	}

	g_string_append(buffer, row->str);
	g_string_append_c(buffer, '\n');
}

static void
discord_print_permission_override(GString *buffer, GHashTable *permission_overrides, const gchar *type)
{
	GHashTableIter permission_override_iter;
	GString *row_buffer = g_string_new("");
	gpointer key, value;

	type = purple_strequal("role", type) ? "Role override count: %d" : "User override count: %d";
	discord_print_append(2, buffer, row_buffer, type, g_hash_table_size(permission_overrides));
	g_hash_table_iter_init(&permission_override_iter, permission_overrides);

	while (g_hash_table_iter_next(&permission_override_iter, &key, &value)) {
		DiscordPermissionOverride *permission_override = value;

		discord_print_append(3, buffer, row_buffer, "Override id: %" G_GUINT64_FORMAT, permission_override->id);
		discord_print_append(4, buffer, row_buffer, "Allow: %" G_GUINT64_FORMAT, permission_override->allow);
		discord_print_append(4, buffer, row_buffer, "Deny: %" G_GUINT64_FORMAT, permission_override->deny);
	}
}
#endif

static void
discord_print_guilds(GHashTable *guilds)
{
#ifdef IGNORE_PRINTS
	return;
#else
	GString *buffer = g_string_new("\n");
	GString *row_buffer = g_string_new("");
	GHashTableIter guild_iter, channel_iter, role_iter;
	gpointer key, value;

	g_hash_table_iter_init(&guild_iter, guilds);

	while (g_hash_table_iter_next(&guild_iter, &key, &value)) {
		DiscordGuild *guild = value;

		discord_print_append(0, buffer, row_buffer, "Guild id: %" G_GUINT64_FORMAT, guild->id);
		discord_print_append(1, buffer, row_buffer, "Name: %s", guild->name);
		discord_print_append(1, buffer, row_buffer, "Icon: %s", guild->icon);
		discord_print_append(1, buffer, row_buffer, "Owner: %" G_GUINT64_FORMAT, guild->owner);
		discord_print_append(1, buffer, row_buffer, "Afk timeout: %d", guild->afk_timeout);
		discord_print_append(1, buffer, row_buffer, "Afk channel: %s", guild->afk_voice_channel);

		g_hash_table_iter_init(&role_iter, guild->roles);

		while (g_hash_table_iter_next(&role_iter, &key, &value)) {
			DiscordGuildRole *role = value;
			discord_print_append(1, buffer, row_buffer, "Role id: %" G_GUINT64_FORMAT, role->id);
			discord_print_append(2, buffer, row_buffer, "Name: %s", role->name);
			discord_print_append(2, buffer, row_buffer, "Color: %d", role->color);
			discord_print_append(2, buffer, row_buffer, "Permissions: %" G_GUINT64_FORMAT, role->permissions);
		}

		discord_print_append(1, buffer, row_buffer, "Member count: %d", guild->members->len);

		for (guint i = 0; i < guild->members->len; i++) {
			guint64 member_id = g_array_index(guild->members, guint64, i);
			discord_print_append(3, buffer, row_buffer, "Member id: %" G_GUINT64_FORMAT, member_id);
		}

		g_hash_table_iter_init(&channel_iter, guild->channels);

		while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
			DiscordChannel *channel = value;

			discord_print_append(1, buffer, row_buffer, "Channel id: %" G_GUINT64_FORMAT, channel->id);
			discord_print_append(2, buffer, row_buffer, "Name: %s", channel->name);
			discord_print_append(2, buffer, row_buffer, "Topic: %s", channel->topic);
			discord_print_append(2, buffer, row_buffer, "Type: %d", channel->type);
			discord_print_append(2, buffer, row_buffer, "Position: %d", channel->position);
			discord_print_append(2, buffer, row_buffer, "Last message: %" G_GUINT64_FORMAT, channel->last_message_id);

			discord_print_permission_override(buffer, channel->permission_role_overrides, "Role");
			discord_print_permission_override(buffer, channel->permission_user_overrides, "User");
		}
	}

	purple_debug_info("discord", "%s", buffer->str);
	g_string_free(buffer, TRUE);
	g_string_free(row_buffer, TRUE);
#endif
}

static void
discord_print_users(GHashTable *users)
{
#ifdef IGNORE_PRINTS
	return;
#else
	GString *buffer = g_string_new("\n");
	GString *row_buffer = g_string_new("");
	GHashTableIter user_iter, guild_membership_iter;
	gpointer key, value;

	g_hash_table_iter_init(&user_iter, users);

	while (g_hash_table_iter_next(&user_iter, &key, &value)) {
		DiscordUser *user = value;

		discord_print_append(0, buffer, row_buffer, "User id: %" G_GUINT64_FORMAT, user->id);
		discord_print_append(1, buffer, row_buffer, "Name: %s", user->name);
		discord_print_append(1, buffer, row_buffer, "Discriminator: %d", user->discriminator);
		discord_print_append(1, buffer, row_buffer, "Game: %s", user->game);
		discord_print_append(1, buffer, row_buffer, "Avatar: %s", user->avatar);
		discord_print_append(1, buffer, row_buffer, "Status: %d", user->status);

		g_hash_table_iter_init(&guild_membership_iter, user->guild_memberships);

		while (g_hash_table_iter_next(&guild_membership_iter, &key, &value)) {
			DiscordGuildMembership *guild_membership = value;

			discord_print_append(1, buffer, row_buffer, "Guild membership id: %" G_GUINT64_FORMAT, guild_membership->id);
			discord_print_append(2, buffer, row_buffer, "Nick: %s", guild_membership->nick);
			discord_print_append(2, buffer, row_buffer, "Joined at: %s", guild_membership->joined_at);
			discord_print_append(2, buffer, row_buffer, "Role count: %d", guild_membership->roles->len);

			for (guint i = 0; i < guild_membership->roles->len; i++) {
				guint64 role_id = g_array_index(guild_membership->roles, guint64, i);
				discord_print_append(3, buffer, row_buffer, "Role id: %" G_GUINT64_FORMAT, role_id);
			}
		}
	}

	purple_debug_info("discord", "%s", buffer->str);

	g_string_free(buffer, TRUE);
	g_string_free(row_buffer, TRUE);
#endif
}

PurpleChatUserFlags
discord_get_user_flags(DiscordAccount *da, DiscordGuild *guild, DiscordUser *user)
{
	if (user == NULL) {
		return PURPLE_CHAT_USER_NONE;
	}

	guint64 gid = guild->id;
	DiscordGuildMembership *guild_membership = g_hash_table_lookup_int64(user->guild_memberships, gid);
	PurpleChatUserFlags best_flag = user->bot ? PURPLE_CHAT_USER_VOICE : PURPLE_CHAT_USER_NONE;

	if (guild_membership == NULL) {
		return best_flag;
	}

	for (guint i = 0; i < guild_membership->roles->len; i++) {
		guint64 role_id = g_array_index(guild_membership->roles, guint64, i);
		DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, role_id);
		PurpleChatUserFlags this_flag = PURPLE_CHAT_USER_NONE;

		if (role != NULL) {
			if (role->permissions & 0x8) { /* Admin */
				this_flag = PURPLE_CHAT_USER_OP;
			} else if (role->permissions & (0x2 | 0x4)) { /* Ban/kick */
				this_flag = PURPLE_CHAT_USER_HALFOP;
			}
		}

		if (this_flag > best_flag) {
			best_flag = this_flag;
		}
	}

	return best_flag;
}

typedef void (*DiscordProxyCallbackFunc)(DiscordAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	DiscordAccount *ya;
	DiscordProxyCallbackFunc callback;
	gpointer user_data;
} DiscordProxyConnection;

static gchar *
discord_combine_username(const gchar *username, const gchar *discriminator)
{
	g_return_val_if_fail(username != NULL, NULL);
	
	if (discriminator == NULL) {
		discriminator = "0000";
	}
	
	return g_strconcat(username, "#", discriminator, NULL);
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

	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur)) {
		cookie_start = cur->data;

		cookie_end = strchr(cookie_start, '=');

		if (cookie_end != NULL) {
			cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');

			if (cookie_end != NULL) {
				cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
				cookie_start = cookie_end;

				g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
			}
		}
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

	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len) {
		cookie_start += 14;
		cookie_end = strchr(cookie_start, '=');

		if (cookie_end != NULL) {
			cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');

			if (cookie_end != NULL) {
				cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
				cookie_start = cookie_end;

				g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
			}
		}
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

	g_hash_table_foreach(ya->cookie_table, (GHFunc) discord_cookie_foreach_cb, str);

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
		/* connection error - unersolvable dns name, non existing server */
		gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
		purple_connection_error(conn->ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
		g_free(error_msg_formatted);
		g_free(conn);
		return;
	}

	if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
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

	if (purple_account_is_disconnected(account)) {
		return;
	}

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
		if (strstr(url, "/login") && strstr(postdata, "password")) {
			purple_debug_info("discord", "With postdata ###PASSWORD REMOVED###\n");
		} else {
			purple_debug_info("discord", "With postdata %s\n", postdata);
		}

		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}

		purple_http_request_set_contents(request, postdata, -1);
	}

	http_conn = purple_http_request(ya->pc, request, discord_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL) {
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);
	}

#else
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	purple_url_parse(url, &host, &port, &path, &user, &password);

	headers = g_string_new(NULL);

	/* Use the full 'url' until libpurple can handle path's longer than 256 chars */
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", method, path);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " DISCORD_USERAGENT "\r\n");
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);

	if (ya->token) {
		g_string_append_printf(headers, "Authorization: %s\r\n", ya->token);
	}

	if (postdata) {
		if (strstr(url, "/login") && strstr(postdata, "password")) {
			purple_debug_info("discord", "With postdata ###PASSWORD REMOVED###\n");
		} else {
			purple_debug_info("discord", "With postdata %s\n", postdata);
		}

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

	if (http_conn != NULL) {
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);
	}

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
static void discord_mark_room_messages_read(DiscordAccount *ya, guint64 room_id);

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
		json_object_set_int_member(data, "large_threshold", 25000);

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

		/* TODO real presence */
		json_object_set_string_member(presence, "status", "online");
		json_object_set_object_member(data, "presence", presence);
	}

	json_object_set_object_member(obj, "d", data);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);
}

static gboolean
discord_send_heartbeat(gpointer userdata)
{
	DiscordAccount *da = userdata;
	JsonObject *obj = json_object_new();

	json_object_set_int_member(obj, "op", 1);
	json_object_set_int_member(obj, "d", da->seq);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);

	return TRUE;
}

void discord_handle_add_new_user(DiscordAccount *ya, JsonObject *obj);

PurpleGroup *discord_get_or_create_default_group();

static void discord_create_relationship(DiscordAccount *da, JsonObject *json);
static void discord_got_relationships(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_private_channels(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_presences(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_read_states(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_history_static(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_history_of_room(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_populate_guild(DiscordAccount *da, JsonObject *guild);
static void discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_avatar(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_get_avatar(DiscordAccount *da, DiscordUser *user, gboolean is_buddy);
static void discord_buddy_guild(DiscordAccount *da, DiscordGuild *guild);

static const gchar *discord_normalise_room_name(const gchar *guild_name, const gchar *name);
static guint64 discord_compute_permission(DiscordAccount *da, DiscordUser *user, DiscordChannel *channel);
static DiscordChannel *discord_open_chat(DiscordAccount *da, guint64 id, gboolean present);

static gboolean
discord_replace_channel(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccount *da = user_data;
	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *channel_id = g_match_info_fetch(match, 1);
	DiscordChannel *channel = discord_get_channel_global(da, channel_id);

	if (channel) {
		/* TODO make this a clickable link */
		DiscordGuild *guild = discord_get_guild(da, channel->guild_id);

		if (guild) {
			g_string_append_printf(result, "%s", discord_normalise_room_name(guild->name, channel->name));
		} else {
			g_string_append_printf(result, "#%s", channel->name);
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(channel_id);
	g_free(match_string);

	return FALSE;
}

#define COLOR_START "<font color=\"#%06X\">"
#define COLOR_END "</font>"

static gboolean
discord_replace_role(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccountGuild *ag = user_data;
	/* DiscordAccount *da = ag->account; */
	DiscordGuild *guild = ag->guild;

	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *role_id = g_match_info_fetch(match, 1);
	guint64 rid = to_int(role_id);

	DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, rid);

	if (rid == guild->id) {
		g_string_append(result, "<b>@everyone</b>");
	} else if (role) {
		/* TODO make this a clickable link */

		if (role->color) {
			g_string_append_printf(result, COLOR_START "<b>@%s</b>" COLOR_END, role->color, role->name);
		} else {
			g_string_append_printf(result, "<b>@%s</b>", role->name);
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(role_id);
	g_free(match_string);

	return FALSE;
}


static gboolean
discord_replace_emoji(const GMatchInfo *match, GString *result, gpointer user_data)
{
	gchar *alt_text = g_match_info_fetch(match, 1);
	gchar *emoji_id = g_match_info_fetch(match, 2);

	/* TODO: download and cache emoji as a PurpleStoredImage? */
	g_string_append_printf(result, "<img src=\"https://cdn.discordapp.com/emojis/%s\" alt=\":%s:\"/>", emoji_id, alt_text);

	g_free(emoji_id);
	g_free(alt_text);

	return FALSE;
}

static gboolean
discord_replace_mention(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccountGuild *ag = user_data;
	DiscordAccount *da = ag->account;
	DiscordGuild *guild = ag->guild;
	gchar *match_string = g_match_info_fetch(match, 0);

	gchar *snowflake_str = g_match_info_fetch(match, 1);
	guint64 snowflake = to_int(snowflake_str);
	g_free(snowflake_str);

	DiscordUser *mention_user = discord_get_user(da, snowflake);

	if (mention_user) {
		/* TODO make this a clickable link */
		gchar *name = discord_create_nickname(mention_user, guild);

		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, name);

		if (buddy && purple_buddy_get_alias(buddy)) {
			g_free(name);
			name = g_strdup(purple_buddy_get_alias(buddy));
		} else if (!guild && snowflake == da->self_user_id && purple_account_get_private_alias(da->account)) {
			g_free(name);
			name = g_strdup(purple_account_get_private_alias(da->account));
		}

		g_string_append_printf(result, "<b>@%s</b>", name);
		g_free(name);
	} else {
		g_string_append(result, match_string);
	}

	g_free(match_string);

	return FALSE;
}

static gchar *
discord_replace_mentions_bare(DiscordAccount *da, DiscordGuild *g, gchar *message)
{
	DiscordAccountGuild ag = { .account = da, .guild = g };
	gchar *tmp = g_regex_replace_eval(mention_regex, message, -1, 0, 0, discord_replace_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	/* Replace <#channel_id> with channel names */
	tmp = g_regex_replace_eval(channel_mentions_regex, message, -1, 0, 0, discord_replace_channel, da, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	/* Replace <@&role_id> with role names */
	if (g) {
		DiscordAccountGuild ag = { .account = da, .guild = g };
		tmp = g_regex_replace_eval(role_mentions_regex, message, -1, 0, 0, discord_replace_role, &ag, NULL);

		if (tmp != NULL) {
			g_free(message);
			message = tmp;
		}
	}

	return message;
}

static guint64
discord_find_role_by_name(DiscordGuild *guild, const gchar *name)
{
	if (!guild) {
		return 0;
	}
	
	if (purple_strequal(name, "everyone")) {
		return guild->id;
	}

	GHashTableIter iter;
	gpointer key;
	gpointer value;
	g_hash_table_iter_init(&iter, guild->roles);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		DiscordGuildRole *role = value;
		if (purple_strequal(role->name, name)) {
			return role->id;
		}
	}

	return 0;
}

static guint64
discord_find_channel_by_name(DiscordGuild *guild, gchar *name)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	
	if (!guild) {
		return 0;
	}
	
	g_hash_table_iter_init(&iter, guild->channels);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		DiscordChannel *channel = value;
		if (purple_strequal(channel->name, name)) {
			return channel->id;
		}
	}

	return 0;
}

static gboolean
discord_make_mention(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccountGuild *ag = user_data;
	DiscordAccount *da = ag->account;
	DiscordGuild *guild = ag->guild;

	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *identifier = g_match_info_fetch(match, 1);

	/* Try to find user by discriminator */
	DiscordUser *user = discord_get_user_fullname(da, identifier);

	/* If that fails, find it by alias */
	if (!user) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, da->new_users);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			/* Key is the user ID, value is DiscordUser */

			DiscordUser *u = value;
			gchar *username = discord_create_fullname(u);
			PurpleBuddy *buddy = purple_blist_find_buddy(da->account, username);
			g_free(username);

			if (buddy && purple_strequal(purple_buddy_get_alias(buddy), identifier)) {
				user = u;
				break;
			}
		}
	}

	/* If that fails, find it by nick */
	if (!user && guild) {
		guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, identifier);

		if (uid) {
			user = discord_get_user(da, *uid);
		}
	}

	if (user) {
		g_string_append_printf(result, "&lt;@%" G_GUINT64_FORMAT "&gt; ", user->id);
	} else if (guild != NULL) {
		/* If that fails, find a role */
		guint64 role = discord_find_role_by_name(guild, identifier);

		if (role) {
			g_string_append_printf(result, "&lt;@&amp;%" G_GUINT64_FORMAT "&gt; ", role);
		} else {
			/* If that fails, find a channel */
			guint64 channel = discord_find_channel_by_name(guild, identifier);

			if(channel) {
				g_string_append_printf(result, "&lt;#%" G_GUINT64_FORMAT "&gt; ", channel);
			} else {
				/* If all else fails, trap out */
				g_string_append(result, match_string);
			}
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(match_string);
	g_free(identifier);

	return FALSE;
}

static gchar *
discord_make_mentions(DiscordAccount *da, DiscordGuild *guild, gchar *message)
{
	DiscordAccountGuild ag = {.account = da, .guild = guild };
	
	// For converting 'Discord normal' @username into a mention
	gchar *tmp = g_regex_replace_eval(discord_mention_regex, message, -1, 0, 0, discord_make_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}
	
	// For converting 'Pidgin normal' username: into a mention
	tmp = g_regex_replace_eval(natural_mention_regex, message, -1, 0, 0, discord_make_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		return tmp;
	}

	return message;
}

static gchar *
discord_create_nickname(DiscordUser *author, DiscordGuild *guild)
{
	if (!guild) {
		return discord_create_fullname(author);
	}

	gchar *name = g_hash_table_lookup_int64(guild->nicknames, author->id);

	if (!name) {
		name = discord_create_fullname(author);
	} else {
		name = g_strdup(name);
	}

	return name;
}

static gchar *
discord_get_real_name(PurpleConnection *pc, gint id, const char *who)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;

	chatconv = purple_conversations_find_chat(pc, id);
	guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id_ptr) {
		goto bail;
	}

	guint64 room_id = *room_id_ptr;

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);

	if (!guild) {
		goto bail;
	}

	guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, who);

	if (uid) {
		DiscordUser *user = discord_get_user(da, *uid);
		return discord_create_fullname(user);
	}

/* Probably a fullname already, bail out */
bail:
	return g_strdup(who);
}

static guint64
discord_process_message(DiscordAccount *da, JsonObject *data, unsigned special_type)
{
	gboolean edited = special_type == DISCORD_MESSAGE_EDITED;
	gboolean pinned = special_type == DISCORD_MESSAGE_PINNED;

	guint64 msg_id = to_int(json_object_get_string_member(data, "id"));

	if (!json_object_get_object_member(data, "author")) {
		/* Possibly edited message? */
		purple_debug_info("discord", "No author in message processed");
		return msg_id;
	}

	JsonObject *author_obj = json_object_get_object_member(data, "author");
	guint64 author_id = to_int(json_object_get_string_member(author_obj, "id"));

	const gchar *channel_id_s = json_object_get_string_member(data, "channel_id");
	guint64 channel_id = to_int(channel_id_s);

	const gchar *content = json_object_get_string_member(data, "content");
	const gchar *timestamp_str = json_object_get_string_member(data, "timestamp");
	time_t timestamp = purple_str_to_time(timestamp_str, FALSE, NULL, NULL, NULL);
	const gchar *nonce = json_object_get_string_member(data, "nonce");
	gchar *escaped_content = purple_markup_escape_text(content, -1);
	JsonArray *attachments = json_object_get_array_member(data, "attachments");
	JsonArray *mentions = json_object_get_array_member(data, "mentions");
	JsonArray *mention_roles = json_object_get_array_member(data, "mention_roles");
	PurpleMessageFlags flags;
	gchar *tmp;
	gint i;

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, channel_id, &guild);

	if (author_id == da->self_user_id) {
		flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
	} else {
		flags = PURPLE_MESSAGE_RECV;
	}

	if (mentions) {
		for (i = json_array_get_length(mentions) - 1; i >= 0; i--) {
			JsonObject *user = json_array_get_object_element(mentions, i);
			guint64 id = to_int(json_object_get_string_member(user, "id"));

			if (id == da->self_user_id) {
				flags |= PURPLE_MESSAGE_NICK;
			}
		}
	}

	if (mention_roles && guild) {
		DiscordUser *self = discord_get_user(da, da->self_user_id);
		if (self) {
			DiscordGuildMembership *membership = g_hash_table_lookup_int64(self->guild_memberships, guild->id);

			if (membership) {
				for (i = json_array_get_length(mention_roles) - 1; i >= 0; i--) {
					guint64 id = to_int(json_array_get_string_element(mention_roles, i));

					for (guint i = 0; i < membership->roles->len; i++) {
						guint64 role_id = g_array_index(membership->roles, guint64, i);

						if (role_id == id) {
							flags |= PURPLE_MESSAGE_NICK;
							break;
						}
					}
				}
			}
		}
	}

	if (mentions || mention_roles) {
		escaped_content = discord_replace_mentions_bare(da, guild, escaped_content);
	}

	if (json_object_get_boolean_member(data, "mention_everyone")) {
		flags |= PURPLE_MESSAGE_NICK;
	}

	/* Replace <:emoji:id> with emojis */
	tmp = g_regex_replace_eval(emoji_regex, escaped_content, -1, 0, 0, discord_replace_emoji, da, NULL);

	if (tmp != NULL) {
		g_free(escaped_content);
		escaped_content = tmp;
	}

	/* translate Discord-formatted actions into /me syntax */
	tmp = g_regex_replace(action_star_regex, escaped_content, -1, 0, "/me \\1", 0, NULL);

	if (tmp != NULL) {
		g_free(escaped_content);
		escaped_content = tmp;
	}

	/* Convert markdown in Discord quirks mode */
	tmp = markdown_convert_markdown(escaped_content, FALSE, TRUE);
	g_free(escaped_content);
	escaped_content = tmp;

	/* Add prefix for edited/pinned messages */
	if (edited || pinned) {
		const gchar *prefix_fmt = pinned ? "📌 %s" : _("EDIT: %s");

		tmp = g_strdup_printf(prefix_fmt, escaped_content);
		g_free(escaped_content);
		escaped_content = tmp;
	}

	if (channel_id_s && g_hash_table_contains(da->one_to_ones, channel_id_s)) {
		/* private message */

		if (author_id == da->self_user_id) {
			if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
				PurpleConversation *conv;
				PurpleIMConversation *imconv;
				PurpleMessage *msg;

				gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
				imconv = purple_conversations_find_im_with_account(username, da->account);

				if (imconv == NULL) {
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
			DiscordUser *author = discord_upsert_user(da->new_users, author_obj);
			gchar *merged_username = discord_create_fullname(author);

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
		/* Open the buffer if it's not already */
		int head_count = guild ? guild->members->len : 0;

		gboolean mentioned = flags & PURPLE_MESSAGE_NICK;

		if (mentioned || (head_count < purple_account_get_int(da->account, "large-channel-count", 20))) {
			discord_open_chat(da, channel_id, mentioned);
		}

		gchar *name = NULL;
		if (json_object_has_member(data, "webhook_id")) {
			name = g_strdup(json_object_get_string_member(author_obj, "username"));
		} else {
			DiscordUser *author = discord_upsert_user(da->new_users, author_obj);
			name = discord_create_nickname(author, guild);
		}

		if (escaped_content && *escaped_content) {
			purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, escaped_content, timestamp);
		}

		if (attachments) {
			for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
				JsonObject *attachment = json_array_get_object_element(attachments, i);
				const gchar *url = json_object_get_string_member(attachment, "url");

				purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, url, timestamp);
			}
		}

		g_free(name);
	}

	g_free(escaped_content);

	return msg_id;
}

struct discord_group_typing_data {
	DiscordAccount *da;
	guint64 channel_id;
	gchar *username;
	gboolean set;
	gboolean free_me;
};

static gboolean
discord_set_group_typing(void *_u)
{
	if (_u == NULL) {
		return FALSE;
	}

	struct discord_group_typing_data *ctx = _u;

	PurpleChatConversation *chatconv = purple_conversations_find_chat(ctx->da->pc, discord_chat_hash(ctx->channel_id));

	if (chatconv == NULL) {
		goto release_ctx;
	}

	PurpleChatUser *cb = purple_chat_conversation_find_user(chatconv, ctx->username);

	if (!cb) {
		goto release_ctx;
	}

	PurpleChatUserFlags cbflags;

	cbflags = purple_chat_user_get_flags(cb);

	if (ctx->set) {
		cbflags |= PURPLE_CHAT_USER_TYPING;
	} else {
		cbflags &= ~PURPLE_CHAT_USER_TYPING;
	}

	purple_chat_user_set_flags(cb, cbflags);

release_ctx:

	if (ctx->free_me) {
		g_free(ctx->username);
		g_free(ctx);
	}

	return FALSE;
}

static void
discord_got_nick_change(DiscordAccount *da, DiscordUser *user, DiscordGuild *guild, const gchar *new, const gchar *old, gboolean self)
{
	gchar *old_safe = g_strdup(old);

	if (old) {
		g_hash_table_remove(guild->nicknames_rev, old);
	}

	/* Nick change */
	gchar *nick = discord_alloc_nickname(user, guild, new);

	/* Propagate through the guild, see e.g. irc_msg_nick */
	GHashTableIter channel_iter;
	gpointer key, value;

	g_hash_table_iter_init(&channel_iter, guild->channels);

	while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
		DiscordChannel *channel = value;
		PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));

		if (chat && purple_chat_conversation_has_user(chat, old_safe)) {
			purple_chat_conversation_rename_user(chat, old_safe, nick);
		}
	}

	g_free(nick);
}

static gchar *
discord_name_group_dm(DiscordAccount *da, DiscordChannel *channel) {
	/* TODO: Disambiguate with same participants, by topic, username nondiscriminator, cut length... */
	GString *name = g_string_new(NULL);
	GList *l;

	for (l = channel->recipients; l != NULL; l = l->next) {
		guint64 *recipient_ptr = l->data;
		DiscordUser *recipient = discord_get_user(da, *recipient_ptr);
		gchar *fullname = discord_create_fullname(recipient);
		
		if (fullname != NULL) {
			g_string_append(name, fullname);

			if (l->next) {
				g_string_append(name, g_strdup(", "));
			}
			
			g_free(fullname);
		}
	}

	return g_string_free(name, FALSE);
}


PurpleChat *
discord_find_chat_from_node(PurpleAccount *account, const char *id, PurpleBlistNode *root)
{
	PurpleBlistNode *node;
	
	for (node = root;
		 node != NULL;
		 node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_CHAT(node)) {
			PurpleChat *chat = PURPLE_CHAT(node);

			if (purple_chat_get_account(chat) != account) {
				continue;
			}
			
			GHashTable *components = purple_chat_get_components(chat);
			const gchar *chat_id = g_hash_table_lookup(components, "id");
			
			if (purple_strequal(chat_id, id)) {
				return chat;
			}
		}
	}
	
	return NULL;
}

PurpleChat *
discord_find_chat(PurpleAccount *account, const char *id)
{
	return discord_find_chat_from_node(account, id, purple_blist_get_root());
}


PurpleChat *
discord_find_chat_in_group(PurpleAccount *account, const char *id, PurpleGroup *group)
{
	g_return_val_if_fail(group != NULL, NULL);
	
	return discord_find_chat_from_node(account, id, PURPLE_BLIST_NODE(group));
}


static void
discord_add_channel_to_blist(DiscordAccount *da, DiscordChannel *channel, PurpleGroup *group)
{
	GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	gchar *id = from_int(channel->id);
	
	g_hash_table_replace(components, g_strdup("id"), id);
	g_hash_table_replace(components, g_strdup("name"), g_strdup(channel->name));

	if (!group) {
		group = discord_get_or_create_default_group();
	}
	
	/* Don't re-add the channel to the same group */
	if (discord_find_chat_in_group(da->account, id, group) == NULL) {
		PurpleChat *chat = purple_chat_new(da->account, channel->name, components);
		purple_blist_add_chat(chat, group, NULL);
	} else {
		g_hash_table_unref(components);
	}
}

static void
discord_add_group_dms_to_blist(DiscordAccount *da)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!purple_account_is_connected(da->account) 
		|| !purple_account_get_bool(da->account, "populate-blist", TRUE))
	{
		return;
	}
	
	g_hash_table_iter_init(&iter, da->group_dms);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;
		gint64 *id = key;
		gchar *id_str = from_int(*id);
		
		if (purple_blist_find_chat(da->account, id_str) == NULL) {
			discord_add_channel_to_blist(da, channel, NULL);
		}
	}
}

static void
discord_got_group_dm(DiscordAccount *da, JsonObject *data)
{
	DiscordChannel *channel = discord_new_channel(data);
	JsonArray *recipients = json_object_get_array_member(data, "recipients");

	for (int i = json_array_get_length(recipients) - 1; i >= 0; i--) {
		DiscordUser *recipient =
			discord_upsert_user(da->new_users,
								json_array_get_object_element(recipients, i));

		channel->recipients = g_list_prepend(channel->recipients, g_memdup(&(recipient->id), sizeof(guint64)));
	}

	g_hash_table_replace_int64(da->group_dms, channel->id, channel);

	channel->name = discord_name_group_dm(da, channel);

	gchar *id = from_int(channel->id);

	if (purple_account_is_connected(da->account) 
		&& purple_account_get_bool(da->account, "populate-blist", TRUE)
		&& purple_blist_find_chat(da->account, id) == NULL) {
			
		discord_add_channel_to_blist(da, channel, NULL);
	}
	
	g_free(id); 
}

static void
discord_process_dispatch(DiscordAccount *da, const gchar *type, JsonObject *data)
{
	if (purple_strequal(type, "PRESENCE_UPDATE")) {
		JsonObject *userdata = json_object_get_object_member(data, "user");
		DiscordUser *user = discord_upsert_user(da->new_users, userdata);
		discord_update_status(user, data);

		gchar *username = discord_create_fullname_from_id(da, user->id);
		const gchar *guild_id = json_object_get_string_member(data, "guild_id");
		gint64 idle_since = json_object_get_int_member(data, "idle_since");

		if (guild_id) {
			GHashTableIter iter;
			gpointer key, value;

			DiscordGuild *guild = discord_get_guild(da, to_int(guild_id));
			
			if (!guild) {
				purple_debug_error("discord", "Unknown guild %s\n", guild_id);
				g_free(username);
				return;
			}
			
			gchar *nickname = discord_create_nickname(user, guild);

			g_hash_table_iter_init(&iter, guild->channels);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				DiscordChannel *channel = value;
				PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));

				if (chat != NULL) {
					if (user->status == USER_OFFLINE) {
						if (purple_chat_conversation_has_user(chat, nickname)) {
							purple_chat_conversation_remove_user(chat, nickname, NULL);
						}
					} else if (!purple_chat_conversation_has_user(chat, nickname)) {
						PurpleChatUserFlags flags = discord_get_user_flags(da, guild, user);
						purple_chat_conversation_add_user(chat, nickname, NULL, flags, FALSE);
					}
				}
			}
			g_free(nickname);
			
		} else if (username) {
			const gchar *status = json_object_get_string_member(data, "status");
			purple_protocol_got_user_status(da->account, username, status, "message", user->game, NULL);
			purple_protocol_got_user_idle(da->account, username, idle_since ? TRUE : FALSE, 0);
			
			// Check avatar updates
			const gchar *new_avatar = json_object_get_string_member(userdata, "avatar");
			if (!purple_strequal(user->avatar, new_avatar)) {
				g_free(user->avatar);
				user->avatar = g_strdup(new_avatar);
				discord_get_avatar(da, user, TRUE);
			}
			
			// Handle a user being renamed
			const gchar *new_username = json_object_get_string_member(userdata, "username");
			const gchar *new_discriminator = json_object_get_string_member(userdata, "discriminator");
			gint64 new_disc = to_int(new_discriminator);
			if (new_username && new_disc && (!purple_strequal(user->name, new_username) || user->discriminator != new_disc)) {
				
				// create a new PurpleBuddy, add to the current PurpleBuddy's PurpleContact, 'disable' the old PurpleBuddy
				// this allows Pidgin to see the logs for a merged contact, as well as seamlessly switch between old and new
				
				gchar *new_username_full = discord_combine_username(new_username, new_discriminator);
				PurpleBuddy *old_buddy = purple_blist_find_buddy(da->account, username);
				PurpleContact *buddy_contact = NULL;
				PurpleGroup *buddy_group = discord_get_or_create_default_group();
				if (old_buddy != NULL) {
					buddy_contact = purple_buddy_get_contact(old_buddy);
					buddy_group = purple_buddy_get_group(old_buddy);
				}
				PurpleBuddy *buddy = purple_buddy_new(da->account, new_username_full, new_username);
				purple_blist_add_buddy(buddy, buddy_contact, buddy_group, NULL);
				
				// point the user -> id lookup tables at the new user
				g_free(user->name);
				user->name = g_strdup(new_username);
				user->discriminator = new_disc;
				
				const gchar *channel_id = g_hash_table_lookup(da->one_to_ones_rev, username);
				if (channel_id != NULL) {
					const gchar *last_message_id = g_hash_table_lookup(da->last_message_id_dm, channel_id);
					
					g_hash_table_replace(da->one_to_ones, g_strdup(channel_id), new_username_full);
					g_hash_table_replace(da->last_message_id_dm, g_strdup(channel_id), g_strdup(last_message_id));
					g_hash_table_replace(da->one_to_ones_rev, g_strdup(new_username_full), g_strdup(channel_id));
				}
				
				// Change status to the new user
				purple_protocol_got_user_status(da->account, new_username_full, status, "message", user->game, NULL);
				purple_protocol_got_user_idle(da->account, new_username_full, idle_since ? TRUE : FALSE, 0);
				purple_protocol_got_user_status(da->account, username, "offline", NULL);
			}
		}

		g_free(username);
	} else if (purple_strequal(type, "MESSAGE_CREATE") || purple_strequal(type, "MESSAGE_UPDATE")) { /* TODO */
		unsigned msgtype = DISCORD_MESSAGE_NORMAL;

		if (purple_strequal(type, "MESSAGE_UPDATE")) {
			/* An update could mean that we were edited or that we
			 * were pinned. If it's both, default to just showing
			 * pinned. */

			gboolean is_pinned = json_object_get_boolean_member(data, "pinned");

			msgtype = is_pinned ? DISCORD_MESSAGE_PINNED : DISCORD_MESSAGE_EDITED;
		}

		discord_process_message(da, data, msgtype);

		const gchar *channel_id = json_object_get_string_member(data, "channel_id");

		if (!channel_id) {
			return;
		}

		DiscordGuild *guild = NULL;
		discord_get_channel_global_int_guild(da, to_int(channel_id), &guild);

		guint64 tmp = to_int(channel_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(tmp));

		if (!chatconv) {
			return;
		}

		JsonObject *json = json_object_get_object_member(data, "author");
		gchar *n = discord_create_nickname_from_id(da, guild, to_int(json_object_get_string_member(json, "id")));

		struct discord_group_typing_data ctx = {
			.da = da,
			.channel_id = tmp,
			.username = n,
			.set = FALSE,
			.free_me = FALSE
		};

		discord_set_group_typing(&ctx);

		g_free(n);
	} else if (purple_strequal(type, "TYPING_START")) {
		const gchar *channel_id = json_object_get_string_member(data, "channel_id");
		guint64 user_id = to_int(json_object_get_string_member(data, "user_id"));

		/* Don't display typing notifications from ourselves */
		if (user_id == da->self_user_id) {
			return;
		}

		if (!channel_id) {
			return;
		}

		DiscordChannel *channel = discord_get_channel_global(da, channel_id);

		if (channel != NULL) {
			DiscordGuild *guild = discord_get_guild(da, channel->guild_id);
			gchar *username = discord_create_nickname_from_id(da, guild, user_id);

			struct discord_group_typing_data set = {
				.da = da,
				.channel_id = to_int(channel_id),
				.username = username,
				.set = TRUE,
				.free_me = FALSE
			};

			discord_set_group_typing(&set);

			struct discord_group_typing_data *clear = g_memdup(&set, sizeof(set));
			clear->set = FALSE;
			clear->free_me = TRUE;

			g_timeout_add_seconds(10, discord_set_group_typing, clear);
		} else {
			DiscordUser *user = discord_get_user(da, user_id);
			gchar *merged_username = discord_create_fullname(user);
			
			purple_serv_got_typing(da->pc, merged_username, 10, PURPLE_IM_TYPING);
			
			g_free(merged_username);
		}
	} else if (purple_strequal(type, "CHANNEL_CREATE")) {
		const gchar *channel_id = json_object_get_string_member(data, "id");
		gint64 channel_type = json_object_get_int_member(data, "type");
		const gchar *last_message_id = json_object_get_string_member(data, "last_message_id");

		if (channel_type == 1) {
			/* 1:1 direct message */

			JsonObject *first_recipient = json_array_get_object_element(json_object_get_array_member(data, "recipients"), 0);

			if (first_recipient != NULL) {
				const gchar *username = json_object_get_string_member(first_recipient, "username");
				const gchar *discriminator = json_object_get_string_member(first_recipient, "discriminator");
				gchar *combined_username = discord_combine_username(username, discriminator);
				
				if (combined_username != NULL) {
					g_hash_table_replace(da->one_to_ones, g_strdup(channel_id), g_strdup(combined_username));
					g_hash_table_replace(da->last_message_id_dm, g_strdup(channel_id), g_strdup(last_message_id));
					g_hash_table_replace(da->one_to_ones_rev, combined_username, g_strdup(channel_id));
				}
			}
		} else if (channel_type == 3) {
			discord_got_group_dm(da, data);
		} else if (channel_type == 0) {
			const gchar *guild_id = json_object_get_string_member(data, "guild_id");
			DiscordGuild *guild = discord_get_guild(da, to_int(guild_id));
			DiscordChannel *channel = discord_add_channel(guild, data, guild->id);

			JsonArray *permission_overrides = json_object_get_array_member(data, "permission_overwrites");

			for (int k = json_array_get_length(permission_overrides) - 1; k >= 0; k--) {
				JsonObject *permission_override = json_array_get_object_element(permission_overrides, k);
				discord_add_permission_override(channel, permission_override);
			}
			
			if (purple_account_is_connected(da->account) 
				&& purple_account_get_bool(da->account, "populate-blist", TRUE)
				&& purple_blist_find_chat(da->account, channel_id) == NULL) {
				
				DiscordUser *user = discord_get_user(da, da->self_user_id);
				guint64 permission = discord_compute_permission(da, user, channel);

				/* must have READ_MESSAGES */
				if ((permission & 0x400)) {
					discord_add_channel_to_blist(da, channel, NULL);
				}
			}
		}
		
	} else if (purple_strequal(type, "CHANNEL_UPDATE")) {
		guint64 channel_id = to_int(json_object_get_string_member(data, "id"));
		gint64 channel_type = json_object_get_int_member(data, "type");

		if ((channel_type == 0 && json_object_has_member(data, "topic")) || channel_type == 3) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));

			if (chatconv) {
				purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(data, (channel_type == 3 ? "topic" : "name")));
			}
		}
	} else if (purple_strequal(type, "RELATIONSHIP_ADD")) {
		discord_create_relationship(da, data);
	} else if (purple_strequal(type, "RELATIONSHIP_REMOVE")) {
		guint64 user_id = to_int(json_object_get_string_member(data, "id"));
		DiscordUser *user = discord_get_user(da, user_id);

		if (user) {
			gchar *username = discord_create_fullname(user);
			gint64 type = json_object_get_int_member(data, "type");
			
			if (username != NULL) {
				if (type == 2) {
					/* remove user from blocklist */
					purple_account_privacy_deny_remove(da->account, username, TRUE);
					
				} else {
					PurpleBuddy *buddy = purple_blist_find_buddy(da->account, username);
					purple_blist_remove_buddy(buddy);

					const gchar *room_id = g_hash_table_lookup(da->one_to_ones_rev, username);
					if (room_id != NULL) {
						g_hash_table_remove(da->one_to_ones, room_id);
						g_hash_table_remove(da->last_message_id_dm, room_id);
						g_hash_table_remove(da->one_to_ones_rev, username);
					}
				}

				g_free(username);
			}
		}
	} else if (purple_strequal(type, "RESUMED")) {
		purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
	} else if (purple_strequal(type, "READY")) {
		JsonObject *self_user = json_object_get_object_member(data, "user");
		DiscordUser *self_user_obj = NULL;
		da->self_user_id = to_int(json_object_get_string_member(self_user, "id"));

		if (!purple_account_get_private_alias(da->account)) {
			purple_account_set_private_alias(da->account, json_object_get_string_member(self_user, "username"));
		}

		g_free(da->self_username);
		da->self_username = discord_combine_username(json_object_get_string_member(self_user, "username"), json_object_get_string_member(self_user, "discriminator"));
		purple_connection_set_display_name(da->pc, da->self_username);

		g_free(da->session_id);
		da->session_id = g_strdup(json_object_get_string_member(data, "session_id"));

		self_user_obj = discord_get_user(da, da->self_user_id);
		if (!self_user_obj) {
			/* Ensure user is non-null... */
			discord_upsert_user(da->new_users, self_user);
		}

		discord_got_relationships(da, json_object_get_member(data, "relationships"), NULL);
		discord_got_private_channels(da, json_object_get_member(data, "private_channels"), NULL);
		discord_got_presences(da, json_object_get_member(data, "presences"), NULL);
		discord_got_guilds(da, json_object_get_member(data, "guilds"), NULL);
		discord_got_read_states(da, json_object_get_member(data, "read_state"), NULL);

		/* Fetch our own avatar */
		self_user_obj = discord_get_user(da, da->self_user_id);
		discord_get_avatar(da, self_user_obj, FALSE);

		if (!self_user_obj) {
			/* ...But remove afterward, this user object is partial */
			g_hash_table_remove(da->new_users, &da->self_user_id);
		}
		
		/* ready for libpurple to join chats etc */
		purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
		
		discord_add_group_dms_to_blist(da);
		
	} else if (purple_strequal(type, "GUILD_SYNC") || purple_strequal(type, "GUILD_CREATE")) {
		if (purple_strequal(type, "GUILD_CREATE")) {
			discord_populate_guild(da, data);
		}

		JsonArray *presences = json_object_get_array_member(data, "presences");
		JsonArray *members = json_object_get_array_member(data, "members");
		guint64 guild_id = to_int(json_object_get_string_member(data, "id"));

		DiscordGuild *guild = discord_get_guild(da, guild_id);

		if (!guild) {
			purple_debug_error("discord", "Unknown guild %" G_GUINT64_FORMAT "\n", guild_id);
			return;
		}
		
		g_array_set_size(guild->members, 0);
		
		/* all members in small groups, online in large */
		for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
			JsonObject *member = json_array_get_object_element(members, j);
			JsonObject *user = json_object_get_object_member(member, "user");

			DiscordUser *u = discord_upsert_user(da->new_users, user);
			DiscordGuildMembership *membership = discord_new_guild_membership(guild_id, member);
			g_hash_table_replace_int64(u->guild_memberships, membership->id, membership);
			g_array_append_val(guild->members, u->id);

			g_free(discord_alloc_nickname(u, guild, membership->nick));

			JsonArray *roles = json_object_get_array_member(member, "roles");

			for (int k = json_array_get_length(roles) - 1; k >= 0; k--) {
				guint64 role = to_int(json_array_get_string_element(roles, k));
				g_array_append_val(membership->roles, role);
			}
		}

		if (purple_account_get_bool(da->account, "populate-blist", TRUE)) {
			discord_buddy_guild(da, guild);
		}
		
		/* Update online users first */
		for (int j = json_array_get_length(presences) - 1; j >= 0; j--) {
			JsonObject *presence = json_array_get_object_element(presences, j);

			DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(presence, "user"));
			discord_update_status(user, presence);
		}

		/* Add online people to any open chats */
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, guild->channels);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			GList *users = NULL, *flags = NULL;
			DiscordChannel *channel = value;

			PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));
			if (chat == NULL) {
				//Skip over closed chats
				continue;
			}
		
			/* Presence only contains online users */
			for (int j = json_array_get_length(presences) - 1; j >= 0; j--) {
				JsonObject *presence = json_array_get_object_element(presences, j);

				DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(presence, "user"));
				
				guint64 permission = discord_compute_permission(da, user, channel);

				/* must have READ_MESSAGES */
				if ((permission & 0x400)) {
					PurpleChatUserFlags cbflags = discord_get_user_flags(da, guild, user);
					gchar *nickname = discord_create_nickname(user, guild);
					
					if (nickname != NULL) {
						users = g_list_prepend(users, nickname);
						flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
					}
				}
			}
			
			purple_chat_conversation_clear_users(chat);
			purple_chat_conversation_add_users(chat, users, NULL, flags, FALSE);
			
			while (users != NULL) {
				g_free(users->data);
				users = g_list_delete_link(users, users);
			}

			g_list_free(flags);
		}


		discord_print_users(da->new_users);
	} else if (purple_strequal(type, "GUILD_MEMBER_ADD")) {
		JsonObject *userdata = json_object_get_object_member(data, "user");
		DiscordUser *user = discord_upsert_user(da->new_users, userdata);
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);
		
		if (!guild) {
			purple_debug_error("discord", "Unknown guild %" G_GUINT64_FORMAT "\n", guild_id);
			return;
		}
		
		DiscordGuildMembership *membership = discord_new_guild_membership(guild_id, userdata);
		g_hash_table_replace_int64(user->guild_memberships, membership->id, membership);
		g_array_append_val(guild->members, user->id);

		g_free(discord_alloc_nickname(user, guild, membership->nick));

		JsonArray *roles = json_object_get_array_member(data, "roles");

		for (int k = json_array_get_length(roles) - 1; k >= 0; k--) {
			guint64 role = to_int(json_array_get_string_element(roles, k));
			g_array_append_val(membership->roles, role);
		}
		
	} else if (purple_strequal(type, "GUILD_MEMBER_UPDATE")) {
		DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		DiscordGuild *guild = discord_get_guild(da, to_int(json_object_get_string_member(data, "guild_id")));

		if (guild && user) {
			const gchar *new_nick = json_object_get_string_member(data, "nick");
			const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, user->id);

			if (!purple_strequal(new_nick, old_nick)) {
				discord_got_nick_change(da, user, guild, new_nick, old_nick, FALSE);
			}
		}

		/* TODO: Track role changes */
	} else if (purple_strequal(type, "CHANNEL_RECIPIENT_ADD") || purple_strequal(type, "CHANNEL_RECIPIENT_REMOVE")) {
		DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		gchar *name = discord_create_fullname(user);
		guint64 room_id = to_int(json_object_get_string_member(data, "channel_id"));
		PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(room_id));

		if (purple_strequal(type, "CHANNEL_RECIPIENT_ADD")) {
			purple_chat_conversation_add_user(chat, name, NULL, PURPLE_CHAT_USER_NONE, TRUE);
		} else {
			purple_chat_conversation_remove_user(chat, name, NULL);
		}
		
		g_free(name);
	} else {
		purple_debug_info("discord", "Unhandled message type '%s'\n", type);
	}
}

PurpleGroup *
discord_get_or_create_default_group()
{
	PurpleGroup *discord_group = purple_blist_find_group("Discord");

	if (!discord_group) {
		discord_group = purple_group_new("Discord");
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
	g_free(channel_name);

	return old_name;
}

static void
discord_roomlist_got_list(DiscordAccount *da, DiscordGuild *guild, gpointer user_data)
{
	PurpleRoomlist *roomlist = user_data;
	const gchar *guild_name = guild ? guild->name : _("Group DMs");
	PurpleRoomlistRoom *category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, guild_name, NULL);
	purple_roomlist_room_add_field(roomlist, category, (gpointer) guild_name);
	purple_roomlist_room_add(roomlist, category);

	GHashTableIter iter;
	gpointer key, value;

	if (guild != NULL) {
		g_hash_table_iter_init(&iter, guild->channels);
	} else {
		g_hash_table_iter_init(&iter, da->group_dms);	
	}

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;
		PurpleRoomlistRoom *room;

		gchar *channel_id = from_int(channel->id);
		gchar *type_str;

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, "", category);

		purple_roomlist_room_add_field(roomlist, room, channel_id);
		purple_roomlist_room_add_field(roomlist, room, channel->name);

		switch (channel->type) {
			case 0:
				type_str = _("Text");
				break;
			
			case 1:
				type_str = _("Direct Message");
				break;
			
			case 2:
				type_str = _("Voice");
				break;
			
			case 3:
				type_str = _("Group DM");
				break;
			
			case 4:
				type_str = _("Guild Category");
				break;

			default:
				type_str = _("Unknown");
				break;
		}

		purple_roomlist_room_add_field(roomlist, room, type_str);

		purple_roomlist_room_add(roomlist, room);
		g_free(channel_id);
	}
}

static gchar *
discord_roomlist_serialize(PurpleRoomlistRoom *room)
{
	GList *fields = purple_roomlist_room_get_fields(room);
	const gchar *id = (const gchar *) fields->data;

	return g_strdup(id);
}

PurpleRoomlist *
discord_roomlist_get_list(PurpleConnection *pc)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;

	roomlist = purple_roomlist_new(da->account);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "id", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Room Type"), "type", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);

	// Add group-DM's first
	discord_roomlist_got_list(da, NULL, roomlist);
	
	GHashTableIter iter;
	gpointer key, guild;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &guild)) {
		discord_roomlist_got_list(da, guild, roomlist);
	}

	purple_roomlist_set_in_progress(roomlist, FALSE);

	return roomlist;
}

void
discord_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	DiscordAccount *ya = purple_connection_get_protocol_data(pc);
	const gchar *status_id = purple_status_get_id(status);
	gchar *postdata;

	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();

	if (g_str_has_prefix(status_id, "set-")) {
		status_id = &status_id[4];
	}

	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status_id);
	json_object_set_int_member(data, "since", 0);

	if (purple_account_get_bool(account, "use-status-as-game", FALSE)) {
		JsonObject *game = json_object_new();
		const gchar *message = purple_status_get_attr_string(status, "message");

		json_object_set_int_member(game, "type", 0); /* 0 = Playing, 1 = Streaming */
		json_object_set_string_member(game, "name", message);
		json_object_set_object_member(data, "game", game);
	} else {
		json_object_set_null_member(data, "game");
	}

	json_object_set_boolean_member(data, "afk", FALSE);
	json_object_set_object_member(obj, "d", data);

	discord_socket_write_json(ya, obj);

	data = json_object_new();
	json_object_set_string_member(data, "status", status_id);
	postdata = json_object_to_string(data);

	discord_fetch_url_with_method(ya, "PATCH", "https://" DISCORD_API_SERVER "/api/v6/users/@me/settings", postdata, NULL, NULL);

	g_free(postdata);
	json_object_unref(data);
}

void
discord_set_idle(PurpleConnection *pc, int idle_time)
{
	DiscordAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	const gchar *status = "idle";
	gint64 since = ((gint64) time(NULL) - (gint64) idle_time) * 1000;

	if (idle_time < 20) {
		status = "online";
		since = 0;
	}

	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status);
	json_object_set_int_member(data, "since", since);
	json_object_set_null_member(data, "game");
	json_object_set_boolean_member(data, "afk", idle_time >= 20);
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
		if (PURPLE_IS_BUDDY(node)) {
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
				g_hash_table_replace(ya->last_message_id_dm, g_strdup(discord_id), g_strdup("0"));
				g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(discord_id));
			}
		}
	}
}

static guint discord_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, DiscordAccount *ya);
static gulong chat_conversation_typing_signal = 0;
static void discord_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);
static gulong conversation_updated_signal = 0;
static gboolean discord_capture_join_part(PurpleConversation *conv, const char *name, PurpleConvChatBuddyFlags flags, GHashTable *users);
static gulong join_signal = 0;
static gulong part_signal = 0;

typedef struct {
	DiscordAccount *da;
	DiscordUser *user;
} DiscordUserInviteResponseStore;

/* Always be quiet */

static gboolean
discord_capture_join_part(PurpleConversation *conv, const char *name, PurpleConvChatBuddyFlags flags, GHashTable *users)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	
	if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), DISCORD_PLUGIN_ID)) {
		return FALSE;
	}
	
	return TRUE;
}

static void
discord_friends_auth_accept(
#if PURPLE_VERSION_CHECK(3, 0, 0)
  const gchar *response,
#endif
  gpointer userdata)
{
	DiscordUserInviteResponseStore *store = userdata;
	DiscordUser *user = store->user;
	DiscordAccount *da = store->da;

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "PUT", url, NULL, NULL, NULL);
	g_free(url);

	g_free(store);
}

static void
discord_friends_auth_reject(
#if PURPLE_VERSION_CHECK(3, 0, 0)
  const gchar *response,
#endif
  gpointer userdata)
{
	DiscordUserInviteResponseStore *store = userdata;
	DiscordUser *user = store->user;
	DiscordAccount *da = store->da;

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);

	g_free(store);
}

static void
discord_create_relationship(DiscordAccount *da, JsonObject *json)
{
	DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(json, "user"));
	gint64 type = json_object_get_int_member(json, "type");
	gchar *merged_username = discord_create_fullname(user);

	if (type == 3) {
		/* request add */
		DiscordUserInviteResponseStore *store = g_new0(DiscordUserInviteResponseStore, 1);

		store->da = da;
		store->user = user;

		purple_account_request_authorization(da->account, merged_username, NULL, NULL, NULL, FALSE, discord_friends_auth_accept, discord_friends_auth_reject, store);
	} else if (type == 1) {
		/* buddy on list */
		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, merged_username);

		if (buddy == NULL) {
			buddy = purple_buddy_new(da->account, merged_username, user->name);
			purple_blist_add_buddy(buddy, NULL, discord_get_or_create_default_group(), NULL);
		}

		discord_get_avatar(da, user, TRUE);
		
	} else if (type == 2) {
		/* blocked buddy */
		purple_account_privacy_deny_add(da->account, merged_username, TRUE);
		
	} else if (type == 4) {
		/* pending buddy */
	}

	g_free(merged_username);
}

static void
discord_got_relationships(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *relationships = json_node_get_array(node);
	guint len = json_array_get_length(relationships);

	for (int i = len - 1; i >= 0; i--) {
		discord_create_relationship(da, json_array_get_object_element(relationships, i));
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
		const gchar *last_message_id = json_object_get_string_member(channel, "last_message_id");
		gint64 room_type = json_object_get_int_member(channel, "type");

		if (room_type == 1) {
			/* One-to-one DM */
			JsonObject *user = json_array_get_object_element(recipients, 0);
			const gchar *username = json_object_get_string_member(user, "username");
			const gchar *discriminator = json_object_get_string_member(user, "discriminator");
			gchar *merged_username = discord_combine_username(username, discriminator);

			g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(merged_username));
			g_hash_table_replace(da->one_to_ones_rev, g_strdup(merged_username), g_strdup(room_id));
			g_hash_table_replace(da->last_message_id_dm, g_strdup(room_id), g_strdup(last_message_id));

			g_free(merged_username);
		} else if (room_type == 3) {
			discord_got_group_dm(da, channel);
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
		/* TODO convert to user object */
		JsonObject *presence = json_array_get_object_element(presences, i);
		JsonObject *user = json_object_get_object_member(presence, "user");
		const gchar *status = json_object_get_string_member(presence, "status");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *discriminator = json_object_get_string_member(user, "discriminator");
		JsonObject *game = json_object_get_object_member(presence, "game");
		const gchar *game_name = json_object_get_string_member(game, "name");
		gchar *merged_username = discord_combine_username(username, discriminator);

		purple_protocol_got_user_status(da->account, merged_username, status, "message", game_name, NULL);
		purple_protocol_got_user_idle(da->account, merged_username, purple_strequal(status, "idle"), 0);

		g_free(merged_username);
	}
}

static void
discord_buddy_guild(DiscordAccount *da, DiscordGuild *guild)
{
	/* Create group */
	/* TODO: What if this is not unique? */

	PurpleGroup *group = purple_blist_find_group(guild->name);

	if (!group) {
		group = purple_group_new(guild->name);

		if (!group) {
			return;
		}

		purple_blist_add_group(group, NULL);
	}

	GHashTableIter iter;
	gpointer key;
	gpointer value;

	DiscordUser *user = discord_get_user(da, da->self_user_id);

	if (!user) {
		purple_debug_info("discord", "Null user; aborting blist population");
		return;
	}

	g_hash_table_iter_init(&iter, guild->channels);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;

		/* Ensure that we actually have permissions for this channel */
		guint64 permission = discord_compute_permission(da, user, channel);

		/* must have READ_MESSAGES */
		if (!(permission & 0x400)) {
			continue;
		}

		/* Drop voice channels since we don't support them anyway */
		if (channel->type == CHANNEL_VOICE) {
			continue;
		}

		discord_add_channel_to_blist(da, channel, group);
	}
}

static void
discord_populate_guild(DiscordAccount *da, JsonObject *guild)
{
	DiscordGuild *g = discord_upsert_guild(da->new_guilds, guild);

	JsonArray *channels = json_object_get_array_member(guild, "channels");
	JsonArray *roles = json_object_get_array_member(guild, "roles");

	for (int j = json_array_get_length(roles) - 1; j >= 0; j--) {
		JsonObject *role = json_array_get_object_element(roles, j);
		discord_add_guild_role(g, role);
	}

	for (int j = json_array_get_length(channels) - 1; j >= 0; j--) {
		JsonObject *channel = json_array_get_object_element(channels, j);

		DiscordChannel *c = discord_add_channel(g, channel, g->id);

		JsonArray *permission_overrides = json_object_get_array_member(channel, "permission_overwrites");

		for (int k = json_array_get_length(permission_overrides) - 1; k >= 0; k--) {
			JsonObject *permission_override = json_array_get_object_element(permission_overrides, k);
			discord_add_permission_override(c, permission_override);
		}
	}
}

static void
discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *guilds = json_node_get_array(node);
	guint len = json_array_get_length(guilds);
	JsonArray *guild_ids = json_array_new();
	JsonObject *obj;

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *guild = json_array_get_object_element(guilds, i);
		discord_populate_guild(da, guild);
		json_array_add_string_element(guild_ids, json_object_get_string_member(guild, "id"));
	}

	discord_print_guilds(da->new_guilds);

	/* Request more info about guilds (online/offline buddy status) */
	//XXX disable for now as it causes the websocket to disconnect with error 4001
	obj = json_object_new();
	json_object_set_int_member(obj, "op", 12);
	json_object_set_array_member(obj, "d", guild_ids);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);
}

/* If count is explicitly specified, use a static request (DMs).
 * If it is not, use a dynamic request (rooms).
 * TODO: Possible edge case if there are over 100 incoming DMs?
 */

static void
discord_get_history(DiscordAccount *da, const gchar *channel, const gchar *last, int count)
{
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%s/messages?limit=%d&after=%s", channel, count ? count : 100, last);
	discord_fetch_url(da, url, NULL, count ? discord_got_history_static : discord_got_history_of_room, count ? NULL : discord_get_channel_global(da, channel));
	g_free(url);
}


static guint64 discord_get_room_last_id(DiscordAccount *da, guint64 id);
static void discord_set_room_last_id(DiscordAccount *da, guint64 channel_id, guint64 last_id);

static void
discord_got_read_states(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *states = json_node_get_array(node);
	guint len = json_array_get_length(states);

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *state = json_array_get_object_element(states, i);

		const gchar *channel = json_object_get_string_member(state, "id");
		gchar *last_id = from_int(discord_get_room_last_id(da, to_int(channel)));
		guint mentions = json_object_get_int_member(state, "mention_count");

		if (mentions && channel) {
			gboolean isDM = g_hash_table_contains(da->one_to_ones, channel);

			if (isDM) {
				discord_get_history(da, channel, last_id, mentions * 2);
			} else {
				/* TODO: fetch channel history */
				DiscordChannel *dchannel = discord_get_channel_global(da, channel);
				if (dchannel != NULL) {
					purple_debug_misc("discord", "%d unhandled mentions in channel %s\n", mentions, dchannel->name);
				}
			}
		}
		
		g_free(last_id);
	}
}

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

	purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Cancelled 2FA auth"));
}

static void
discord_login_response(DiscordAccount *da, JsonNode *node, gpointer user_data)
{

	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);

		da->token = g_strdup(json_object_get_string_member(response, "token"));

		purple_account_set_string(da->account, "token", da->token);

		if (da->token) {
			discord_start_socket(da);
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
			/* Probably an error about new location */
			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "email"));
			return;
		}

		if (json_object_has_member(response, "password")) {
			/* Probably an error about bad password */
			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "password"));
			return;
		}
	}

	purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Bad username/password"));
}

void
discord_login(PurpleAccount *account)
{
	DiscordAccount *da;
	PurpleConnection *pc = purple_account_get_connection(account);
	PurpleConnectionFlags pc_flags;

	if (!strchr(purple_account_get_username(account), '@')) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, _("Username needs to be an email address"));
		return;
	}

	pc_flags = purple_connection_get_flags(pc);
	pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	purple_connection_set_flags(pc, pc_flags);

	da = g_new0(DiscordAccount, 1);
	purple_connection_set_protocol_data(pc, da);
	da->account = account;
	da->pc = pc;
	da->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	da->last_load_last_message_id = purple_account_get_int(account, "last_message_id_high", 0);

	if (da->last_load_last_message_id != 0) {
		da->last_load_last_message_id = (da->last_load_last_message_id << 32) | ((guint64) purple_account_get_int(account, "last_message_id_low", 0) & 0xFFFFFFFF);
	}
	
	da->compress = !purple_account_get_bool(account, "disable-compress", FALSE);

	da->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->last_message_id_dm = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	da->result_callbacks = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->received_message_queue = g_queue_new();

	/* TODO make these the roots of all discord data */
	da->new_users = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_user);
	da->new_guilds = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_guild);
	da->group_dms = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_channel);

	discord_build_groups_from_blist(da);

	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

	da->token = g_strdup(purple_account_get_string(account, "token", NULL));

	if (da->token) {
		discord_start_socket(da);
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

	if (!join_signal) {
		join_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-buddy-joining", purple_connection_get_protocol(pc), PURPLE_CALLBACK(discord_capture_join_part), NULL);
	}

	if (!part_signal) {
		part_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-buddy-leaving", purple_connection_get_protocol(pc), PURPLE_CALLBACK(discord_capture_join_part), NULL);
	}
}

static void
discord_close(PurpleConnection *pc)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	g_return_if_fail(da != NULL);

	if (da->heartbeat_timeout) {
		g_source_remove(da->heartbeat_timeout);
	}

	if (da->websocket != NULL) {
		purple_ssl_close(da->websocket);
		da->websocket = NULL;
	}
	if (da->zstream != NULL) {
		inflateEnd(da->zstream);
		g_free(da->zstream);
		da->zstream = NULL;
	}

	g_hash_table_unref(da->one_to_ones);
	da->one_to_ones = NULL;
	g_hash_table_unref(da->one_to_ones_rev);
	da->one_to_ones_rev = NULL;
	g_hash_table_unref(da->last_message_id_dm);
	da->last_message_id_dm = NULL;
	g_hash_table_unref(da->sent_message_ids);
	da->sent_message_ids = NULL;
	g_hash_table_unref(da->result_callbacks);
	da->result_callbacks = NULL;

	g_hash_table_unref(da->new_users);
	da->new_users = NULL;
	g_hash_table_unref(da->new_guilds);
	da->new_guilds = NULL;
	g_queue_free(da->received_message_queue);
	da->received_message_queue = NULL;

	while (da->http_conns) {
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		purple_util_fetch_url_cancel(da->http_conns->data);
#else
		purple_http_conn_cancel(da->http_conns->data);
#endif
		da->http_conns = g_slist_delete_link(da->http_conns, da->http_conns);
	}

	while (da->pending_writes) {
		json_object_unref(da->pending_writes->data);
		da->pending_writes = g_slist_delete_link(da->pending_writes, da->pending_writes);
	}

	g_hash_table_destroy(da->cookie_table);
	da->cookie_table = NULL;
	g_free(da->frame);
	da->frame = NULL;
	g_free(da->token);
	da->token = NULL;
	g_free(da->session_id);
	da->session_id = NULL;
	g_free(da->self_username);
	da->self_username = NULL;
	g_free(da);
}

/* static void discord_start_polling(DiscordAccount *ya); */

static gboolean
discord_process_frame(DiscordAccount *da, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	gint64 opcode;

	purple_debug_info("discord", "got frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame, -1, NULL)) {
		purple_debug_error("discord", "Error parsing response: %s\n", frame);
		return TRUE;
	}

	root = json_parser_get_root(parser);

	if (root != NULL) {
		JsonObject *obj = json_node_get_object(root);

		opcode = json_object_get_int_member(obj, "op");

		switch (opcode) {
		case 0: { /* Dispatch */
			const gchar *type = json_object_get_string_member(obj, "t");
			gint64 seq = json_object_get_int_member(obj, "s");

			da->seq = seq;
			discord_process_dispatch(da, type, json_object_get_object_member(obj, "d"));

			break;
		}

		case 7: { /* Reconnect */
			discord_start_socket(da);
			break;
		}

		case 9: { /* Invalid session */
			da->seq = 0;
			g_free(da->session_id);
			da->session_id = NULL;

			discord_send_auth(da);
			break;
		}

		case 10: { /* Hello */
			JsonObject *data = json_object_get_object_member(obj, "d");
			gint64 heartbeat_interval = json_object_get_int_member(data, "heartbeat_interval");
			discord_send_auth(da);

			if (da->heartbeat_timeout) {
				g_source_remove(da->heartbeat_timeout);
			}

			if (heartbeat_interval) {
				da->heartbeat_timeout = g_timeout_add(json_object_get_int_member(data, "heartbeat_interval"), discord_send_heartbeat, da);
			} else {
				da->heartbeat_timeout = 0;
			}

			break;
		}

		case 11: { /* Heartbeat ACK */
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
	int ret;

	if (data_len) {
		purple_debug_info("discord", "sending frame: %*s\n", (int) data_len, data);
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

	ret = purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
	if (ret < 0) {
		purple_debug_error("discord", "websocket sending error: %d\n", errno);
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Websocket failed to send"));
		
		// We can't just restart the socket because that would mean we lose this packet as a pending write
		//discord_start_socket(ya);
	}

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

	discord_socket_write_data(rca, (guchar *) str, len, 0);

	g_free(str);
}

static gchar *
discord_inflate(DiscordAccount *da, gchar *frame, gsize frame_len)
{
	if (!da->zstream) {
		da->zstream = g_new0(z_stream, 1);
		inflateInit2(da->zstream, MAX_WBITS + 32);
	}
	
	z_stream *zs = da->zstream;
	
	zs->next_in = (z_const Bytef*)frame;
	zs->avail_in = frame_len;
	
	int gzres = Z_DATA_ERROR;
	GString *ret = g_string_new(NULL);
	gchar decomp_buff[65535];
	gsize decomp_len;
	
	while (zs->avail_in > 0) {
		zs->next_out = (Bytef*)decomp_buff;
		zs->avail_out = sizeof(decomp_buff);
		decomp_len = zs->avail_out = sizeof(decomp_buff);
		gzres = inflate(zs, Z_SYNC_FLUSH);
		decomp_len -= zs->avail_out;
		
		if (gzres == Z_OK || gzres == Z_STREAM_END) {
			g_string_append_len(ret, decomp_buff, decomp_len);
		} else {
			break;
		}
	}
	
	if (gzres != Z_OK && gzres != Z_STREAM_END) {
		g_string_free(ret, TRUE);
		return NULL;
	}
	
	return g_string_free(ret, FALSE);
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

		while (nlbr_count < 4 && (read_len = purple_ssl_read(conn, &nextchar, 1)) == 1) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}

		if (nlbr_count == 4) {
			ya->websocket_header_received = TRUE;
			done_some_reads = TRUE;

			/* flush stuff that we attempted to send before the websocket was ready */
			while (ya->pending_writes) {
				discord_socket_write_json(ya, ya->pending_writes->data);
				ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
			}
		}
	}

	while (ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
		if (!ya->frame) {
			if (ya->packet_code != 129 && ya->packet_code != 130) {
				if (ya->packet_code == 136) {
					purple_debug_error("discord", "websocket closed\n");

					length_code = 0;
					purple_ssl_read(conn, &length_code, 1);

					if (length_code > 0 && length_code <= 125) {
						guchar error_buf[2];

						if (purple_ssl_read(conn, &error_buf, 2) == 2) {
							gint error_code = (error_buf[0] << 8) + error_buf[1];
							purple_debug_error("discord", "error code %d\n", error_code);

							if (error_code == 4004) {
								/* bad auth token, clear and reset */
								purple_account_set_string(ya->account, "token", NULL);

								purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Reauthentication required"));
								return;
							}
						}
					}

					/* Try reconnect */
					discord_start_socket(ya);

					return;
				} else if (ya->packet_code == 137) {
					/* Ping */
					gint ping_frame_len = 0;
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
					/* Ignore pong */
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
			if (ya->compress) {
				gchar *temp = discord_inflate(ya, ya->frame, ya->frame_len);
				g_free(ya->frame);
				ya->frame = temp;
			}
			
			gboolean success = discord_process_frame(ya, ya->frame);
			g_free(ya->frame);
			ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			ya->frames_since_reconnect++;

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
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Lost connection to server"));
		} else {
			/* Try reconnect */
			discord_start_socket(ya);
		}
	}
}

static void
discord_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	DiscordAccount *da = userdata;
	gchar *websocket_header;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; /* TODO don't be lazy */

	purple_ssl_input_add(da->websocket, discord_socket_got_data, da);

	websocket_header = g_strdup_printf("GET %s%s HTTP/1.1\r\n"
									   "Host: %s\r\n"
									   "Connection: Upgrade\r\n"
									   "Pragma: no-cache\r\n"
									   "Cache-Control: no-cache\r\n"
									   "Upgrade: websocket\r\n"
									   "Sec-WebSocket-Version: 13\r\n"
									   "Sec-WebSocket-Key: %s\r\n"
									   "User-Agent: " DISCORD_USERAGENT "\r\n"
									   "\r\n",
									   DISCORD_GATEWAY_SERVER_PATH, da->compress ? "&compress=zlib-stream" : "",
									   DISCORD_GATEWAY_SERVER, websocket_key);

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
		purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Couldn't connect to gateway"));
	} else {
		discord_restart_channel(da);
	}
}

static void
discord_start_socket(DiscordAccount *da)
{
	if (da->heartbeat_timeout) {
		g_source_remove(da->heartbeat_timeout);
	}

	/* Reset all the old stuff */
	if (da->websocket != NULL) {
		purple_ssl_close(da->websocket);
	}
	if (da->zstream != NULL) {
		inflateEnd(da->zstream);
		g_free(da->zstream);
		da->zstream = NULL;
	}

	da->websocket = NULL;
	da->websocket_header_received = FALSE;
	g_free(da->frame);
	da->frame = NULL;
	da->packet_code = 0;
	da->frame_len = 0;
	da->frames_since_reconnect = 0;

	da->websocket = purple_ssl_connect(da->account, DISCORD_GATEWAY_SERVER, DISCORD_GATEWAY_PORT, discord_socket_connected, discord_socket_failed, da);
}

static void
discord_chat_leave_by_room_id(PurpleConnection *pc, guint64 room_id)
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
discord_got_pinned(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	PurpleChatConversation *chatconv = user_data;
	PurpleConversation *conv = purple_conv_chat_get_conversation(chatconv);

	JsonArray *messages = json_node_get_array(node);

	int count = json_array_get_length(messages);

	if (count) {
		/* Display each message with a pinned icon through the normal channel */

		for (int i = 0; i < count; ++i) {
			JsonObject *message = json_array_get_object_element(messages, i);
			discord_process_message(da, message, DISCORD_MESSAGE_PINNED);
		}
	} else {
		/* Don't make the user think we forget about them */
		purple_conversation_write(conv, NULL, _("No pinned messages"), PURPLE_MESSAGE_SYSTEM, time(NULL));
	}
}

static void
discord_chat_pinned_by_room_id(PurpleConnection *pc, PurpleChatConversation *chatconv, guint64 room_id)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/pins", room_id);
	discord_fetch_url(da, url, NULL, discord_got_pinned, chatconv);
	g_free(url);
}

static void
discord_chat_leave(PurpleConnection *pc, int id)
{
	PurpleChatConversation *chatconv;
	/* TODO check source */
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	discord_chat_leave_by_room_id(pc, room_id);
}

static void
discord_chat_pinned(PurpleConnection *pc, int id)
{
	PurpleChatConversation *chatconv;
	/* TODO check source */
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	discord_chat_pinned_by_room_id(pc, chatconv, room_id);
}

/* Invite to a _group DM_
 * The API for inviting to a guild is different, TODO implement that one too */

static void
discord_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	DiscordAccount *ya;
	guint64 room_id;
	PurpleChatConversation *chatconv;
	DiscordUser *user;

	JsonObject *data;

	ya = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if(!room_id_ptr) {
		return;
	}

	room_id = *room_id_ptr;
	user = discord_get_user_fullname(ya, who);

	if (!user) {
		purple_debug_info("discord", "Missing user in invitation for %s", who);
		return;
	}

	data = json_object_new();
	json_object_set_string_member(data, "recipient", from_int(user->id));
	gchar *postdata = json_object_to_string(data);

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/recipients/%" G_GUINT64_FORMAT, room_id, user->id);
	discord_fetch_url_with_method(ya, "PUT", url, postdata, NULL, NULL);
	g_free(url);

	g_free(postdata);
	json_object_unref(data);

}

static void
discord_chat_nick(PurpleConnection *pc, int id, gchar *new_nick)
{
	PurpleChatConversation *chatconv;
	/* TODO check source */
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);

	if (guild != NULL) {
		JsonObject *data = json_object_new();
		json_object_set_string_member(data, "nick", new_nick);
		gchar *postdata = json_object_to_string(data);

		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/guilds/%" G_GUINT64_FORMAT "/members/@me/nick", guild->id);
		discord_fetch_url_with_method(da, "PATCH", url, postdata, NULL, NULL);

		g_free(url);
		g_free(postdata);
		json_object_unref(data);

		/* Propagate locally as well */
		const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, da->self_user_id);
		discord_got_nick_change(da, discord_get_user(da, da->self_user_id), guild, new_nick, old_nick, TRUE);
	}
}

static GList *
discord_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("ID");
	pce->identifier = "id";
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Name");
	pce->identifier = "name";
	m = g_list_append(m, pce);

	return m;
}

static gboolean
str_is_number(const gchar *str)
{
	gint i = strlen(str) - 1;

	for (; i >= 0; i--) {
		if (!g_ascii_isdigit(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static __attribute__((optimize("O0"))) GHashTable *
discord_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chatname != NULL) {
		if (str_is_number(chatname)) {
			DiscordChannel *channel = discord_get_channel_global(da, chatname);

			if (channel != NULL) {
				g_hash_table_insert(defaults, "name", g_strdup(channel->name));
			}

			g_hash_table_insert(defaults, "id", g_strdup(chatname));
		} else {
			DiscordChannel *channel = discord_get_channel_global_name(da, chatname);

			if (channel != NULL) {
				g_hash_table_insert(defaults, "name", g_strdup(channel->name));
				g_hash_table_insert(defaults, "id", from_int(channel->id));
			}
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

static void
discord_got_history_of_room(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *messages = json_node_get_array(node);
	DiscordChannel *channel = user_data;
	gint i, len = json_array_get_length(messages);
	guint64 last_message = channel->last_message_id;
	guint64 rolling_last_message_id = 0;

	/* latest are first */
	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
		guint64 id = to_int(json_object_get_string_member(message, "id"));

		if (id >= last_message) {
			break;
		}

		rolling_last_message_id = discord_process_message(da, message, DISCORD_MESSAGE_NORMAL);
	}

	if (rolling_last_message_id != 0) {
		discord_set_room_last_id(da, channel->id, rolling_last_message_id);

		if (rolling_last_message_id < last_message) {
			/* Request the next 100 messages */
			gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, channel->id, rolling_last_message_id);
			discord_fetch_url(da, url, NULL, discord_got_history_of_room, channel);
			g_free(url);
		}
	}
}

/* identical endpoint as above, but not rolling */

static void
discord_got_history_static(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *messages = json_node_get_array(node);
	gint i, len = json_array_get_length(messages);

	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);

		discord_process_message(da, message, DISCORD_MESSAGE_NORMAL);
	}
}

/* libpurple can't store a 64bit int on a 32bit machine, so convert to
 * something more usable instead (puke). also needs to work cross platform, in
 * case the accounts.xml is being shared (double puke)
 */

static guint64
discord_get_room_last_id(DiscordAccount *da, guint64 id)
{
	guint64 last_message_id = da->last_load_last_message_id;
	PurpleBlistNode *blistnode = NULL;
	gchar *channel_id = from_int(id);

	if (g_hash_table_contains(da->one_to_ones, channel_id)) {
		/* is a direct message */
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(da->account, g_hash_table_lookup(da->one_to_ones, channel_id)));
	} else {
		/* twas a group chat */
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));
	}

	if (blistnode != NULL) {
		guint64 last_room_id = purple_blist_node_get_int(blistnode, "last_message_id_high");

		if (last_room_id != 0) {
			last_room_id = (last_room_id << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_id_low") & 0xFFFFFFFF);

			last_message_id = MAX(da->last_message_id, last_room_id);
		}
	}

	g_free(channel_id);
	return last_message_id;
}

static void
discord_set_room_last_id(DiscordAccount *da, guint64 id, guint64 last_id)
{
	PurpleBlistNode *blistnode = NULL;
	gchar *channel_id = from_int(id);

	if (g_hash_table_contains(da->one_to_ones, channel_id)) {
		/* is a direct message */
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(da->account, g_hash_table_lookup(da->one_to_ones, channel_id)));
	} else {
		/* twas a group chat */
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));
	}

	if (blistnode != NULL) {
		purple_blist_node_set_int(blistnode, "last_message_id_high", last_id >> 32);
		purple_blist_node_set_int(blistnode, "last_message_id_low", last_id & 0xFFFFFFFF);
	}

	da->last_message_id = MAX(da->last_message_id, last_id);
	purple_account_set_int(da->account, "last_message_id_high", last_id >> 32);
	purple_account_set_int(da->account, "last_message_id_low", last_id & 0xFFFFFFFF);

	g_free(channel_id);
}

/* TODO: Cache better, sane defaults */

/* https://support.discordapp.com/hc/en-us/articles/206141927-How-is-the-permission-hierarchy-structured- */

static guint64
discord_permission_role(DiscordGuild *guild, guint64 r, guint64 permission)
{
	g_return_val_if_fail(guild, permission);
	
	DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, r);
	return role ? (permission | role->permissions) : permission;
}

static guint64
discord_permission_role_override(DiscordChannel *channel, guint64 role, guint64 permission)
{
	DiscordPermissionOverride *ro =
	  g_hash_table_lookup_int64(channel->permission_role_overrides, role);

	return ro ? ((permission & ~(ro->deny)) | ro->allow) : permission;
}

static guint64
discord_compute_permission(DiscordAccount *da, DiscordUser *user, DiscordChannel *channel)
{
	g_return_val_if_fail(channel && user, 0);
	
	guint64 uid = user->id;
	guint64 permissions = 0;

	DiscordGuildMembership *guild_membership = g_hash_table_lookup_int64(user->guild_memberships, channel->guild_id);

	if (guild_membership) {
		/* Should always exist, but just in case... */

		DiscordGuild *guild = discord_get_guild(da, channel->guild_id);

		/* @everyone */
		permissions = discord_permission_role(guild, channel->guild_id, permissions);

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 r = g_array_index(guild_membership->roles, guint64, i);
			permissions = discord_permission_role(guild, r, permissions);
		}

		permissions = discord_permission_role_override(channel, channel->guild_id, permissions);

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 role = g_array_index(guild_membership->roles, guint64, i);
			permissions = discord_permission_role_override(channel, role, permissions);
		}
	}

	/* Check special permission overrides just for us */

	DiscordPermissionOverride *uo =
	  g_hash_table_lookup_int64(channel->permission_user_overrides, uid);

	if (uo) {
		permissions = (permissions & ~(uo->deny)) | uo->allow;
	}

	return permissions;
}

static void discord_join_chat(PurpleConnection *pc, GHashTable *chatdata);

static void
discord_got_channel_info(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *channel = json_node_get_object(node);
	const gchar *id = json_object_get_string_member(channel, "id");

	PurpleChatConversation *chatconv;

	if (id == NULL) {
		/* No permissions?  Should be an error message in json_object_get_string_member(channel, "message") */
		return;
	}

	guint64 tmp = to_int(id);
	chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(tmp));

	if (chatconv == NULL) {
		return;
	}

	if (json_object_has_member(channel, "topic")) {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "topic"));
	} else {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "name"));
	}

	if (json_object_has_member(channel, "recipients")) {
		// This is a Group DM
		JsonArray *recipients = json_object_get_array_member(channel, "recipients");
		gint i;
		guint len = json_array_get_length(recipients);
		GList *users = NULL, *flags = NULL;

		for (i = len - 1; i >= 0; i--) {
			JsonObject *recipient = json_array_get_object_element(recipients, i);
			DiscordUser *user = discord_upsert_user(da->new_users, recipient);
			gchar *fullname = discord_create_fullname(user);

			if (fullname != NULL) {
				users = g_list_prepend(users, fullname);
				flags = g_list_prepend(flags, PURPLE_CHAT_USER_NONE);
			}
		}

		// Add self
		users = g_list_prepend(users, g_strdup(da->self_username));
		flags = g_list_prepend(flags, PURPLE_CHAT_USER_NONE);

		purple_chat_conversation_clear_users(chatconv);
		purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);

		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}

		g_list_free(flags);
	} else if (json_object_has_member(channel, "permission_overwrites")) {
		// This is a guild/server room
		DiscordGuild *guild = discord_get_guild(da, to_int(json_object_get_string_member(channel, "guild_id")));

		PurpleChatConversation *chat = chatconv;
		GList *users = NULL, *flags = NULL;
		DiscordChannel *chnl = discord_get_channel_global_int(da, tmp);
		
		for (guint i = 0; guild && i < guild->members->len; i++) {
			DiscordUser *user = discord_get_user(da, g_array_index(guild->members, guint64, i));
			
			if (!user) {
				continue;
			}
			
			/* Ensure that we actually have permissions for this channel */
			guint64 permission = discord_compute_permission(da, user, chnl);

			/* must have READ_MESSAGES */
			if ((permission & 0x400)) {
				PurpleChatUserFlags cbflags = discord_get_user_flags(da, guild, user);
				gchar *nickname = discord_create_nickname(user, guild);

				if (nickname != NULL && user->status != USER_OFFLINE) {
					users = g_list_prepend(users, nickname);
					flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
				}
			}
		}

		if (users != NULL) {
			purple_chat_conversation_clear_users(chat);
			purple_chat_conversation_add_users(chat, users, NULL, flags, FALSE);
		}

		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}

		g_list_free(flags);
	}
}

static DiscordChannel *
discord_open_chat(DiscordAccount *da, guint64 id, gboolean present)
{
	PurpleChatConversation *chatconv = NULL;

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, id, &guild);

	if (channel == NULL) {
		return NULL;
	}

	if (channel->type == CHANNEL_VOICE) {
		purple_notify_error(da, _("Bad channel type"), _("Cannot join a voice channel as text"), "", purple_request_cpar_from_connection(da->pc));
		return NULL;
	}

	gchar *id_str = from_int(id);
	chatconv = purple_conversations_find_chat_with_account(id_str, da->account);

	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		g_free(id_str);

		if (present) {
			purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		}

		return NULL;
	}

	chatconv = purple_serv_got_joined_chat(da->pc, discord_chat_hash(id), id_str);
	g_free(id_str);

	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_memdup(&(id), sizeof(guint64)));

	purple_conversation_present(PURPLE_CONVERSATION(chatconv));

	/* Get info about the channel */
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT, id);
	discord_fetch_url(da, url, NULL, discord_got_channel_info, channel);
	g_free(url);
	
	if (guild != NULL) {
		gchar *name = discord_create_nickname_from_id(da, guild, da->self_user_id);
		purple_chat_conversation_set_nick(chatconv, name);
		g_free(name);
	}

	return channel;
}

static void
discord_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	guint64 id = to_int(g_hash_table_lookup(chatdata, "id"));

	DiscordChannel *channel = discord_open_chat(da, id, TRUE);

	if (!channel) {
		return;
	}

	/* Get any missing messages */
	guint64 last_message_id = discord_get_room_last_id(da, id);

	if (last_message_id != 0 && channel->last_message_id > last_message_id) {
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, id, last_message_id);
		discord_fetch_url(da, url, NULL, discord_got_history_of_room, channel);
		g_free(url);
	}
}

static void
discord_mark_room_messages_read(DiscordAccount *da, guint64 channel_id)
{
	if (!channel_id) {
		return;
	}

	DiscordChannel *channel = discord_get_channel_global_int(da, channel_id);

	guint64 last_message_id;

	if (channel) {
		last_message_id = channel->last_message_id;
	} else {
		gchar *channel = from_int(channel_id);
		gchar *msg = g_hash_table_lookup(da->last_message_id_dm, channel);
		g_free(channel);

		if (msg) {
			last_message_id = to_int(msg);
		} else {
			purple_debug_info("discord", "Unknown acked channel %" G_GUINT64_FORMAT, channel_id);
			return;
		}
	}

	if (last_message_id == 0) {
		purple_debug_info("discord", "Won't ack message ID == 0");
	}

	guint64 known_message_id = discord_get_room_last_id(da, channel_id);

	if (last_message_id == known_message_id) {
		/* Up to date */
		return;
	}

	last_message_id = MAX(last_message_id, known_message_id);
	
	discord_set_room_last_id(da, channel_id, last_message_id);

	gchar *url;

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages/%" G_GUINT64_FORMAT "/ack", channel_id, last_message_id);
	discord_fetch_url(da, url, "{\"token\":null}", NULL, NULL);
	g_free(url);
}

static void
discord_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
	PurpleConnection *pc;
	DiscordAccount *ya;

	if (type != PURPLE_CONVERSATION_UPDATE_UNSEEN) {
		return;
	}

	pc = purple_conversation_get_connection(conv);

	if (!PURPLE_CONNECTION_IS_CONNECTED(pc)) {
		return;
	}

	if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), DISCORD_PLUGIN_ID)) {
		return;
	}

	ya = purple_connection_get_protocol_data(pc);

	guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");
	guint64 room_id = 0;

	if (room_id_ptr) {
		room_id = *room_id_ptr;
	} else {
		room_id = to_int(g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv)));
	}

	if (room_id != 0) {
		discord_mark_room_messages_read(ya, room_id);
	}
	
}

static guint
discord_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, DiscordAccount *ya)
{
	PurpleConnection *pc;
	gchar *url;

	if (state != PURPLE_IM_TYPING) {
		return 0;
	}

	pc = ya ? ya->pc : purple_conversation_get_connection(conv);

	if (!PURPLE_CONNECTION_IS_CONNECTED(pc)) {
		return 0;
	}

	if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), DISCORD_PLUGIN_ID)) {
		return 0;
	}

	if (ya == NULL) {
		ya = purple_connection_get_protocol_data(pc);
	}

	guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");
	guint64 room_id = 0;

	if (room_id_ptr) {
		room_id = *room_id_ptr;
	} else {
		room_id = to_int(g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv)));
	}
	
	if (room_id == 0) {
		return 0;
	}

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/typing", room_id);
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

static gboolean
discord_replace_natural_emoji(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordGuild *guild = user_data;
	gchar *emoji = g_match_info_fetch(match, 1);

	gchar *emoji_id = g_hash_table_lookup(guild->emojis, emoji);

	if (emoji_id) {
		g_string_append_printf(result, "&lt;:%s:%s&gt;", emoji, emoji_id);
	} else {
		g_string_append_printf(result, ":%s:", emoji);
	}

	g_free(emoji);

	return FALSE;
}

static gint
discord_conversation_send_message(DiscordAccount *da, guint64 room_id, const gchar *message)
{
	JsonObject *data = json_object_new();
	gchar *url;
	gchar *postdata;
	gchar *nonce;
	gchar *marked;
	gchar *stripped;
	gchar *final;
	gint final_len;

	nonce = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());
	g_hash_table_insert(da->sent_message_ids, nonce, nonce);

	/* Convert to Discord-flavour markdown */
	marked = markdown_html_to_markdown(markdown_escape_md(message, TRUE));
	stripped = g_strstrip(purple_markup_strip_html(marked));

	/* translate Discord-formatted actions into *markdown* syntax */
	if (purple_message_meify(stripped, -1)) {
		final = g_strdup_printf("_%s_", stripped);
	} else {
		final = g_strdup(stripped);
	}
	
	final_len = strlen(final);
	if (final_len <= 2000) {
		json_object_set_string_member(data, "content", final);
		json_object_set_string_member(data, "nonce", nonce);
		json_object_set_boolean_member(data, "tts", FALSE);

		url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages", room_id);
		postdata = json_object_to_string(data);

		discord_fetch_url(da, url, postdata, NULL, NULL);
		
		g_free(postdata);
		g_free(url);
	}

	g_free(marked);
	g_free(stripped);
	g_free(final);
	json_object_unref(data);

	if (final_len > 2000) {
		return -E2BIG;
	}
	
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
	PurpleChatConversation *chatconv;
	gint ret;

	da = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	g_return_val_if_fail(room_id_ptr, -1);
	guint64 room_id = *room_id_ptr;

	gchar *d_message = g_strdup(message);

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);
	
	d_message = discord_make_mentions(da, guild, d_message);

	if(guild) {
		g_return_val_if_fail(guild, -1);

		gchar *tmp = g_regex_replace_eval(emoji_natural_regex, d_message, -1, 0, 0, discord_replace_natural_emoji, guild, NULL);

		if (tmp != NULL) {
			g_free(d_message);
			d_message = tmp;
		}
	}

	g_return_val_if_fail(discord_get_channel_global_int(da, room_id), -1); /* TODO rejoin room? */
	ret = discord_conversation_send_message(da, room_id, d_message);

	if (ret > 0) {
		gchar *tmp = g_regex_replace_eval(emoji_regex, d_message, -1, 0, 0, discord_replace_emoji, da, NULL);

		if (tmp != NULL) {
			g_free(d_message);
			d_message = tmp;
		}

		d_message = discord_replace_mentions_bare(da, guild, d_message);

		gchar *name = discord_create_nickname_from_id(da, guild, da->self_user_id);
		purple_serv_got_chat_in(pc, discord_chat_hash(room_id), name, PURPLE_MESSAGE_SEND, d_message, time(NULL));
		g_free(name);
	}

	g_free(d_message);
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
	
	if (json_object_get_int_member(result, "code") == 50007) {
		purple_conversation_present_error(who, da->account, _("Could not send message to this user"));
		purple_message_destroy(msg);
		return;
	}
	
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

	if (room_id != NULL) {
		discord_conversation_send_message(da, to_int(room_id), message);
	} else {
		purple_conversation_present_error(who, da->account, _("Invalid channel for this user"));
	}
	
	purple_message_destroy(msg);
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

	/* Create DM if there isn't one */
	if (room_id == NULL) {
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
		DiscordUser *user = discord_get_user_fullname(da, who);

		if (user) {
			JsonObject *data = json_object_new();
			json_object_set_int_member(data, "recipient_id", user->id);
			gchar *postdata = json_object_to_string(data);

			discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/users/@me/channels", postdata, discord_created_direct_message_send, msg);

			g_free(postdata);
			json_object_unref(data);

			return 1;
		}

#if !PURPLE_VERSION_CHECK(3, 0, 0)
		purple_message_destroy(msg);
#endif
		purple_conversation_present_error(who, da->account, _("Cannot send a message to someone who is not on your friend list."));
		return -1;
	}

	return discord_conversation_send_message(da, to_int(room_id), message);
}

static void
discord_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	/* PATCH https:// DISCORD_API_SERVER /api/v6/channels/%s channel */
	/*{ "name" : "test", "position" : 1, "topic" : "new topic", "bitrate" : 64000, "user_limit" : 0 } */
}

static void
discord_got_avatar(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordUser *user = user_data;
	gchar *username = discord_create_fullname(user);

	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;

		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup(response_str, response_len);

		if (user->id == da->self_user_id) {
			purple_buddy_icons_set_account_icon(da->account, response_dup, response_len);
			purple_account_set_string(da->account, "avatar_checksum", user->avatar);
		} else {
			purple_buddy_icons_set_for_user(da->account, username, response_dup, response_len, user->avatar);
		}
	}
	
	g_free(username);
}

static void
discord_get_avatar(DiscordAccount *da, DiscordUser *user, gboolean is_buddy)
{
	if (!user || !user->avatar) {
		return;
	}

	/* libpurple only manages checksums for buddies. If we're fetching our
	 * own icon, we need to use our own store */

	const gchar *checksum = NULL;

	if (is_buddy) {
		gchar *username = discord_create_fullname(user);
		checksum = purple_buddy_icons_get_checksum_for_user(purple_blist_find_buddy(da->account, username));
		g_free(username);
	} else if (user->id == da->self_user_id) {
		checksum = purple_account_get_string(da->account, "avatar_checksum", "");
	} 

	if (checksum && *checksum) {
		/* There is a checksum, so make sure we match */

		if (purple_strequal(checksum, user->avatar)) {
			return;
		}
	}

	/* Construct the URL for the desired avatar. Specifically select png to
	 * avoid being returned animated gifs, which are a bandwidth hog in
	 * Pidgin (which ignores the animation) and a CPU hog in other clients
	 * (which animate). Either way, given that Discord does transcoding
	 * anyway, we specifically request the png version, for the best
	 * balance of quality and non-animated-ness */

	GString *url = g_string_new("https://cdn.discordapp.com/avatars/");
	g_string_append_printf(url, "%" G_GUINT64_FORMAT, user->id);
	g_string_append_c(url, '/');
	g_string_append_printf(url, "%s.png", purple_url_encode(user->avatar));

	discord_fetch_url(da, url->str, NULL, discord_got_avatar, user);

	g_string_free(url, TRUE);
}

static void
discord_add_buddy_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *response = json_node_get_object(node);
	PurpleBuddy *buddy = user_data;
	
	if (json_object_get_int_member(response, "code") == 80004) {
		gchar *message = g_strdup_printf(_("No users with tag %s exist"), purple_buddy_get_name(buddy));
		purple_notify_error(da, _("Unknown user"), message, "", purple_request_cpar_from_connection(da->pc));
		g_free(message);
		
		purple_blist_remove_buddy(buddy);
	}
}

static void
discord_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
				  ,
				  const char *message
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
	json_object_set_string_member(data, "username", g_strstrip(usersplit[0]));
	json_object_set_string_member(data, "discriminator", g_strstrip(usersplit[1]));

	postdata = json_object_to_string(data);

	discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships", postdata, discord_add_buddy_cb, buddy);

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
	DiscordUser *user = discord_get_user_fullname(da, buddy_name);

	if (!user) {
		return;
	}

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);
}

static void
discord_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	/* Do nothing to stop the remove+add behaviour */
}

static void
discord_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	/* Do nothing to stop the remove+add behaviour */
}

static void
discord_got_info(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordUser *user = user_data;

	PurpleNotifyUserInfo *user_info;
	JsonObject *info = json_node_get_object(node);
	JsonArray *connected_accounts = json_object_get_array_member(info, "connected_accounts");
	JsonArray *mutual_guilds = json_object_get_array_member(info, "mutual_guilds");
	gint i;

	user_info = purple_notify_user_info_new();

	gchar *id_str = from_int(user->id);
	purple_notify_user_info_add_pair_html(user_info, _("ID"), id_str);
	g_free(id_str);
	
	purple_notify_user_info_add_pair_html(user_info, _("Username"), user->name);

	/* Display other non-profile info that we know about this buddy */
	gchar *status_strings[4] = {
		_("Online"),
		_("Idle"),
		_("Offline"),
		_("Do Not Disturb")
	};

	purple_notify_user_info_add_pair_html(user_info, _("Status"), status_strings[user->status]);

	if (user->game != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Playing"), user->game);
	}

	if (json_array_get_length(connected_accounts)) {
		purple_notify_user_info_add_section_break(user_info);
		purple_notify_user_info_add_pair_html(user_info, _("Connected Accounts"), NULL);
	}

	for (i = json_array_get_length(connected_accounts) - 1; i >= 0; i--) {
		JsonObject *account = json_array_get_object_element(connected_accounts, i);
		const gchar *type = json_object_get_string_member(account, "type");
		const gchar *name = json_object_get_string_member(account, "name");

		/* const gchar *id = json_object_get_string_member(account, "id"); */
		/* TODO href link to account? */

		purple_notify_user_info_add_pair_html(user_info, type, name);
	}

	if (json_array_get_length(mutual_guilds)) {
		purple_notify_user_info_add_section_break(user_info);
		purple_notify_user_info_add_pair_html(user_info, _("Mutual Servers"), NULL);
	}

	for (i = json_array_get_length(mutual_guilds) - 1; i >= 0; i--) {
		JsonObject *guild_o = json_array_get_object_element(mutual_guilds, i);
		guint64 id = to_int(json_object_get_string_member(guild_o, "id"));

		DiscordGuild *guild = discord_get_guild(da, id);
		DiscordGuildMembership *membership = g_hash_table_lookup_int64(user->guild_memberships, id);

		if (membership && guild) {
			gchar *name = membership->nick;
			if (!name || !strlen(name)) {
				name = user->name;
			}

			GString *role_str = g_string_new(name);

			for (guint i = 0; i < membership->roles->len; i++) {
				guint64 role_id = g_array_index(membership->roles, guint64, i);
				DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, role_id);

				if (role) {
					g_string_append_printf(role_str, " [" COLOR_START "%s" COLOR_END "]", role->color, role->name);
				}
			}

			purple_notify_user_info_add_pair_html(user_info, guild->name, g_string_free(role_str, FALSE));
		}
	}

	gchar *username = discord_create_fullname(user);
	purple_notify_userinfo(da->pc, username, user_info, NULL, NULL);
	g_free(username);
}

static void
discord_get_info(PurpleConnection *pc, const gchar *username)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *url;
	DiscordUser *user = discord_get_user_fullname(da, username);

	if (!user) {
		return;
	}

	/* TODO string format fix */
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/%" G_GUINT64_FORMAT "/profile", user->id);
	discord_fetch_url(da, url, NULL, discord_got_info, user);
	g_free(url);
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
	gboolean use_status_as_game = purple_account_get_bool(account, "use-status-as-game", FALSE);

	/* We can only set statuses without in-game info */
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "set-online", _("Online"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "set-idle", _("Idle"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, "set-dnd", _("Do Not Disturb"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, "set-invisible", _("Invisible"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "set-offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	/* Other people can have an in-game display */
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "idle", _("Idle"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "dnd", _("Do Not Disturb"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, FALSE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	return types;
}

static gchar *
discord_status_text(PurpleBuddy *buddy)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (purple_account_is_connected(account)) {
		PurpleConnection *pc = purple_account_get_connection(account);
		DiscordAccount *da = purple_connection_get_protocol_data(pc);
		DiscordUser *user = discord_get_user_fullname(da, purple_buddy_get_name(buddy));

		if (user == NULL || user->game == NULL) {
			return NULL;
		}

		return g_markup_printf_escaped(_("Playing %s"), user->game);
	}

	return NULL;
}

static void
discord_block_user(PurpleConnection *pc, const char *who)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *url;
	DiscordUser *user = discord_get_user_fullname(da, who);

	if (!user) {
		return;
	}

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "PUT", url, "{\"type\":2}", NULL, NULL);
	g_free(url);
}

static void
discord_unblock_user(PurpleConnection *pc, const char *who)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *url;
	DiscordUser *user = discord_get_user_fullname(da, who);

	if (!user) {
		return;
	}

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);
}

const gchar *
discord_list_emblem(PurpleBuddy *buddy)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (purple_account_is_connected(account)) {
		PurpleConnection *pc = purple_account_get_connection(account);
		DiscordAccount *da = purple_connection_get_protocol_data(pc);
		DiscordUser *user = discord_get_user_fullname(da, purple_buddy_get_name(buddy));

		if (user != NULL) {
			if (user->game != NULL) {
				return "game";
			} else if (user->bot) {
				return "bot";
			}
		}
	}

	return NULL;
}

void
discord_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurplePresence *presence = purple_buddy_get_presence(buddy);
	PurpleStatus *status = purple_presence_get_active_status(presence);
	const gchar *message = purple_status_get_attr_string(status, "message");

	purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));

	if (message != NULL) {
		gchar *escaped = g_markup_printf_escaped("%s", message);

		purple_notify_user_info_add_pair_html(user_info, _("Playing"), escaped);

		g_free(escaped);
	}
}

static GHashTable *
discord_get_account_text_table(PurpleAccount *unused)
{
	GHashTable *table;

	table = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(table, "login_label", (gpointer) _("Email address..."));

	return table;
}

static GList *
discord_add_account_options(GList *account_options)
{
	PurpleAccountOption *option;

	option = purple_account_option_bool_new(_("Use status message as in-game info"), "use-status-as-game", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Auto-create rooms on buddy list"), "populate-blist", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_int_new(_("Number of users in a large channel"), "large-channel-count", 20);
	account_options = g_list_append(account_options, option);

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
	} else {
		invite_code += 1;
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
						 _("_Join"), G_CALLBACK(discord_join_server_text),
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
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_leave(pc, id);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_pinned(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_pinned(pc, id);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_nick(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_nick(pc, id, args[0]);

	return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{

	channel_mentions_regex = g_regex_new("&lt;#(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	role_mentions_regex = g_regex_new("&lt;@&amp;(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	emoji_regex = g_regex_new("&lt;a?:([^:]+):(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	emoji_natural_regex = g_regex_new(":([^:]+):", G_REGEX_OPTIMIZE, 0, NULL);
	action_star_regex = g_regex_new("^_([^\\*]+)_$", G_REGEX_OPTIMIZE, 0, NULL);
	mention_regex = g_regex_new("&lt;@!?(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	natural_mention_regex = g_regex_new("^([^:]+): ", G_REGEX_OPTIMIZE, 0, NULL);
	discord_mention_regex = g_regex_new("(?:^|\\s)@([^\\s@]+)\b", G_REGEX_OPTIMIZE, 0, NULL);

	purple_cmd_register("nick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
															PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_nick,
						_("nick <new nickname>:  Changes nickname on a server"), NULL);

#if 0
	purple_cmd_register("kick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
	PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
	DISCORD_PLUGIN_ID, discord_slash_command,
	_("kick <username>:  Remove someone from channel"), NULL);
#endif

	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
															PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_leave,
						_("leave:  Leave the channel"), NULL);

	purple_cmd_register("part", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
														   PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_leave,
						_("part:  Leave the channel"), NULL);

	purple_cmd_register("pinned", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
														   PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_pinned,
						_("pinned:  Display pinned messages"), NULL);



#if 0
	purple_cmd_register("mute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
	PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
	DISCORD_PLUGIN_ID, discord_slash_command,
	_("mute <username>:  Mute someone in channel"), NULL);

	purple_cmd_register("unmute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
	PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
	DISCORD_PLUGIN_ID, discord_slash_command,
	_("unmute <username>:  Un-mute someone in channel"), NULL);

	purple_cmd_register("topic", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
	PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
	DISCORD_PLUGIN_ID, discord_slash_command,
	_("topic <description>:  Set the channel topic description"), NULL);
#endif

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	g_regex_unref(channel_mentions_regex);
	g_regex_unref(role_mentions_regex);
	g_regex_unref(emoji_regex);
	g_regex_unref(emoji_natural_regex);
	g_regex_unref(action_star_regex);
	g_regex_unref(mention_regex);
	g_regex_unref(natural_mention_regex);
	g_regex_unref(discord_mention_regex);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
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

#ifdef ENABLE_NLS
	bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

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
/* prpl_info->add_buddy_with_invite = discord_add_buddy_with_invite; */
#endif

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
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
	prpl_info->tooltip_text = discord_tooltip_text;
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
	prpl_info->find_blist_chat = discord_find_chat;
	prpl_info->chat_invite = discord_chat_invite;
	prpl_info->chat_send = discord_chat_send;
	prpl_info->set_chat_topic = discord_chat_set_topic;
	prpl_info->get_cb_real_name = discord_get_real_name;
	prpl_info->add_buddy = discord_add_buddy;
	prpl_info->remove_buddy = discord_buddy_remove;
	prpl_info->group_buddy = discord_fake_group_buddy;
	prpl_info->rename_group = discord_fake_group_rename;
	prpl_info->get_info = discord_get_info;
	prpl_info->add_deny = discord_block_user;
	prpl_info->rem_deny = discord_unblock_user;

	prpl_info->roomlist_get_list = discord_roomlist_get_list;
	prpl_info->roomlist_room_serialize = discord_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	DISCORD_PLUGIN_ID,				/* id */
	"Discord",						/* name */
	DISCORD_PLUGIN_VERSION,			/* version */
	"",								/* summary */
	"",								/* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	DISCORD_PLUGIN_WEBSITE,			/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	discord_actions,				/* actions */
	NULL,							/* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(discord, plugin_init, info);

#else
/* Purple 3 plugin load functions */

gssize
discord_get_max_message_size(PurpleConversation *conv)
{
	return 2000;
}

G_MODULE_EXPORT GType discord_protocol_get_type(void);
#define DISCORD_TYPE_PROTOCOL (discord_protocol_get_type())
#define DISCORD_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), DISCORD_TYPE_PROTOCOL, DiscordProtocol))
#define DISCORD_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), DISCORD_TYPE_PROTOCOL, DiscordProtocolClass))
#define DISCORD_IS_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), DISCORD_TYPE_PROTOCOL))
#define DISCORD_IS_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), DISCORD_TYPE_PROTOCOL))
#define DISCORD_PROTOCOL_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), DISCORD_TYPE_PROTOCOL, DiscordProtocolClass))

typedef struct _DiscordProtocol {
	PurpleProtocol parent;
} DiscordProtocol;

typedef struct _DiscordProtocolClass {
	PurpleProtocolClass parent_class;
} DiscordProtocolClass;

static void
discord_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = DISCORD_PLUGIN_ID;
	info->name = "Discord";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
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
	prpl_info->get_user_real_name = discord_get_real_name;
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
	prpl_info->get_info = discord_get_info;
}

static void
discord_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_account_text_table = discord_get_account_text_table;
	prpl_info->status_text = discord_status_text;
	prpl_info->get_actions = discord_actions;
	prpl_info->list_emblem = discord_list_emblem;
	prpl_info->tooltip_text = discord_tooltip_text;
	prpl_info->find_blist_chat = discord_find_chat;
	prpl_info->get_max_message_size = discord_get_max_message_size;
}

static void
discord_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	prpl_info->add_deny = discord_block_user;
	prpl_info->rem_deny = discord_unblock_user;
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
								  
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
									  discord_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
									  discord_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	discord_protocol_register_type(plugin);
	discord_protocol = purple_protocols_add(DISCORD_TYPE_PROTOCOL, error);

	if (!discord_protocol) {
		return FALSE;
	}

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error)) {
		return FALSE;
	}

	if (!purple_protocols_remove(discord_protocol, error)) {
		return FALSE;
	}

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
#ifdef ENABLE_NLS
	bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif
	
	return purple_plugin_info_new(
	  "id", DISCORD_PLUGIN_ID,
	  "name", "Discord",
	  "version", DISCORD_PLUGIN_VERSION,
	  "category", _("Protocol"),
	  "summary", _("Discord Protocol Plugins."),
	  "description", _("Adds Discord protocol support to libpurple."),
	  "website", DISCORD_PLUGIN_WEBSITE,
	  "abi-version", PURPLE_ABI_VERSION,
	  "flags", PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
				 PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
	  NULL);
}

PURPLE_PLUGIN_INIT(discord, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
