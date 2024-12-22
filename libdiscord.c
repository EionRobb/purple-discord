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
#include <time.h>
#include <math.h>
#ifdef __GNUC__
#include <unistd.h>
#endif
#include <errno.h>
#include <assert.h>

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

// Prevent segfault in libpurple ssl plugins
#define purple_ssl_read(a, b, c)  ((a) && (a)->private_data ? purple_ssl_read((a), (b), (c)) : 0)

#define DISCORD_PLUGIN_ID "prpl-eionrobb-discord"
#ifndef DISCORD_PLUGIN_VERSION
#define DISCORD_PLUGIN_VERSION "1.0"
#endif
#define DISCORD_PLUGIN_WEBSITE "https://github.com/EionRobb/purple-discord"

#define DISCORD_USERAGENT_VERSION "126.0.0.0"
#define DISCORD_USERAGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" DISCORD_USERAGENT_VERSION " Safari/537.36"

#define DISCORD_BUFFER_DEFAULT_SIZE 40960

#define DISCORD_API_SERVER "discord.com"
#define DISCORD_GATEWAY_SERVER "gateway.discord.gg"
#define DISCORD_GATEWAY_PORT 443
#define DISCORD_GATEWAY_SERVER_PATH "/?encoding=json&v=10"
#define DISCORD_API_VERSION "v10"
#define DISCORD_CDN_SERVER "cdn.discordapp.com"

#ifdef USE_QRCODE_AUTH
#define DISCORD_QRCODE_AUTH_SERVER "remote-auth-gateway.discord.gg"
#define DISCORD_QRCODE_AUTH_SERVER_PORT 443
#define DISCORD_QRCODE_AUTH_SERVER_PATH "/?v=2"
#endif

#define DISCORD_EPOCH_MS 1420070400000

#define DISCORD_MAX_LARGE_THRESHOLD 250

#define DISCORD_MESSAGE_NORMAL (0)
#define DISCORD_MESSAGE_EDITED (1)
#define DISCORD_MESSAGE_PINNED (2)

#define DISCORD_GUILD_SIZE_DEFAULT (0)
#define DISCORD_GUILD_SIZE_LARGE (1)
#define DISCORD_GUILD_SIZE_SMALL (2)

#define IGNORE_PRINTS

static GRegex *channel_mentions_regex = NULL;
static GRegex *role_mentions_regex = NULL;
static GRegex *emoji_regex = NULL;
static GRegex *emoji_natural_regex = NULL;
static GRegex *action_star_regex = NULL;
static GRegex *mention_regex = NULL;
static GRegex *natural_mention_regex = NULL;
static GRegex *discord_mention_regex = NULL;
static GRegex *discord_spaced_mention_regex = NULL;

/*
 	xRateAllowedPerSecond = (int)( (double)xrateRemaining / (double)xrateResetAfter );
	xRateAllowedRemaining = xRateAllowedPerSecond;
	xRateDelayPerRequest =  (int)((1.0 / (double)xRateAllowedPerSecond) * 1000.0);
 */

const int init_xrateLimit=40;
const int init_xrateRemaining=10;
const double init_xrateReset=55;
const double init_xrateResetAfter=1;
const int init_xRateAllowedPerSecond=15;
const int init_xRateDelayPerRequest=(int)((1.0 / (double)init_xRateAllowedPerSecond) * 1000.0);
const int init_xRateAllowedRemaining=10;

static int xrateLimit=init_xrateLimit;
static int xrateRemaining=init_xrateRemaining;
static double xrateReset=init_xrateReset;
static double xrateResetAfter=init_xrateResetAfter;
static int xRateAllowedPerSecond=init_xRateAllowedPerSecond;
static int xRateDelayPerRequest=init_xRateDelayPerRequest;
static int xRateAllowedRemaining=init_xRateAllowedRemaining;

static int getJitteredDelay(int delay) {
	return (g_random_int() % delay) + delay;
}
static int getJitteredDelayGlobal(void) {
	return getJitteredDelay(xRateDelayPerRequest);
}

typedef enum {
	OP_DISPATCH = 0,
	OP_HEARTBEAT = 1,
	OP_IDENTIFY = 2,
	OP_PRESENCE_UPDATE = 3,
	OP_VOICE_STATE_UPDATE = 4,
	OP_VOICE_SERVER_PING = 5,
	OP_RESUME = 6,
	OP_RECONNECT = 7,
	OP_REQUEST_GUILD_MEMBERS = 8,
	OP_INVALID_SESSION = 9,
	OP_HELLO = 10,
	OP_HEARTBEAT_ACK = 11,
	OP_DM_UPDATE = 13,
	OP_GUILD_SYNC = 12,
	OP_LAZY_GUILD_REQUEST = 14,
	OP_LOBBY_CONNECT = 15,
	OP_LOBBY_DISCONNECT = 16,
	OP_LOBBY_VOICE_STATES_UPDATE = 17,
	OP_STREAM_CREATE = 18,
	OP_STREAM_DELETE = 19,
	OP_STREAM_WATCH = 20,
	OP_STREAM_PING = 21,
	OP_STREAM_SET_PAUSED = 22,
	OP_REQUEST_APPLICATION_COMMANDS = 24,
} DiscordOpCode;

typedef enum {
	USER_ONLINE,
	USER_IDLE,
	USER_OFFLINE,
	USER_DND,
	USER_MOBILE
} DiscordStatus;

typedef enum {
	RELATIONSHIP_FRIEND = 1,
	RELATIONSHIP_BLOCKED = 2,
	RELATIONSHIP_PENDING_INCOMING = 3,
	RELATIONSHIP_PENDING_OUTGOING = 4,
} DiscordRelationshipType;

typedef enum {
	CHANNEL_GUILD_TEXT = 0,
	CHANNEL_DM = 1,
	CHANNEL_VOICE = 2,
	CHANNEL_GROUP_DM = 3,
	CHANNEL_GUILD_CATEGORY = 4,
	CHANNEL_GUILD_NEWS = 5,
	CHANNEL_GUILD_STORE = 6,
	CHANNEL_GUILD_NEWS_THREAD = 10,
	CHANNEL_GUILD_PUBLIC_THREAD = 11,
	CHANNEL_GUILD_PRIVATE_THREAD = 12,
	CHANNEL_GUILD_STAGE_VOICE = 13,
	CHANNEL_GUILD_DIRECTORY = 14,
	CHANNEL_GUILD_FORUM = 15,
} DiscordChannelType;

typedef enum {
	MESSAGE_DEFAULT = 0,
	MESSAGE_RECIPIENT_ADD = 1,
	MESSAGE_RECIPIENT_REMOVE = 2,
	MESSAGE_CALL = 3,
	MESSAGE_CHANNEL_NAME_CHANGE = 4,
	MESSAGE_CHANNEL_ICON_CHANGE = 5,
	MESSAGE_CHANNEL_PINNED_MESSAGE = 6,
	MESSAGE_GUILD_MEMBER_JOIN = 7,
	MESSAGE_GUILD_BOOST = 8,
	MESSAGE_GUILD_BOOST_TIER_1 = 9,
	MESSAGE_GUILD_BOOST_TIER_2 = 10,
	MESSAGE_GUILD_BOOST_TIER_3 = 11,
	MESSAGE_CHANNEL_FOLLOW_ADD = 12,
	MESSAGE_GUILD_DISCOVERY_DISQUALIFIED = 14,
	MESSAGE_GUILD_DISCOVERY_REQUALIFIED = 15,
	MESSAGE_GUILD_DISCOVERY_GRACE_PERIOD_INITIAL_WARNING = 16,
	MESSAGE_GUILD_DISCOVERY_GRACE_PERIOD_FINAL_WARNING = 17,
	MESSAGE_THREAD_CREATED = 18,
	MESSAGE_REPLY = 19,
	MESSAGE_CHAT_INPUT_COMMAND = 20,
	MESSAGE_THREAD_STARTER_MESSAGE = 21,
	MESSAGE_GUILD_INVITE_REMINDER = 22,
	MESSAGE_CONTEXT_MENU_COMMAND = 23,
	MESSAGE_AUTO_MODERATION_ACTION = 24,
} DiscordMessageType;

typedef enum {
	NOTIFICATIONS_ALL = 0,
	NOTIFICATIONS_MENTIONS = 1,
	NOTIFICATIONS_NONE = 2,
	NOTIFICATIONS_INHERIT = 3,
} DiscordNotificationLevel;

typedef enum {
	GAME_TYPE_PLAYING = 0,
	GAME_TYPE_STREAMING = 1,
	GAME_TYPE_LISTENING = 2,
	GAME_TYPE_WATCHING = 3,
	GAME_TYPE_CUSTOM_STATUS = 4,
	GAME_TYPE_COMPETING = 5,
} DiscordGameType;

typedef enum {
	PERM_CREATE_INSTANT_INVITE = 0x1,               //1 << 0
	PERM_KICK_MEMBERS = 0x2,                        //1 << 1
	PERM_BAN_MEMBERS = 0x4,                         //1 << 2
	PERM_ADMINISTRATOR = 0x8,                       //1 << 3
	PERM_MANAGE_CHANNELS = 0x10,                    //1 << 4
	PERM_MANAGE_GUILD = 0x20,                       //1 << 5
	PERM_ADD_REACTIONS = 0x40,                      //1 << 6
	PERM_VIEW_AUDIT_LOG = 0x80,                     //1 << 7
	PERM_PRIORITY_SPEAKER = 0x100,                  //1 << 8
	PERM_STREAM = 0x200,                            //1 << 9
	PERM_VIEW_CHANNEL = 0x400,                      //1 << 10
	PERM_SEND_MESSAGES = 0x800,                     //1 << 11
	PERM_SEND_TTS_MESSAGES = 0x1000,                //1 << 12
	PERM_MANAGE_MESSAGES = 0x2000,                  //1 << 13
	PERM_EMBED_LINKS = 0x4000,                      //1 << 14
	PERM_ATTACH_FILES = 0x8000,                     //1 << 15
	PERM_READ_MESSAGE_HISTORY = 0x10000,            //1 << 16
	PERM_MENTION_EVERYONE = 0x20000,                //1 << 17
	PERM_USE_EXTERNAL_EMOJIS = 0x40000,             //1 << 18
	PERM_VIEW_GUILD_INSIGHTS = 0x80000,             //1 << 19
	PERM_CONNECT = 0x100000,                        //1 << 20
	PERM_SPEAK = 0x200000,                          //1 << 21
	PERM_MUTE_MEMBERS = 0x400000,                   //1 << 22
	PERM_DEAFEN_MEMBERS = 0x800000,                 //1 << 23
	PERM_MOVE_MEMBERS = 0x1000000,                  //1 << 24
	PERM_USE_VAD = 0x2000000,                       //1 << 25
	PERM_CHANGE_NICKNAME = 0x4000000,               //1 << 26
	PERM_MANAGE_NICKNAMES = 0x8000000,              //1 << 27
	PERM_MANAGE_ROLES = 0x10000000,                 //1 << 28
	PERM_MANAGE_WEBHOOKS = 0x20000000,              //1 << 29
	PERM_MANAGE_EMOJIS_AND_STICKERS = 0x40000000,   //1 << 30
	PERM_USE_APPLICATION_COMMANDS = 0x80000000,     //1 << 31
	PERM_REQUEST_TO_SPEAK = 0x100000000,            //1 << 32
	PERM_MANAGE_EVENTS = 0x200000000,               //1 << 33
	PERM_MANAGE_THREADS = 0x400000000,              //1 << 34
	PERM_CREATE_PUBLIC_THREADS = 0x800000000,       //1 << 35
	PERM_CREATE_PRIVATE_THREADS = 0x1000000000,     //1 << 36
	PERM_USE_EXTERNAL_STICKERS = 0x2000000000,      //1 << 37
	PERM_SEND_MESSAGES_IN_THREADS = 0x4000000000,   //1 << 38
	PERM_START_EMBEDDED_ACTIVITIES = 0x8000000000,  //1 << 39
	PERM_MODERATE_MEMBERS = 0x10000000000,          //1 << 40
} DiscordPermissionFlags;

typedef struct {
	guint num_tokens;
	guint max_tokens;
	guint time_interval;
	time_t prev_time;
} DiscordTokenBucket;

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
	guint64 parent_id;
	gchar *name;
	gchar *topic;
	DiscordChannelType type;
	int position;
	guint64 last_message_id;
	GHashTable *permission_user_overrides;
	GHashTable *permission_role_overrides;
	gboolean suppress_everyone;
	gboolean muted;
	DiscordNotificationLevel notification_level;

	/* For guild channels */
	GHashTable *threads;

	/* For group DMs */
	GList *recipients;
	GHashTable *names; /* Undiscriminated names -> count of that name */

	/* For threads */
	gboolean archived;
	gboolean locked;
} DiscordChannel;

typedef struct {
	guint64 id;
	gchar *name;
	gchar *icon;
	guint64 owner;

	GHashTable *roles;
	GHashTable *members;	 /* list of member ids */
	GHashTable *nicknames;	 /* id->nick? */
	GHashTable *nicknames_rev; /* reverse */
	guint next_mem_to_sync;

	GHashTable *channels;
	GHashTable *threads;
	int afk_timeout;
	gchar *afk_voice_channel;

	GHashTable *emojis;
	guint64 system_channel_id; // the primary/general channel
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
	gchar *custom_status;
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
	guint64 last_load_last_message_id;

	gchar *token;
	gchar *session_id;
	gchar *mfa_ticket;
	gchar *ack_token;

	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;

	gint64 seq; /* incrementing counter */
	guint heartbeat_timeout;
	guint five_minute_restart;

	GHashTable *one_to_ones;		/* A store of known room_id's -> username's */
	GHashTable *one_to_ones_rev;	/* A store of known usernames's -> room_id's */
	GHashTable *last_message_id_dm; /* A store of known room_id's -> last_message_id's */
	GHashTable *sent_message_ids;   /* A store of message id's that we generated from this instance */
	GHashTable *result_callbacks;   /* Result ID -> Callback function */
	GQueue *received_message_queue; /* A store of the last 10 received message id's for de-dup */

	GHashTable *new_users;
	GHashTable *new_guilds;
	GHashTable *group_dms;			/* A store of known room_id's -> DiscordChannel's */

	gint frames_since_reconnect;
	GSList *pending_writes;
	DiscordTokenBucket *gateway_bucket;
	gint roomlist_guild_count;
	gchar *gateway_url;

	gboolean compress;
	z_stream *zstream;

	PurpleHttpKeepalivePool *http_keepalive_pool;

#ifdef USE_QRCODE_AUTH
	gboolean running_auth_qrcode;
#endif

} DiscordAccount;

#ifdef USE_QRCODE_AUTH
#	include "discord_rsa.c"
#endif

typedef struct {
	DiscordAccount *account;
	DiscordGuild *guild;
} DiscordAccountGuild;

typedef struct {
	DiscordAccount *account;
	DiscordGuild *guild;
	gpointer user_data;
} DiscordAccountGuildData;

typedef struct _DiscordImgMsgContext {
	gint conv_id;
	gchar *from;
	gchar *url;
	PurpleMessageFlags flags;
	time_t timestamp;
} DiscordImgMsgContext;

typedef struct {
	PurpleConversation *conv;
	guint64 user_id;
	guint count;
	gboolean is_me;
	gchar *reaction;
	time_t msg_time;
	gchar *msg_txt;
	gboolean is_unreact;
} DiscordReaction;

typedef struct {
	guint64 room_id;
	time_t msg_time;
	gchar *msg_txt;
	PurpleConversation *conv;
} DiscordReply;

typedef struct {
	guint64 room_id;
	gboolean canceleable;
} DiscordTransfer;


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

static time_t
discord_time_from_snowflake(guint64 id)
{
	return (time_t)(((id >> 22) + DISCORD_EPOCH_MS)/1000);
}

static guint64
discord_snowflake_from_time(time_t timestamp)
{
	return ((((guint64)timestamp)*1000) - DISCORD_EPOCH_MS) << 22;
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

static gboolean discord_join_chat_by_id(DiscordAccount *da, guint64 id, gboolean present);

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
	guild->members = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	guild->nicknames = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	guild->nicknames_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	guild->next_mem_to_sync = 0;

	guild->channels = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_channel);
	guild->threads = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, discord_free_channel);
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
	if (json_object_get_string_member(json, "deny")) {
		// v9 and above
		permission->deny = to_int(json_object_get_string_member(json, "deny"));
		permission->allow = to_int(json_object_get_string_member(json, "allow"));
	} else {
		// v6 and below
		permission->deny = json_object_get_int_member(json, "deny");
		permission->allow = json_object_get_int_member(json, "allow");
	}

	return permission;
}

static DiscordChannel *discord_get_channel_global(DiscordAccount *da, const gchar *id);

static DiscordChannel *
discord_new_channel(JsonObject *json)
{
	DiscordChannel *channel = g_new0(DiscordChannel, 1);

	channel->id = to_int(json_object_get_string_member(json, "id"));
	channel->type = json_object_get_int_member(json, "type");
	channel->last_message_id = to_int(json_object_get_string_member(json, "last_message_id"));
	channel->parent_id = to_int(json_object_get_string_member(json, "parent_id"));
	channel->name = g_strdup(json_object_get_string_member(json, "name"));
	if (channel->type < CHANNEL_GUILD_NEWS_THREAD || channel->type == CHANNEL_GUILD_STAGE_VOICE) {
		channel->topic = g_strdup(json_object_get_string_member(json, "topic"));
		channel->position = json_object_get_int_member(json, "position");
		channel->threads = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	} else { // thread
		JsonObject *metadata = json_object_get_object_member(json, "thread_metadata");
		channel->archived = json_object_get_boolean_member(metadata, "archived");
		channel->locked = json_object_get_boolean_member(metadata, "locked");
	}

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

	if (json_object_get_string_member(json, "permissions")) {
		const gchar *permissions = json_object_get_string_member(json, "permissions");
		guild_role->permissions = to_int(permissions);
	} else {
		guild_role->permissions = json_object_get_int_member(json, "permissions");
	}

	return guild_role;
}

/* freeing */

static void
discord_free_guild_role(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordGuildRole *guild_role = data;
	g_free(guild_role->name);
	g_free(guild_role);
}

static void
discord_free_guild_membership(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordGuildMembership *guild_membership = data;
	g_free(guild_membership->nick);
	g_free(guild_membership->joined_at);

	g_array_unref(guild_membership->roles);
	g_free(guild_membership);
}

static void
discord_free_user(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordUser *user = data;
	g_free(user->name);
	g_free(user->game);
	g_free(user->avatar);
	g_free(user->custom_status);

	g_hash_table_unref(user->guild_memberships);
	g_free(user);
}

static void
discord_free_guild(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordGuild *guild = data;
	g_free(guild->name);
	g_free(guild->icon);
	g_free(guild->afk_voice_channel);

	g_hash_table_unref(guild->roles);
	g_hash_table_unref(guild->members);
	g_hash_table_unref(guild->nicknames);
	g_hash_table_unref(guild->nicknames_rev);
	g_hash_table_unref(guild->channels);
	g_hash_table_unref(guild->threads);
	g_hash_table_unref(guild->emojis);
	g_free(guild);
}

static void
discord_free_channel(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordChannel *channel = data;
	g_free(channel->name);
	g_free(channel->topic);

	g_hash_table_unref(channel->permission_user_overrides);
	g_hash_table_unref(channel->permission_role_overrides);
	if (channel->threads) {
		g_hash_table_unref(channel->threads);
	}
	g_list_free_full(channel->recipients, g_free);

	g_free(channel);
}

static void
discord_free_image_context(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordImgMsgContext *img_context = data;
	g_free(img_context->from);
	g_free(img_context->url);
	g_free(img_context);
}

static void
discord_free_reaction(gpointer data)
{
	g_return_if_fail(data != NULL);

	DiscordReaction *react = data;
	g_free(react->reaction);
	if (react->msg_txt)
		g_free(react->msg_txt);
	g_free(react);
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

	if (json_object_has_member(json, "client_status")) {
		JsonObject *client_status = json_object_get_object_member(json, "client_status");
		if (
			json_object_has_member(client_status, "mobile") &&
			!json_object_has_member(client_status, "desktop") && !json_object_has_member(client_status, "web")
			)
		{
			user->status |= USER_MOBILE;
		}
	}

	if (json_object_get_object_member(json, "game") != NULL) {
		JsonObject *game = json_object_get_object_member(json, "game");
		const gchar *game_id = json_object_get_string_member(game, "id");

		g_free(user->game);
		g_free(user->custom_status);
		if (purple_strequal(game_id, "custom")) {
			const gchar *state = json_object_get_string_member(game, "state");
			user->custom_status = g_strdup(state);
			user->game = NULL;
		} else {
			const gchar *game_name = json_object_get_string_member(game, "name");
			user->game = g_strdup(game_name);
			user->custom_status = NULL;
		}
	}
}

static DiscordChannel *
discord_add_thread(DiscordAccount *da, DiscordGuild *guild, DiscordChannel *parent_chan, JsonObject *json, guint64 guild_id)
{
	g_return_val_if_fail(guild != NULL, NULL);

	DiscordChannel *thread = discord_new_channel(json);
	thread->guild_id = guild_id;
	g_hash_table_replace_int64(guild->threads, thread->id, thread);
	//g_hash_table_replace_int64(guild->channels, thread->id, thread);
	DiscordChannel *parent = parent_chan;
	if (parent == NULL) {
		parent = discord_get_channel_global(da, from_int(thread->parent_id));
	}
	if (parent) {
		g_hash_table_replace_int64(parent->threads, thread->id, thread);
	}
	return thread;
}

static DiscordChannel *
discord_add_channel(DiscordAccount *da, DiscordGuild *guild, JsonObject *json, guint64 guild_id)
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
	if (json_object_get_string_member(json, "type")) {
		// v6 and below
		return purple_strequal(json_object_get_string_member(json, "type"), "role");
	}

	// v9 and above
	return (json_object_get_int_member(json, "type") == 0);
}

static DiscordUser *
discord_get_user_name(DiscordAccount *da, int discriminator, const gchar *name)
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

	if (user == NULL) {
		user = discord_get_user_name(da, 0, name);
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

	if (g_hash_table_lookup_extended_int64(user_table, user_id, (gpointer) &key, (gpointer) &user) && user->id) {
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

	if (user->discriminator == 0) {
		return g_strdup(user->name);
	}
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

static gchar *discord_create_nickname(DiscordUser *author, DiscordGuild *guild, DiscordChannel *channel);

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

		if (user->discriminator == 0) {
			nick = g_strdup(base_nick);
		} else {
			nick = g_strdup_printf("%s#%04d", base_nick, user->discriminator);
		}

		existing = g_hash_table_lookup(guild->nicknames_rev, nick);

		if (existing && existing->id != user->id) {
			/* Ambiguous; use the full tag */

			g_free(nick);
			if (user->discriminator == 0) {
				nick = g_strdup_printf("%s (%s)", base_nick, user->name);
			} else {
				nick = g_strdup_printf("%s (%s#%04d)", base_nick, user->name, user->discriminator);
			}
		}
	}

	if (!nick) {
		nick = g_strdup(base_nick);
	}

	g_hash_table_replace_int64(guild->nicknames, user->id, g_strdup(nick));
	g_hash_table_replace(guild->nicknames_rev, g_strdup(nick), g_memdup2(&user->id, sizeof(user->id)));

	return nick;
}

static gchar *
discord_create_nickname_from_id(DiscordAccount *da, DiscordGuild *g, DiscordChannel *channel, guint64 id)
{
	DiscordUser *user = discord_get_user(da, id);

	if (user) {
		return discord_create_nickname(user, g, channel);
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
	}

	guild = discord_new_guild(json);
	g_hash_table_replace_int64(guild_table, guild->id, guild);
	return guild;
}

static DiscordChannel *
discord_get_thread_global_int_guild(DiscordAccount *da, guint64 id, DiscordGuild **o_guild)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordGuild *guild = value;

		if (!guild) {
			continue;
		}

		DiscordChannel *thread = g_hash_table_lookup_int64(guild->threads, id);

		if (thread) {
			if (o_guild) {
				*o_guild = guild;
			}

			return thread;
		}
	}

	return NULL;
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

		discord_print_append(1, buffer, row_buffer, "Member count: %d", g_hash_table_size(guild->members));

		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, guild->members);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			guint64 member_id = *(gint64 *) key;
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
		discord_print_append(1, buffer, row_buffer, "Custom Status: %s", user->custom_status);
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
discord_get_user_flags_from_permissions(DiscordUser *user, guint64 permissions)
{
	if (permissions & PERM_ADMINISTRATOR) { // Admin
		return PURPLE_CHAT_USER_OP;
	}
	if (permissions & (PERM_BAN_MEMBERS | PERM_KICK_MEMBERS)) { // Ban or Kick
		return PURPLE_CHAT_USER_HALFOP;
	}

	if (user == NULL) {
		return PURPLE_CHAT_USER_NONE;
	}
	if (user->bot) {
		return PURPLE_CHAT_USER_VOICE;
	}

	return PURPLE_CHAT_USER_NONE;
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
			if (role->permissions & PERM_ADMINISTRATOR) { /* Admin */
				this_flag = PURPLE_CHAT_USER_OP;
			} else if (role->permissions & (PERM_BAN_MEMBERS | PERM_KICK_MEMBERS)) { /* Ban/kick */
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

	gint disc_int = to_int(discriminator);

	if (disc_int == 0) {
		return g_strdup(username);
	}

	return g_strdup_printf("%s#%04d", username, disc_int);
}

static gchar *
discord_get_display_name(DiscordAccount *da, DiscordGuild *guild, DiscordChannel *channel, DiscordUser *user, JsonObject *user_json)
{
	gchar *ret = NULL;
	gchar *tmp = NULL;

	if (user == NULL) {
		if (user_json) {
			const gchar *username = json_object_get_string_member(user_json, "username");
			const gchar *discriminator = json_object_get_string_member(user_json, "discriminator");
			tmp = discord_combine_username(username, discriminator);
		}
	} else if (channel == NULL) {
		// Probably a DM
		tmp = discord_create_fullname(user);
		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, ret);
		if (buddy != NULL)
			tmp = g_strdup(purple_buddy_get_alias(buddy));

	} else {
		tmp = discord_create_nickname(user, guild, channel);
	}

	ret = purple_markup_escape_text(tmp, -1);
	g_free(tmp);

	return ret;
}

static gchar *
discord_get_display_name_or_unk(DiscordAccount *da, DiscordGuild *guild, DiscordChannel *channel, DiscordUser *user, JsonObject *user_json)
{
	if (user || user_json) {
		gchar *name = discord_get_display_name(da, guild, channel, user, user_json);
		if (name) {
			return name;
		}
	}
	return g_strdup(_("Unknown user"));
}

static gchar * discord_truncate_message(const gchar *msg_txt, guint count);
static gchar * discord_parse_timestamp(time_t timestamp);

static gchar *
discord_get_reply_text(DiscordAccount *da, DiscordGuild *guild, DiscordChannel *channel, JsonObject *referenced_message)
{
	JsonObject *reply_author = json_object_get_object_member(referenced_message, "author");
	DiscordUser *reply_user = discord_upsert_user(da->new_users, reply_author);

	gchar *reply_name = discord_get_display_name_or_unk(da, guild, channel, reply_user, reply_author);


	gchar *prev_text = NULL;
	const gchar *msg_txt = json_object_get_string_member(referenced_message, "content");
	if (msg_txt && *msg_txt) {
		prev_text = discord_truncate_message(msg_txt, 32);
	} else {
		const gchar *msg_id = json_object_get_string_member(referenced_message, "id");
		time_t msg_timestamp = discord_time_from_snowflake(to_int(msg_id));
		gchar *msg_time = discord_parse_timestamp(msg_timestamp);

		prev_text = g_strdup_printf(_("&lt;message at %s&gt;"), msg_time);
		g_free(msg_time);
	}

	// Formatting could be better. I went with something similar to Discord's
	// format to make it familiar to the user
	gchar *reply_txt = g_strdup_printf("<font size=1>┌──@%s: %s</font>", reply_name, prev_text);
	g_free(reply_name);
	g_free(prev_text);

	/* Convert markdown in Discord quirks mode */
	gchar *ret = markdown_convert_markdown(reply_txt, FALSE, TRUE);
	g_free(reply_txt);

	return ret;
}

static void
discord_update_cookies(DiscordAccount *ya, const GList *cookie_headers)
{
	const GList *cur;

	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur)) {
		const gchar *cookie_start;
		const gchar *cookie_end;

		cookie_start = cur->data;
		cookie_end = strchr(cookie_start, '=');

		if (cookie_end != NULL) {
			gchar *cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');

			if (cookie_end != NULL) {
				gchar *cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);

				g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
			}
		}
	}
}

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

static void discord_fetch_url_with_method_delay(DiscordAccount *da, const gchar *method, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data, guint delay);
static void UpdateRateLimits(const gchar *xrateLimitS, const gchar *xrateRemainingS, const gchar *xRateReset, const gchar *xRateResetAfter)
{
	if(!xrateLimitS || !xrateRemainingS || !xRateReset || !xRateResetAfter) return;
	xrateLimit=atoi(xrateLimitS);
	purple_debug_info("discord", "X-RateLimit-Limit: %s\n", xrateLimitS);
	xrateRemaining=atoi(xrateRemainingS);
	purple_debug_info("discord", "X-RateLimit-Remaining: %s\n", xrateRemainingS);
	xrateReset=atof(xRateReset);
	purple_debug_info("discord", "X-RateLimit-Reset: %s\n", xRateReset);
	// Multiply reset after by 4 to be more conservative with rate limiting
	xrateResetAfter=atof(xRateResetAfter) * 3.0;
	purple_debug_info("discord", "X-RateLimit-Reset-After: %s\n", xRateResetAfter);
	if (xrateResetAfter > 0) {
		xRateAllowedPerSecond = (int)( (double)xrateRemaining / (double)xrateResetAfter );
		xRateAllowedRemaining = xRateAllowedPerSecond;
		xRateDelayPerRequest = xRateAllowedPerSecond > 0 ? 
			(int)((1.0 / (double)xRateAllowedPerSecond) * 1000.0) : 1000;
		purple_debug_info("discord", "Rate limits calculated: %d requests/sec, %d ms delay\n", 
			xRateAllowedPerSecond, xRateDelayPerRequest);
	} else {
		purple_debug_warning("discord", "Invalid rate limit reset value\n");
		xRateAllowedPerSecond = 1;
		xRateAllowedRemaining = 1; 
		xRateDelayPerRequest = 1000;
	}
}
static void parse_rate_limit_headers(PurpleHttpResponse *response) {
    const gchar *xrateLimitS = purple_http_response_get_header(response,"X-RateLimit-Limit");
    const gchar *xrateRemainingS = purple_http_response_get_header(response,"X-RateLimit-Remaining");  
    const gchar *xRateReset = purple_http_response_get_header(response,"X-RateLimit-Reset");
    const gchar *xRateResetAfter = purple_http_response_get_header(response,"X-RateLimit-Reset-After");
    UpdateRateLimits(xrateLimitS, xrateRemainingS, xRateReset, xRateResetAfter);
}

static void
discord_response_callback(PurpleHttpConnection *http_conn,
							PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
	const gchar *error_message = purple_http_response_get_error(response);
	parse_rate_limit_headers(response);
	const gchar *body;
	gsize body_len;
	DiscordProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();

	discord_update_cookies(conn->ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));
	int response_code = purple_http_response_get_code(response);

	if (response_code == 429) {
		const gchar *retry_after_s = purple_http_response_get_header(response,"Retry-After");
		gdouble retry_after = retry_after_s ? g_ascii_strtod(retry_after_s, NULL) : 5;
		PurpleHttpRequest *request = purple_http_conn_get_request(http_conn);

		discord_fetch_url_with_method_delay(conn->ya,
																				purple_http_request_get_method(request),
																				purple_http_request_get_url(request),
																				purple_http_request_get_contents(request),
																				conn->callback, conn->user_data,
																				(guint) retry_after*1000);

		g_free(conn);
		return;
	}

	body = url_text;
	body_len = len;

	if (body == NULL && error_message != NULL) {
		if (conn->callback) {
			conn->callback(conn->ya, NULL, conn->user_data);
		}

		/* connection error - unresolvable dns name, non existing server */
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

		purple_debug_misc("discord", "Got response: %s\n", body ? body : "(null)");

		if (conn->callback) {
			conn->callback(conn->ya, root, conn->user_data);
		}
	}

	g_object_unref(parser);
	g_free(conn);
}

static void
discord_fetch_url_with_method_len(DiscordAccount *ya, const gchar *method, const gchar *url, const gchar *postdata, gsize postdata_len, DiscordProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	DiscordProxyConnection *conn;
	gchar *cookies;

	account = ya->account;

	if (!PURPLE_CONNECTION_IS_VALID(ya->pc) || purple_account_is_disconnected(account)) {
		if (callback != NULL) {
			// Allow callback to free memory
			callback(ya, NULL, user_data);
		}
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

	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_set_method(request, method);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", DISCORD_USERAGENT);
	purple_http_request_header_set(request, "Cookie", cookies);
	purple_http_request_set_keepalive_pool(request, ya->http_keepalive_pool);

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
		} else if (postdata[0] == '-' && postdata[1] == '-') {
			const gchar *boundary = g_strndup(&postdata[2], strchr(&postdata[2], '\r') - postdata - 2);
			purple_http_request_header_set_printf(request, "Content-Type", "multipart/form-data; boundary=%s", boundary);
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}

		purple_http_request_set_contents(request, postdata, postdata_len);
	}

	purple_http_request(ya->pc, request, discord_response_callback, conn);
	purple_http_request_unref(request);

	g_free(cookies);
}

typedef struct {
	DiscordAccount *ya;
	gchar *method;
	gchar *url;
	gchar *contents;
	DiscordProxyCallbackFunc callback;
	gpointer user_data;
} DiscordDelayedRequest;

static gboolean
discord_fetch_url_with_method_delay_cb(gpointer data)
{
	DiscordDelayedRequest *request = data;
	discord_fetch_url_with_method_len(request->ya,
																		request->method,
																		request->url,
																		request->contents,
																		request-> contents ? strlen(request->contents) : 0,
																		request->callback,
																		request->user_data);
	g_free(request->method);
	g_free(request->url);
	if (request->contents) {
		g_free(request->contents);
	}
	g_free(request);

	return FALSE;
}

static void
discord_fetch_url_with_method_delay(DiscordAccount *da, const gchar *method, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data, guint delay)
{
		DiscordDelayedRequest *request;
		request = g_new0(DiscordDelayedRequest, 1);
		request->ya = da;
		request->callback = callback;
		request->user_data = user_data;
		request->method = g_strdup(method);
		request->url = g_strdup(url);
		request->contents = postdata ? g_strdup(postdata) : NULL;

		purple_timeout_add(delay + getJitteredDelay(MAX(65,xRateDelayPerRequest)), discord_fetch_url_with_method_delay_cb, request);
}

static void
discord_fetch_url_with_delay(DiscordAccount *da, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data, guint delay)
{
	discord_fetch_url_with_method_delay(da, (postdata ? "POST" : "GET"), url, postdata, callback, user_data, delay);
}

static void
discord_fetch_url_with_method(DiscordAccount *da, const gchar *method, const gchar *url, const gchar *postdata, DiscordProxyCallbackFunc callback, gpointer user_data)
{
	//discord_fetch_url_with_method_len(da, method, url, postdata, postdata ? strlen(postdata) : 0, callback, user_data);
	discord_fetch_url_with_method_delay(da, method, url, postdata, callback, user_data, 0);
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
		json_object_set_int_member(obj, "op", OP_RESUME);

		json_object_set_string_member(data, "session_id", da->session_id);
		json_object_set_int_member(data, "seq", da->seq);
	} else {
		JsonObject *properties = json_object_new();
		JsonObject *presence = json_object_new();
		JsonObject *client_state = json_object_new();

		json_object_set_int_member(obj, "op", OP_IDENTIFY);

		json_object_set_int_member(data, "capabilities", 509);

		json_object_set_string_member(properties, "os", "Windows");
		json_object_set_string_member(properties, "browser", "Chrome");
		json_object_set_string_member(properties, "device", "");
		json_object_set_string_member(properties, "browser_user_agent", DISCORD_USERAGENT);
		json_object_set_string_member(properties, "browser_version", DISCORD_USERAGENT_VERSION);
		json_object_set_string_member(properties, "os_version", "10");

		json_object_set_string_member(properties, "referrer", "https://discord.com/channels/@me");
		json_object_set_string_member(properties, "referring_domain", "discord.com");
		json_object_set_string_member(properties, "referrer_current", "");
		json_object_set_string_member(properties, "referring_domain_current", "");
		json_object_set_string_member(properties, "release_channel", "stable");
		json_object_set_int_member(properties, "client_build_number", 96355);
		json_object_set_null_member(properties, "client_event_source");

		json_object_set_object_member(data, "properties", properties);

		/* TODO real presence */
		json_object_set_string_member(presence, "status", "online");
		json_object_set_int_member(presence, "since", 0);
		json_object_set_array_member(presence, "activities", json_array_new());
		json_object_set_boolean_member(presence, "afk", FALSE);
		json_object_set_object_member(data, "presence", presence);

		json_object_set_boolean_member(data, "compress", FALSE);
		json_object_set_int_member(data, "large_threshold", DISCORD_MAX_LARGE_THRESHOLD);

		json_object_set_object_member(client_state, "guild_hashes", json_object_new());
		json_object_set_string_member(client_state, "highest_last_message_id", "0");
		json_object_set_int_member(client_state, "read_state_version", 0);
		json_object_set_int_member(client_state, "user_guild_settings_version", -1);
		json_object_set_object_member(data, "client_state", client_state);

		//json_object_set_boolean_member(data, "guild_subscriptions", TRUE);

		//json_object_set_int_member(data, "intents", 0x3FFF); //14bit mask
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

#ifdef USE_QRCODE_AUTH
	if (da->running_auth_qrcode)
		json_object_set_string_member(obj, "op", "heartbeat");
	else
#endif

	json_object_set_int_member(obj, "op", OP_HEARTBEAT);
	json_object_set_int_member(obj, "d", da->seq);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);

	return TRUE;
}

void discord_handle_add_new_user(DiscordAccount *ya, JsonObject *obj);

PurpleGroup *discord_get_or_create_default_group();

static void discord_got_initial_load_users(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_create_relationship(DiscordAccount *da, JsonObject *json);
static void discord_got_relationships(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_private_channels(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_presences(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_read_states(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_guild_setting(DiscordAccount *da, JsonObject *obj);
static void discord_got_guild_settings(DiscordAccount *da, JsonNode *node);
static void discord_got_history_static(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_history_of_room(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_populate_guild(DiscordAccount *da, JsonObject *guild);
static void discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_got_avatar(DiscordAccount *da, JsonNode *node, gpointer user_data);
static void discord_get_avatar(DiscordAccount *da, DiscordUser *user, gboolean is_buddy);
static void discord_buddy_guild(DiscordAccount *da, DiscordGuild *guild);
static void discord_guild_get_offline_users(DiscordAccount *da, const gchar *guild_id);

static const gchar *discord_normalise_room_name(const gchar *guild_name, const gchar *name);
static guint64 discord_compute_permission(DiscordAccount *da, DiscordUser *user, DiscordChannel *channel);
static DiscordChannel *discord_open_chat(DiscordAccount *da, guint64 id, gboolean present);

static gboolean
discord_replace_channel(const GMatchInfo *match, GString *result, gpointer user_data)
{
	DiscordAccountGuild *ag = user_data;
	DiscordAccount *da = ag->account;
	DiscordGuild *guild = ag->guild;
	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *channel_id = g_match_info_fetch(match, 1);
	gint64 channel_num = to_int(channel_id);
	DiscordChannel *channel = guild ? g_hash_table_lookup_int64(guild->channels, channel_num) : discord_get_channel_global(da, channel_id);

	if (channel) {
		/* TODO make this a clickable link */

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

typedef struct {
	PurpleConversation *conv;
	gchar *shortcut;
} DiscordSmileyData;

static void
discord_fetch_emoji_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordSmileyData *data = user_data;

	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		const gchar *response_str;
		gsize response_len;
		PurpleSmiley *smiley = NULL;

		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");

		smiley = purple_smiley_new_from_data(data->shortcut, (const guchar *) response_str, response_len);

		purple_conversation_add_smiley(data->conv, smiley);

		g_object_unref(G_OBJECT(smiley));
	}

	g_free(data->shortcut);
	g_free(data);
}

static void
discord_fetch_emoji(PurpleConversation *conv, const gchar *emoji, guint64 id)
{
	DiscordAccount *da;
	PurpleConnection *pc;
	DiscordSmileyData *data;
	gchar *shortcut;

	g_return_if_fail(conv);
	g_return_if_fail(emoji);
	g_return_if_fail(id);

	shortcut = g_strdup_printf(":%s:", emoji);
	if (purple_conversation_get_smiley(conv, shortcut)) {
		g_free(shortcut);
		return;
	}

	pc = purple_conversation_get_connection(conv);
	da = purple_connection_get_protocol_data(pc);
	g_return_if_fail(da);

	// TODO
	// if (id == 0) {
		// id = g_hash_table_lookup(guild->emojis, emoji);
	// }

	data = g_new0(DiscordSmileyData, 1);

	data->shortcut = shortcut;
	data->conv = conv;  //TODO g_object_ref(conv); for purple3?
	GString *url = g_string_new("https://" DISCORD_CDN_SERVER "/emojis/");
	g_string_append_printf(url, "%" G_GUINT64_FORMAT, id);
	g_string_append(url, ".png");

	discord_fetch_url(da, url->str, NULL, discord_fetch_emoji_cb, data);

	g_string_free(url, TRUE);
}

static gboolean
discord_replace_emoji(const GMatchInfo *match, GString *result, gpointer user_data)
{
	PurpleConversation *conv = user_data;
	gchar *alt_text = g_match_info_fetch(match, 1);
	gchar *emoji_id = g_match_info_fetch(match, 2);

	if (conv != NULL && purple_account_get_bool(purple_conversation_get_account(conv), "show-custom-emojis", TRUE)) {
		g_string_append_printf(result, ":%s:", alt_text);

		discord_fetch_emoji(conv, alt_text, to_int(emoji_id));

	} else {
		g_string_append_printf(result, "<img src=\"https://" DISCORD_CDN_SERVER "/emojis/%s\" alt=\":%s:\"/>", emoji_id, alt_text);
	}

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
		gchar *name = discord_create_fullname(mention_user);

		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, name);

		if (buddy && purple_buddy_get_alias(buddy)) {
			g_free(name);
			name = g_strdup(purple_buddy_get_alias(buddy));
		} else if (!guild && snowflake == da->self_user_id && purple_account_get_private_alias(da->account)) {
			g_free(name);
			name = g_strdup(purple_account_get_private_alias(da->account));
		} else if (guild && g_hash_table_lookup_int64(guild->nicknames, snowflake)) {
			g_free(name);
			name = g_strdup(g_hash_table_lookup_int64(guild->nicknames, snowflake));
		}

		if (name != NULL) {
			g_string_append_printf(result, "<b>@%s</b>", name);
			g_free(name);
		} else {
			g_string_append(result, match_string);
		}
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
	tmp = g_regex_replace_eval(channel_mentions_regex, message, -1, 0, 0, discord_replace_channel, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	/* Replace <@&role_id> with role names */
	if (g) {
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
		g_string_append_printf(result, " &lt;@%" G_GUINT64_FORMAT "&gt; ", user->id);
	} else if (guild != NULL) {
		/* If that fails, find a role */
		guint64 role = discord_find_role_by_name(guild, identifier);

		if (role) {
			g_string_append_printf(result, " &lt;@&amp;%" G_GUINT64_FORMAT "&gt; ", role);
		} else {
			/* If that fails, find a channel */
			guint64 channel = discord_find_channel_by_name(guild, identifier);

			if (channel) {
				g_string_append_printf(result, " &lt;#%" G_GUINT64_FORMAT "&gt; ", channel);
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

	// For converting spaced '@user name' into a mention
	tmp = g_regex_replace_eval(discord_spaced_mention_regex, message, -1, 0, 0, discord_make_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	return message;
}

/* Looks up / creates a nickname for a given context. If guild is specified,
 * channel is ignored (for guild nicknames); if guild is NULL, channel is used
 * instead (for group DM nicknames) */

static gchar *
discord_create_nickname(DiscordUser *author, DiscordGuild *guild, DiscordChannel *channel)
{
	if (!guild) {
		/* For a group DM, try undiscriminated if unambiguous */

		if (channel && channel->type == CHANNEL_GROUP_DM) {
			unsigned count = (unsigned) (guintptr) g_hash_table_lookup(channel->names, author->name);

			if (count == 1)
				return g_strdup(author->name);
		}

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
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	if (channel && channel->type == CHANNEL_GROUP_DM) {
		/* TODO: use a hash map... */
		GList *l;

		DiscordUser *self = discord_get_user(da, da->self_user_id);

		if (self && purple_strequal(self->name, who))
			return g_strdup(da->self_username);

		for (l = channel->recipients; l != NULL; l = l->next) {
			guint64 *recipient_ptr = l->data;
			DiscordUser *recipient = discord_get_user(da, *recipient_ptr);

			if (recipient && purple_strequal(recipient->name, who))
				return discord_create_fullname(recipient);
		}

		/* Oh well. We tried */
		goto bail;
	}

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

static time_t
discord_parse_timestring(const gchar *timestring)
{
	time_t timestamp;
	gchar *verified_timestring;
	GTimeZone *local_time = g_time_zone_new_local();
	GDateTime *now = g_date_time_new_now_local();
	gint year = 1970, month = 1, day = 1;

	if (!strchr(timestring, ' ') && !strchr(timestring, 't') && !strchr(timestring, 'T')) {
		// no separator, so no date attached
		g_date_time_get_ymd(now, &year, &month, &day);

		verified_timestring = g_strdup_printf("%i-%02i-%02iT%s", year, month, day, timestring);
	} else {
		verified_timestring = g_strdup(timestring);
	}

	GDateTime *msg_time = g_date_time_new_from_iso8601(verified_timestring, local_time);


	g_free(verified_timestring);

	if (msg_time == NULL) {
		g_time_zone_unref(local_time);
		g_date_time_unref(now);
		return 0;
	}

	if (g_date_time_difference(msg_time, now) > 0) {
		// msg_time is in the future, user is probably up past midnight
		GDateTime *temp = g_date_time_add_days(msg_time, -1);
		g_date_time_unref(msg_time);
		msg_time = temp;

		if (g_date_time_difference(msg_time, now) > 0) {
			g_time_zone_unref(local_time);
			g_date_time_unref(msg_time);
			g_date_time_unref(now);
			return 0;
		}
	}

	timestamp = g_date_time_to_unix(msg_time);

	g_time_zone_unref(local_time);
	g_date_time_unref(msg_time);
	g_date_time_unref(now);
	return timestamp;
}

static gchar *
discord_parse_timestamp(time_t timestamp)
{
	GDateTime *date_time = g_date_time_new_from_unix_local(timestamp);
	GDateTime *now = g_date_time_new_now_local();
	gint then_year = 1970, then_month = 1, then_day = 1;
	gint now_year = 1970, now_month = 1, now_day = 1;
	gchar *format;

	g_date_time_get_ymd(date_time, &then_year, &then_month, &then_day);
	g_date_time_get_ymd(now, &now_year, &now_month, &now_day);

	if (then_year != now_year || then_month != now_month || then_day != now_day) {
		format = "(%F %T)";
	} else {
		format = "%T";
	}

	gchar *timestring = g_date_time_format(date_time, format);

	g_date_time_unref(date_time);
	g_date_time_unref(now);

	return timestring;
}

static gchar *
discord_get_thread_color(time_t ts)
{
	gchar *timestamp = from_int(ts);

	// Reverse gives better color variety
	guint r = g_str_hash(g_strreverse(timestamp));

	g_free(timestamp);

	// Work in HSV because it's easier on my brain, convert to rgb later
	guint hue = (r >> 16) & 255;
	guint sat = (r >>  8) & 255;
	guint val = (r >>  0) & 255;

	// Make text not black/grey/white
	if (val < 110) {
		val |= 110;
	}
	if (sat < 110) {
		sat |= 110;
	}

	// Formulas taken from Wikipedia:
	// https://en.wikipedia.org/wiki/HSL_and_HSV#HSV_to_RGB_alternative
	gdouble frac_hue = (gdouble)hue / 42.0; // Get double between 0 and 6
	gdouble frac_sat = (gdouble)sat / 255.0;
	gdouble frac_val = (gdouble)val / 255.0;

	double rgb_n[3] = {5.0, 3.0, 1.0};
	guint color = 0;

	for (int i = 0; i < 3; i++) {
		double k = remainder((rgb_n[i] + frac_hue), 6.0);
		double f = frac_val - (frac_val * frac_sat * MAX(0, MIN(MIN(k, 4 - k), 1)));
		guint hex = (guint)(f * 255);
		color |= hex << (8 * i);
	}

	gchar *color_string = g_strdup_printf("%06x", color);

	return color_string;

}

static gchar *
discord_get_formatted_thread_timestamp(time_t ts) {
	gchar *color = discord_get_thread_color(ts);
	gchar *time_str = discord_parse_timestamp(ts);

	gchar *timestring = g_strdup_printf("<font color=\"#%s\">%s</font>", color, time_str);
	g_free(color);

	return timestring;
}

static gboolean discord_get_room_force_large(DiscordAccount *da, guint64 id);
static gboolean discord_get_room_force_small(DiscordAccount *da, guint64 id);

static void discord_react_cb(DiscordAccount *da, JsonNode *node, gpointer user_data);

static gchar *
discord_truncate_message(const gchar *msg_text, guint trunc_len)
{
	size_t txt_len = g_utf8_strlen(msg_text, -1);
	gchar *trunc_text;

	// Truncate long messages
	if (txt_len > trunc_len) {
		// Get pointer to (trunc_len+1)th character of msg_text
		gchar *tmp = g_utf8_offset_to_pointer(msg_text, trunc_len);
		// (tmp - msg_text) is # bytes (char*) of first trunc_len characters
		guint num_bytes = tmp - msg_text;
		tmp = g_strndup(msg_text, num_bytes);
		gchar *tmp2 = purple_markup_escape_text(tmp, -1);
		g_free(tmp);
		trunc_text = g_strdup_printf("%s...", tmp2);
		g_free(tmp2);
	} else {
		trunc_text = purple_markup_escape_text(msg_text, -1);
	}
	return trunc_text;
}

static gchar *
discord_get_react_text(DiscordAccount *da, const gchar *author_nick, const gchar *reactors_text, DiscordReaction *react)
{
	gchar *ret = NULL;
	time_t msg_time = react->msg_time;
	gchar *msg_text = react->msg_txt;
	gchar *emoji_name = react->reaction;
	PurpleConversation *conv = react->conv;

	gchar *prev_text;
	if (author_nick == NULL) {
		prev_text = g_strdup("");
	} else {
		gchar * author_nick_pos = purple_strequal(author_nick, "SELF") ? g_strdup(_("your")) : g_strdup_printf(_("%s's"), author_nick);
		if (msg_text && !purple_strequal(msg_text, "")) {
			gchar *tmp = discord_truncate_message(msg_text, 64);
			prev_text = g_strdup_printf(" to %s message: %s", author_nick_pos, tmp);
			g_free(tmp);
		} else {
			gchar *tmp = discord_parse_timestamp(msg_time);
			prev_text = g_strdup_printf(" to %s message at %s", author_nick_pos, tmp);
			g_free(tmp);
		}
		g_free(author_nick_pos);
	}

	gchar *react_text;
	if (react->is_unreact) {
		react_text = g_strdup_printf(_("%s removed the reaction \"%s\"%s"), reactors_text, emoji_name, prev_text);
	} else {
		react_text = g_strdup_printf(_("%s reacted with \"%s\"%s"), reactors_text, emoji_name, prev_text);
	}
	g_free(prev_text);

	if (react_text != NULL) {
		/* Replace <:emoji:id> with emojis */
		ret = g_regex_replace_eval(emoji_regex, react_text, -1, 0, 0, discord_replace_emoji, conv, NULL);
		g_free(react_text);
	}

	return ret;
}

static void
discord_reactor_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordReaction *react = user_data;
	guint64 author_id = react->user_id;
	guint count = react->count;
	JsonArray *users = json_node_get_array(node);
	guint users_len = users ? json_array_get_length(users) : 0;
	guint64 room_id = *(guint64 *) purple_conversation_get_data(react->conv, "id");
	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(react->conv));
	}
	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	gchar **reactors = g_new0(gchar*, users_len+3); // names + you + unnamed reactors + NULL
	guint m = 0;

	if (react->is_me) {
		reactors[m] = g_strdup(_("You"));
		m++;
		count--;
	}
	for (guint n = 0; n < users_len; n++) {
		JsonObject *reactor_obj = json_array_get_object_element(users, n);
		guint64 reactor_id = to_int(json_object_get_string_member(reactor_obj, "id"));
		if (reactor_id == da->self_user_id) {
			count++; // Needed to balance remaining reactors calculation
			continue;
		}

		DiscordUser *reactor = discord_get_user(da, reactor_id);
		reactors[m] = discord_get_display_name_or_unk(da, guild, channel, reactor, reactor_obj);
		m++;
	}

	if (count > users_len) {
		guint remainder = count - users_len;
		const gchar *ppl = remainder == 1 ? _("person") : _("people");
		reactors[m] = g_strdup_printf(_("%d %s%s"), remainder, m ? _("other ") : "", ppl);
		m++;
	}
	if (m > 1) {
		gchar *tmp = g_strdup_printf(_("and %s"), reactors[m-1]);
		g_free(reactors[m-1]);
		reactors[m-1] = tmp;
	}
	reactors[m] = NULL;
	gchar *reactors_text = g_strjoinv(m > 2 ? _(", ") : _(" "), reactors);
	g_strfreev(reactors);

	gchar *author_nick;
	if (author_id == da->self_user_id) {
		author_nick = g_strdup("SELF"); //placeholder
	} else {
		DiscordUser *author = discord_get_user(da, author_id);
		author_nick = discord_get_display_name_or_unk(da, guild, channel, author, NULL);
	}

	gchar *react_text = discord_get_react_text(da, author_nick, reactors_text, react);
	g_free(reactors_text);
	g_free(author_nick);

	purple_conversation_write_system_message(react->conv, react_text, PURPLE_MESSAGE_SYSTEM);

	g_free(react_text);
	discord_free_reaction(react);
}

static void
discord_download_image_cb(DiscordAccount *da, JsonNode *node, gpointer user_data) {
	DiscordImgMsgContext *img_context = user_data;

	if (node != NULL) {
		gchar *attachment_show;
		JsonObject *response = json_node_get_object(node);
		const gchar *img_data_s = g_dataset_get_data(node, "raw_body");
		gsize img_data_len = json_object_get_int_member(response, "len");
		gpointer img_data = g_memdup2(img_data_s, img_data_len);
		int img_id = purple_imgstore_add_with_id(img_data, img_data_len, NULL);

		if (img_id >= 0) {
			attachment_show = g_strdup_printf("<img id=\"%u\" alt=\"%s\"/><br /><a href=\"%s\">(link)</a>", img_id, img_context->url, img_context->url);
		} else {
			attachment_show = g_strdup(img_context->url);
		}

		if (img_context->conv_id >= 0) {
			purple_serv_got_chat_in(da->pc, img_context->conv_id, img_context->from, img_context->flags, attachment_show, img_context->timestamp);
		} else {
			purple_serv_got_im(da->pc, img_context->from, attachment_show, img_context->flags, img_context->timestamp);
		}
		g_free(attachment_show);

	} else {
		purple_debug_error("discord", "Image response node is null!\n");
		if (img_context->conv_id >= 0) {
			purple_serv_got_chat_in(da->pc, img_context->conv_id, img_context->from, img_context->flags, img_context->url, img_context->timestamp);
		} else {
			purple_serv_got_im(da->pc, img_context->from, img_context->url, img_context->flags, img_context->timestamp);
		}
	}

	discord_free_image_context(img_context);
	return;
}

static time_t
discord_str_to_time(const gchar *str) {
	gboolean utc = FALSE;

	if (str == NULL || *str == '\0') {
		return 0;
	}

	//workaround for libpurple 2.14.7
	if (strstr(str, "+00:00")) {
		utc = TRUE;
	}

	return purple_str_to_time(str, utc, NULL, NULL, NULL);
}

static gboolean
discord_treat_room_as_small(DiscordAccount *da, guint64 room_id, DiscordGuild *guild)
{
	if (discord_get_room_force_small(da, room_id)) {
		return TRUE;
	}
	if (discord_get_room_force_large(da, room_id)) {
		return FALSE;
	}
	if (guild == NULL)
	{
		return TRUE;
	}
	gchar *sizepref_id = g_strdup_printf("%" G_GUINT64_FORMAT "-size", guild->id);
	gint sizepref = purple_account_get_int(da->account, sizepref_id, DISCORD_GUILD_SIZE_DEFAULT);
	g_free(sizepref_id);
	if (sizepref == DISCORD_GUILD_SIZE_LARGE) {
		return FALSE;
	} else if (sizepref == DISCORD_GUILD_SIZE_SMALL) {
		return TRUE;
	}
	gint member_count = g_hash_table_size(guild->members);
	if (member_count < purple_account_get_int(da->account, "large-channel-count", 20))
	{
		return TRUE;
	}
	return FALSE;
}

static void discord_thread_parent_cb(DiscordAccount *da, JsonNode *node, gpointer user_data);

static guint64
discord_process_message(DiscordAccount *da, JsonObject *data, unsigned special_type)
{
	gboolean edited = special_type == DISCORD_MESSAGE_EDITED;
	gboolean pinned = special_type == DISCORD_MESSAGE_PINNED;

	guint64 msg_id = to_int(json_object_get_string_member(data, "id"));
	guint64 msg_type = json_object_get_int_member(data, "type");

	if (!json_object_get_object_member(data, "author")) {
		/* Possibly edited message? */
		purple_debug_info("discord", "No author in message processed\n");
		return msg_id;
	}

	JsonObject *author_obj = json_object_get_object_member(data, "author");
	guint64 author_id = to_int(json_object_get_string_member(author_obj, "id"));

	guint64 id = to_int(json_object_get_string_member(data, "channel_id"));
	guint64 channel_id;
	gchar *channel_id_s;

	const gchar *content = json_object_get_string_member(data, "content");
	const gchar *timestamp_str = json_object_get_string_member(data, "timestamp");
	time_t timestamp = discord_str_to_time(timestamp_str);
	const gchar *nonce = json_object_get_string_member(data, "nonce");
	gchar *escaped_content = purple_markup_escape_text(content, -1);
	JsonObject *referenced_message = json_object_get_object_member(data, "referenced_message");
	JsonArray *attachments = json_object_get_array_member(data, "attachments");
	JsonArray *embeds = json_object_get_array_member(data, "embeds");
	JsonArray *stickers = json_object_get_array_member(data, "sticker_items");
	JsonArray *reactions = json_object_get_array_member(data, "reactions");
	JsonArray *mentions = json_object_get_array_member(data, "mentions");
	JsonArray *mention_roles = json_object_get_array_member(data, "mention_roles");
	PurpleMessageFlags flags;
	gchar *tmp;
	gint i;
	PurpleConversation *conv;

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, id, &guild);
	//DiscordChannel *parent = NULL;
	DiscordChannel *thread = NULL;

	if (!channel) {
		thread = discord_get_thread_global_int_guild(da, id, &guild);
	}

	if (thread) {
		channel = discord_get_channel_global_int(da, thread->parent_id);
	}

	if (channel) {
		channel_id = channel->id;
	} else {
		channel_id = id;
	}

	channel_id_s = from_int(channel_id);

	/* Check if we should receive messages at all and shortcircuit if not,
	 * unless the user already opened the channel */

	gboolean muted = channel ? channel->muted : FALSE;
	if (thread && !muted) {
		muted = thread->muted;
	}

	if (muted) {
		if (purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id)) == NULL) {
			g_free(escaped_content);
			g_free(channel_id_s);
			return msg_id;
		}
	}

	if (author_id == da->self_user_id) {
		flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
	} else {
		flags = PURPLE_MESSAGE_RECV;
	}

	/* Check for mentions, but only if the user has not globally disabled
	 * mentions for the channel. If the level is ALL or MENTIONS, it's
	 * okay; we just check for NONE */

	gboolean mentionable = channel ? (channel->notification_level != NOTIFICATIONS_NONE) : FALSE;

	if (mentions && mentionable) {
		for (i = json_array_get_length(mentions) - 1; i >= 0; i--) {
			JsonObject *user = json_array_get_object_element(mentions, i);
			guint64 id = to_int(json_object_get_string_member(user, "id"));

			if (id == da->self_user_id) {
				flags |= PURPLE_MESSAGE_NICK;
			}
		}
	}

	if (mention_roles && guild && mentionable) {
		DiscordUser *self = discord_get_user(da, da->self_user_id);
		if (self) {
			DiscordGuildMembership *membership = g_hash_table_lookup_int64(self->guild_memberships, guild->id);

			if (membership) {
				for (i = json_array_get_length(mention_roles) - 1; i >= 0; i--) {
					guint64 id = to_int(json_array_get_string_element(mention_roles, i));

					for (guint j = 0; j < membership->roles->len; j++) {
						guint64 role_id = g_array_index(membership->roles, guint64, j);

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

	/* Ping for @everyone, but only if we didn't suppress it in the channel */

	gboolean mention_everyone = json_object_get_boolean_member(data, "mention_everyone");
	gboolean everyone_suppressed = channel ? channel->suppress_everyone : FALSE;

	if (mention_everyone && !everyone_suppressed) {
		flags |= PURPLE_MESSAGE_NICK;
	}

	// Find the conversation for adding the emoji's to
	if (channel_id_s && g_hash_table_contains(da->one_to_ones, channel_id_s)) {
		PurpleIMConversation *imconv;

		gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
		imconv = purple_conversations_find_im_with_account(username, da->account);

		conv = PURPLE_CONVERSATION(imconv);
	} else {
		PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));

		conv = PURPLE_CONVERSATION(chatconv);
	}

	/* Replace <:emoji:id> with emojis */
	tmp = g_regex_replace_eval(emoji_regex, escaped_content, -1, 0, 0, discord_replace_emoji, conv, NULL);

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

	/* Handle thread formatting */
	if (thread) {
		time_t ts = discord_time_from_snowflake(thread->id);
		time_t msg_ts = discord_time_from_snowflake(msg_id);
		const gchar *color = "#606060";
		const gchar *indicator;
		if (thread->last_message_id == 0 || msg_ts == ts) {
			indicator = purple_account_get_string(da->account, "parent-indicator", "◈ ");
		} else {
			indicator = purple_account_get_string(da->account, "thread-indicator", "⤷ ");
		}
		// Do this manually because msg counts for parent channel, not thread
		thread->last_message_id = msg_id;
		gchar *thread_ts = discord_get_formatted_thread_timestamp(ts);

		if (escaped_content && *escaped_content) {
			tmp = g_strdup_printf(
				"%s%s: <font color=\"%s\">%s</font>",
				indicator,
				thread_ts,
				color,
				escaped_content
			);
			g_free(escaped_content);
			escaped_content = tmp;
			tmp = NULL;
		}
		g_free(thread_ts);
	}

	if (stickers != NULL) {
		guint stickers_len = json_array_get_length(stickers);

		for (guint n = 0; n < stickers_len; n++) {
			JsonObject *sticker = json_array_get_object_element(stickers, n);
			const gchar *sticker_id = json_object_get_string_member(sticker, "id");
			const gchar *sticker_format = json_object_get_int_member(sticker, "format_type") == 3 ? "json" : "png";

			tmp = g_strdup_printf("%s\nhttps://" DISCORD_CDN_SERVER "/stickers/%s.%s", escaped_content, sticker_id, sticker_format);
			g_free(escaped_content);
			escaped_content = tmp;
		}
	}

	if (embeds != NULL) {
		GString *embed_str = g_string_new(NULL);
		guint embeds_len = json_array_get_length(embeds);
		static const gchar *border_format = "<font back=\"#%06x\" color=\"#%06x\"> </font> ";

		for (guint n = 0; n < embeds_len; n++) {
			JsonObject *embed = json_array_get_object_element(embeds, n);
			JsonObject *author = json_object_get_object_member(embed, "author");
			JsonObject *footer = json_object_get_object_member(embed, "footer");
			JsonObject *image = json_object_get_object_member(embed, "image");
			JsonObject *video = json_object_get_object_member(embed, "video");
			JsonArray *fields = json_object_get_array_member(embed, "fields");
			gint64 color = 0xcccccc;

			if (json_object_has_member(embed, "color")) {
				color = json_object_get_int_member(embed, "color");
			}

			if (author != NULL) {
				// author name (url)
				const gchar *author_name = json_object_get_string_member(author, "name");
				const gchar *author_url = json_object_get_string_member(author, "url");

				g_string_append_printf(embed_str, border_format, color, color);
				if (author_url) {
					g_string_append_printf(embed_str, "<a href=\"%s\">", author_url);
				}
				if (author_name) {
					g_string_append_printf(embed_str, "<b>%s</b>", author_name);
				} else {
					g_string_append(embed_str, "<b>Unknown author</b>");
				}
				if (author_url) {
					g_string_append(embed_str, "</a>");
				}
				g_string_append(embed_str, "<br/>");
			}

			if (json_object_has_member(embed, "title")) {
				// title (url)
				const gchar *title = json_object_get_string_member(embed, "title");
				const gchar *url = json_object_get_string_member(embed, "url");

				g_string_append_printf(embed_str, border_format, color, color);
				if (url) {
					g_string_append_printf(embed_str, "<a href=\"%s\">", url);
				}

				tmp = markdown_convert_markdown(title, FALSE, TRUE);
				g_string_append(embed_str, tmp);
				g_free(tmp);

				if (url) {
					g_string_append(embed_str, "</a>");
				}
				g_string_append(embed_str, "<br/>");

			} else if (json_object_has_member(embed, "url")) {
				// bare url
				const gchar *url = json_object_get_string_member(embed, "url");

				g_string_append_printf(embed_str, border_format, color, color);
				g_string_append_printf(embed_str, "%s<br/>", url);
			}

			if (json_object_has_member(embed, "description")) {
				// description
				const gchar *description = json_object_get_string_member(embed, "description");

				g_string_append_printf(embed_str, border_format, color, color);

				tmp = markdown_convert_markdown(description, FALSE, TRUE);
				g_string_append(embed_str, tmp);
				g_free(tmp);

				g_string_append(embed_str, "<br/>");
			}

			if (fields != NULL) {
				guint j, fields_len = json_array_get_length(fields);
				// loop over fields
				for(j = 0; j < fields_len; j++) {
					JsonObject *field = json_array_get_object_element(fields, j);
					const gchar *field_title = json_object_get_string_member(field, "name");
					const gchar *field_text = json_object_get_string_member(field, "value");
					//TODO inline?

					if (field_title) {
						g_string_append_printf(embed_str, border_format, color, color);
						tmp = markdown_convert_markdown(field_title, FALSE, TRUE);
						g_string_append_printf(embed_str, "<b>%s</b> ", tmp);
						g_free(tmp);
						g_string_append(embed_str, "<br/>");
					}
					if (field_text) {
						g_string_append_printf(embed_str, border_format, color, color);
						tmp = markdown_convert_markdown(field_text, FALSE, TRUE);
						g_string_append(embed_str, tmp);
						g_free(tmp);
						g_string_append(embed_str, "<br/>");
					}
				}
			}

			if (image != NULL && json_object_has_member(image, "url")) {
				const gchar *url = json_object_get_string_member(image, "url");

				g_string_append_printf(embed_str, border_format, color, color);
				g_string_append_printf(embed_str, "%s<br/>", url);
			}

			if (video != NULL && json_object_has_member(video, "url")) {
				const gchar *url = json_object_get_string_member(video, "url");

				g_string_append_printf(embed_str, border_format, color, color);
				g_string_append_printf(embed_str, "%s<br/>", url);
			}

			// footer | time

			g_string_append_printf(embed_str, border_format, color, color);

			if (footer != NULL) {
				// footer - XXX is this really the only one without markdown?
				const gchar *footer_text = json_object_get_string_member(footer, "text");
				if (footer_text != NULL) {
					g_string_append(embed_str, footer_text);
					g_string_append(embed_str, " | ");
				}
			}

			g_string_append(embed_str, purple_utf8_strftime("%c", NULL));
			g_string_append(embed_str, "<br/>");
		}

		if (embeds_len > 0) {
			g_string_prepend(embed_str, "<br/>");
			g_string_prepend(embed_str, escaped_content);
			tmp = g_string_free(embed_str, FALSE);
			g_free(escaped_content);
			escaped_content = tmp;
		} else {
			g_string_free(embed_str, TRUE);
		}
	}

	if (channel_id_s && g_hash_table_contains(da->one_to_ones, channel_id_s)) {
		/* private message */

		if (author_id == da->self_user_id) {
			if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
				PurpleMessage *msg;

				gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);

				if (conv == NULL) {
					PurpleIMConversation *imconv;
					imconv = purple_conversations_find_im_with_account(username, da->account);
					if (imconv == NULL) {
						imconv = purple_im_conversation_new(da->account, username);
					}

					conv = PURPLE_CONVERSATION(imconv);
				}

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

			if (referenced_message != NULL) {

				gchar *reply_txt = discord_get_reply_text(da, guild, channel, referenced_message);

				purple_conversation_write(conv, NULL, reply_txt, PURPLE_MESSAGE_SYSTEM, time(NULL));
				g_free(reply_txt);
			}

			if (escaped_content && *escaped_content && msg_type != MESSAGE_CALL) {
				purple_serv_got_im(da->pc, merged_username, escaped_content, flags, timestamp);
			} else if (msg_type == MESSAGE_CALL) {
				gchar *call_txt = g_strdup_printf(_("%s started a call"), merged_username);
				purple_conversation_write(conv, NULL, call_txt, PURPLE_MESSAGE_SYSTEM, timestamp);
				g_free(call_txt);
			}

			if (attachments) {
				for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
					JsonObject *attachment = json_array_get_object_element(attachments, i);

					const gchar *url = json_object_get_string_member(attachment, "proxy_url");
					const gchar *url_log = json_object_get_string_member(attachment, "url");
					const gchar *type = json_object_get_string_member(attachment, "content_type");
					if (url && type && g_str_has_prefix(type, "image") && (!strstr(url, "/SPOILER_")) && purple_account_get_bool(da->account, "display-images", FALSE)) {

						gchar *sized_url;
						gint64 height = json_object_get_int_member(attachment, "height");
						gint64 width = json_object_get_int_member(attachment, "width");
						if (purple_account_get_int(da->account, "image-size", 0) && purple_account_get_int(da->account, "image-size", 0) < width) {
							gdouble factor = (double) purple_account_get_int(da->account, "image-size", 0) / (gdouble) width;
							sized_url = g_strdup_printf("%s?width=%u&height=%u", url, (guint) ((gdouble) width * factor), (guint) ((gdouble) height * factor));
						} else {
							sized_url = g_strdup(url);
						}

						DiscordImgMsgContext *img_context = g_new0(DiscordImgMsgContext, 1);
						img_context->conv_id = -1;
						img_context->from = g_strdup(merged_username);
						img_context->url = sized_url;
						img_context->flags = flags | PURPLE_MESSAGE_IMAGES;
						img_context->timestamp = timestamp;

						if (conv == NULL) {
							PurpleIMConversation *imconv;
							imconv = purple_conversations_find_im_with_account(merged_username, da->account);
							if (imconv == NULL) {
								imconv = purple_im_conversation_new(da->account, merged_username);
							}

							conv = PURPLE_CONVERSATION(imconv);
						}

						discord_fetch_url(da, img_context->url, NULL, discord_download_image_cb, img_context);
						if (conv != NULL) {
							GList *l = conv->logs;
							if (l != NULL) {
								PurpleLog *log = l->data;
								purple_log_write(log, flags | PURPLE_MESSAGE_INVISIBLE, merged_username, timestamp, url_log);
							}
						}

					} else {
						purple_serv_got_im(da->pc, merged_username, url_log, flags, timestamp);
					}

				}
			}

			g_free(merged_username);
		}

		if (reactions != NULL) {
			PurpleIMConversation *imconv;
			const gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
			imconv = purple_conversations_find_im_with_account(username, da->account);
			conv = PURPLE_CONVERSATION(imconv);

			guint reactions_len = json_array_get_length(reactions);
			for (guint n = 0; n < reactions_len; n++) {
				JsonObject *reaction = json_array_get_object_element(reactions, n);
				JsonObject *emoji = json_object_get_object_member(reaction, "emoji");
				const gchar *emoji_id = json_object_get_string_member(emoji, "id");
				const gchar *emoji_name = json_object_get_string_member(emoji, "name");
				guint count = json_object_get_int_member(reaction, "count");
				gboolean is_me = json_object_get_boolean_member(reaction, "me");

				DiscordReaction *reaction_data;
				reaction_data = g_new0(DiscordReaction, 1);
				reaction_data->conv = conv;
				reaction_data->user_id = author_id;
				reaction_data->msg_time = discord_time_from_snowflake(msg_id);
				reaction_data->msg_txt = g_strdup(escaped_content);
				reaction_data->is_me = is_me;
				reaction_data->count = count;
				reaction_data->reaction = (emoji_id != NULL) ? g_strdup_printf("&lt;:%s:%s&gt;", emoji_name, emoji_id) : g_strdup(emoji_name);
				reaction_data->is_unreact = FALSE;

				if (purple_account_get_bool(da->account, "fetch-react-backlog", FALSE)) {
					gchar *emoji_str = (emoji_id != NULL) ? g_strdup_printf("%s:%s", emoji_name, emoji_id) : g_strdup(emoji_name);
					gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages/%" G_GUINT64_FORMAT "/reactions/%s?limit=10", channel_id, msg_id, purple_url_encode(emoji_str));
					discord_fetch_url(da, url, NULL, discord_reactor_cb, reaction_data);
					g_free(emoji_str);
					g_free(url);
				} else {
					gchar *reaction_str = discord_get_react_text(da, NULL, username, reaction_data);
					discord_free_reaction(reaction_data);

					if (reaction_str != NULL) {
						purple_conversation_write_system_message(conv, reaction_str, PURPLE_MESSAGE_SYSTEM);
						g_free(reaction_str);
					}
				}
			}
		}

	} else if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
		/* Open the buffer if it's not already */
		gboolean mentioned = flags & PURPLE_MESSAGE_NICK;

		if (
			(mentioned && purple_account_get_bool(da->account, "open-chat-on-mention", TRUE)) ||
			discord_treat_room_as_small(da, channel_id, guild)
		) {
			//discord_open_chat(da, channel_id, mentioned);
			gboolean fetched_history = discord_join_chat_by_id(da, channel_id, mentioned);
			if (fetched_history) {
				g_free(escaped_content);
				g_free(channel_id_s);
				return msg_id;
			}
		}

		gchar *name = NULL;
		if (json_object_has_member(data, "webhook_id")) {
			name = g_strdup(json_object_get_string_member(author_obj, "username"));
		} else {
			DiscordUser *author = discord_upsert_user(da->new_users, author_obj);
			name = discord_create_nickname(author, guild, channel);
		}

		if (referenced_message != NULL && msg_type != MESSAGE_THREAD_STARTER_MESSAGE) {
			gchar *reply_txt = discord_get_reply_text(da, guild, channel, referenced_message);
			if (conv == NULL) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
				conv = PURPLE_CONVERSATION(chatconv);
			}

			if (conv != NULL) {
				purple_conversation_write_system_message(conv, reply_txt, PURPLE_MESSAGE_SYSTEM);
			}
			g_free(reply_txt);
		}

		if (
				escaped_content &&
				*escaped_content &&
				msg_type != MESSAGE_GUILD_MEMBER_JOIN &&
				msg_type != MESSAGE_CALL &&
				msg_type != MESSAGE_THREAD_CREATED &&
				msg_type != MESSAGE_THREAD_STARTER_MESSAGE
			)
		{
			purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, escaped_content, timestamp);
			if (conv == NULL) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
				conv = PURPLE_CONVERSATION(chatconv);
			}

		} else if (msg_type == MESSAGE_GUILD_MEMBER_JOIN) {
			gchar *join_txt = g_strdup_printf(_("%s joined the guild!"), name);
			if (conv != NULL)
				purple_conversation_write(conv, NULL, join_txt, PURPLE_MESSAGE_SYSTEM, timestamp);
			g_free(join_txt);
			//return msg_id;
		} else if (msg_type == MESSAGE_CALL) {
			gchar *call_txt = g_strdup_printf(_("%s started a call"), name);
			if (conv != NULL) {
				purple_conversation_write(conv, NULL, call_txt, PURPLE_MESSAGE_SYSTEM, timestamp);
			}
			g_free(call_txt);
			//return msg_id;
		} else if (msg_type == MESSAGE_THREAD_STARTER_MESSAGE || msg_type == MESSAGE_THREAD_CREATED) {
			JsonObject *thread_root = json_object_get_object_member(data, "message_reference");
			guint64 ref_id = to_int(json_object_get_string_member(thread_root, "message_id"));
			time_t ref_timestamp = discord_time_from_snowflake(ref_id);
			gchar *timestring = discord_parse_timestamp(ref_timestamp);
			const gchar *thread_name = thread ? thread->name : escaped_content; // MESSAGE_THREAD_CREATED msgs have thread name as their content
			gchar *new_thread_txt;
			if (ref_timestamp > DISCORD_EPOCH_MS/1000) {
				new_thread_txt = g_strdup_printf(_("%s started thread \"%s\" from message at %s"), name, thread_name, timestring);
			} else {
				new_thread_txt = g_strdup_printf(_("%s started thread \"%s\""), name, thread_name);
			}
			g_free(timestring);
			if (conv != NULL) {
				purple_conversation_write(conv, NULL, new_thread_txt, PURPLE_MESSAGE_SYSTEM, timestamp);
			}
			g_free(new_thread_txt);


			if (msg_type == MESSAGE_THREAD_STARTER_MESSAGE && thread) {
				if (referenced_message) {
					const gchar *msg_txt = json_object_get_string_member(referenced_message, "content");
					JsonObject *tstart_author = json_object_get_object_member(referenced_message, "author");
					guint64 tstart_author_id = to_int(json_object_get_string_member(tstart_author, "id"));

					PurpleMessageFlags tstart_flags;
					if (tstart_author_id == da->self_user_id) {
						tstart_flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
					} else {
						tstart_flags = PURPLE_MESSAGE_RECV;
					}
					DiscordUser *tstart_user = discord_upsert_user(da->new_users, tstart_author);
					gchar *tstart_username = discord_get_display_name_or_unk(da, guild, channel, tstart_user, tstart_author);
					time_t ts = discord_time_from_snowflake(thread->id);
						const gchar *color = "#606060";
						const gchar *indicator = purple_account_get_string(da->account, "parent-indicator", "◈ ");
						gchar *thread_ts = discord_get_formatted_thread_timestamp(ts);

						if (msg_txt && *msg_txt) {
							tmp = g_strdup_printf("%s%s: <font color=\"%s\">%s</font>", indicator, thread_ts, color, msg_txt);
						}
					purple_serv_got_chat_in(da->pc, discord_chat_hash(channel->id), tstart_username, tstart_flags, tmp, ref_timestamp);
					if (tmp)
						g_free(tmp);
					g_free(tstart_username);
				} else {
					// Get array of messages because single-message endpoint is bot-only
					gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=5&after=%" G_GUINT64_FORMAT, channel_id, ref_id-1);
					discord_fetch_url(da, url, NULL, discord_thread_parent_cb, from_int(thread->id));
					g_free(url);
					//thread->last_message_id = thread->id;
				}
			}
		}

		if (attachments) {
			for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
				JsonObject *attachment = json_array_get_object_element(attachments, i);

				const gchar *url = json_object_get_string_member(attachment, "proxy_url");
				const gchar *url_log = json_object_get_string_member(attachment, "url");
				const gchar *type = json_object_get_string_member(attachment, "content_type");

				if (url && type && g_str_has_prefix(type, "image") && (!strstr(url, "/SPOILER_")) && purple_account_get_bool(da->account, "display-images", FALSE)) {

					gchar *sized_url;
					gint64 height = json_object_get_int_member(attachment, "height");
					gint64 width = json_object_get_int_member(attachment, "width");
					if (purple_account_get_int(da->account, "image-size", 0) && purple_account_get_int(da->account, "image-size", 0) < width) {
						gdouble factor = (double) purple_account_get_int(da->account, "image-size", 0) / (gdouble) width;
						sized_url = g_strdup_printf("%s?width=%u&height=%u", url, (guint) ((gdouble) width * factor), (guint) ((gdouble) height * factor));
					} else {
						sized_url = g_strdup(url);
					}

					DiscordImgMsgContext *img_context = g_new0(DiscordImgMsgContext, 1);
					img_context->conv_id = discord_chat_hash(channel_id);
					img_context->from = g_strdup(name);
					img_context->url = sized_url;
					img_context->flags = flags | PURPLE_MESSAGE_IMAGES;
					img_context->timestamp = timestamp;

					if (conv == NULL) {
						PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
 						conv = PURPLE_CONVERSATION(chatconv);
					}

					if (conv != NULL) {
						if (discord_treat_room_as_small(da, channel_id, guild) || purple_account_get_bool(da->account, "display-images-large-servers", FALSE) ) {
							discord_fetch_url(da, img_context->url, NULL, discord_download_image_cb, img_context);
							GList *l = conv->logs;
							if (l != NULL) {
								PurpleLog *log = l->data;
								purple_log_write(log, flags | PURPLE_MESSAGE_INVISIBLE, name, timestamp, url_log);
							}
						} else {
							purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, url_log, timestamp);
						}
					} else {
						purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, url_log, timestamp);
					}
				} else {
					purple_serv_got_chat_in(da->pc, discord_chat_hash(channel_id), name, flags, url_log, timestamp);
				}
			}
		}

		if (reactions != NULL) {
			if (conv == NULL) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
				conv = PURPLE_CONVERSATION(chatconv);
			}
			if (conv != NULL) {
					guint reactions_len = json_array_get_length(reactions);
					for (guint n = 0; n < reactions_len; n++) {
						JsonObject *reaction = json_array_get_object_element(reactions, n);
						JsonObject *emoji = json_object_get_object_member(reaction, "emoji");
						const gchar *emoji_id = json_object_get_string_member(emoji, "id");
						const gchar *emoji_name = json_object_get_string_member(emoji, "name");
						gboolean is_me = json_object_get_boolean_member(reaction, "me");
						guint count = json_object_get_int_member(reaction, "count");

						DiscordReaction *reaction_data;
						reaction_data = g_new0(DiscordReaction, 1);
						reaction_data->conv = conv;
						reaction_data->user_id = author_id;
						reaction_data->msg_time = discord_time_from_snowflake(msg_id);
						reaction_data->msg_txt = g_strdup(escaped_content);
						reaction_data->is_me = is_me;
						reaction_data->count = count;
						reaction_data->reaction = (emoji_id != NULL) ? g_strdup_printf("&lt;:%s:%s&gt;", emoji_name, emoji_id) : g_strdup(emoji_name);
						reaction_data->is_unreact = FALSE;

						if (purple_account_get_bool(da->account, "fetch-react-backlog", FALSE)) {
							gchar *emoji_str = (emoji_id != NULL) ? g_strdup_printf("%s:%s", emoji_name, emoji_id) : g_strdup(emoji_name);
							gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages/%" G_GUINT64_FORMAT "/reactions/%s?limit=10", channel_id, msg_id, purple_url_encode(emoji_str));
							discord_fetch_url(da, url, NULL, discord_reactor_cb, reaction_data);
							g_free(emoji_str);
							g_free(url);
						} else {
							gchar *ppl = g_strdup_printf(_("%d %s"), count, count == 1 ? _("person") : _("people"));
							gchar *reaction_str = discord_get_react_text(da, NULL, ppl, reaction_data);
							discord_free_reaction(reaction_data);

							if (reaction_str != NULL) {
								purple_conversation_write_system_message(conv, reaction_str, PURPLE_MESSAGE_SYSTEM);
								g_free(reaction_str);
							}
						}
					}

			}
		}

		g_free(name);
	}

	g_free(escaped_content);

	if (channel != NULL && msg_id > channel->last_message_id && !thread) {
		channel->last_message_id = msg_id;
	}

	g_free(channel_id_s);
	return msg_id;
}

struct discord_group_typing_data {
	guint64 channel_id;
	DiscordAccount *da;
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
	gchar *old_safe = NULL;

	if (old != NULL) {
		old_safe = g_strdup(old); // The pointer to 'old' can be free'd by the _remove() to copy it
		g_hash_table_remove(guild->nicknames_rev, old);
	}

	/* Nick change */
	gchar *nick = discord_alloc_nickname(user, guild, new);

	if (!purple_strequal(old_safe, nick)) {
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
	}

	g_free(old_safe);
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
		gchar *uname = discord_create_nickname(recipient, NULL, channel);

		if (uname != NULL) {
			g_string_append(name, uname);

			if (l->next) {
				g_string_append(name, ", ");
			}

			g_free(uname);
		}
	}

	return g_string_free(name, FALSE);
}

DiscordChannel *
discord_channel_from_chat(DiscordAccount *da, PurpleChat *chat)
{
	/* Grab the ID */
	GHashTable *components = purple_chat_get_components(chat);
	const gchar *chat_id = g_hash_table_lookup(components, "id");

	if (!chat_id)
		return NULL;

	/* Lookup the channel */
	return discord_get_channel_global(da, chat_id);
}

PurpleChat *
discord_find_chat_from_node(const PurpleAccount *account, const char *id, PurpleBlistNode *root)
{
	PurpleBlistNode *node;

	for (
		node = root;
		node != NULL;
		node = purple_blist_node_next(node, TRUE)
	) {
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

		g_free(id_str);
	}
}

static void
discord_got_group_dm_name(DiscordChannel *channel, DiscordUser *recipient, gboolean joiner)
{
	g_return_if_fail(recipient != NULL);

	unsigned count = (unsigned) (guintptr) g_hash_table_lookup(channel->names, recipient->name);
	unsigned updated = joiner ? (count + 1) : (count - 1);

	g_hash_table_replace(channel->names, g_strdup(recipient->name), (void *) (guintptr) updated);
}

static void
discord_got_group_dm(DiscordAccount *da, JsonObject *data)
{
	DiscordChannel *channel = discord_new_channel(data);
	JsonArray *recipients = json_object_get_array_member(data, "recipients");

	/* In order to efficiently strip discriminators, we need to maintain a
	 * set of names, so we can check in constant-time whether there would
	 * be a collision */

	channel->names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	DiscordUser *self = discord_get_user(da, da->self_user_id);
	discord_got_group_dm_name(channel, self, TRUE);

	for (int i = json_array_get_length(recipients) - 1; i >= 0; i--) {
		DiscordUser *recipient =
			discord_upsert_user(da->new_users,
								json_array_get_object_element(recipients, i));

		channel->recipients = g_list_prepend(channel->recipients, g_memdup2(&(recipient->id), sizeof(guint64)));

		discord_got_group_dm_name(channel, recipient, TRUE);
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
discord_handle_guild_member_update(DiscordAccount *da, guint64 guild_id, JsonObject *data) {
	DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
	DiscordGuild *guild = discord_get_guild(da, guild_id);

	if (guild && user) {
		discord_update_status(user, json_object_get_object_member(data, "presence"));

		const gchar *new_nick = json_object_get_string_member(data, "nick");
		const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, user->id);

		if (!purple_strequal(new_nick, old_nick)) {
			discord_got_nick_change(da, user, guild, new_nick, old_nick, FALSE);
		}

		DiscordGuildMembership *guild_membership = g_hash_table_lookup_int64(user->guild_memberships, guild_id);
		if (guild_membership == NULL) {

			guild_membership = discord_new_guild_membership(guild_id, data);
			g_hash_table_replace_int64(user->guild_memberships, guild_membership->id, guild_membership);
			g_hash_table_replace_int64(guild->members, user->id, NULL);

			g_free(discord_alloc_nickname(user, guild, guild_membership->nick));
		}

		if (guild_membership != NULL) {
			g_array_set_size(guild_membership->roles, 0);
			JsonArray *roles = json_object_get_array_member(data, "roles");
			int roles_len = json_array_get_length(roles);
			for (int k = 0; k < roles_len; k++) {
				guint64 role = to_int(json_array_get_string_element(roles, k));
				g_array_append_val(guild_membership->roles, role);
			}
		}

		//Refresh the user list of all open chats
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, guild->channels);
		gchar *nickname = discord_create_nickname(user, guild, NULL);
		g_return_if_fail(nickname != NULL);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			DiscordChannel *channel = value;

			PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));
			if (chat == NULL) {
				//Skip over closed chats
				continue;
			}

			if ((user->status ^ USER_MOBILE) == USER_OFFLINE) {
				if (purple_chat_conversation_has_user(chat, nickname)) {
					purple_chat_conversation_remove_user(chat, nickname, NULL);
				}

			} else if (!purple_chat_conversation_has_user(chat, nickname)) {
				guint64 permission = discord_compute_permission(da, user, channel);

				/* must have READ_MESSAGES */
				if ((permission & PERM_VIEW_CHANNEL)) {
					if (user->id == da->self_user_id) {
						purple_chat_conversation_set_nick(chat, nickname);
					}

					PurpleChatUserFlags cbflags = discord_get_user_flags_from_permissions(user, permission);
					purple_chat_conversation_add_user(chat, nickname, NULL, cbflags, FALSE);
				}

			}
		}
		g_free(nickname);

		//TODO check if this is ourselves that's getting updated and remove channels from the buddy list
	}
}

static void discord_send_lazy_guild_request(DiscordAccount *da, DiscordGuild *guild);

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

			gchar *nickname = discord_create_nickname(user, guild, NULL);

			g_hash_table_iter_init(&iter, guild->channels);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				DiscordChannel *channel = value;
				PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));

				if (chat != NULL) {
					if ((user->status ^ USER_MOBILE) == USER_OFFLINE) {
						if (purple_chat_conversation_has_user(chat, nickname)) {
							purple_chat_conversation_remove_user(chat, nickname, NULL);
						}

					} else if (!purple_chat_conversation_has_user(chat, nickname)) {
						guint64 permission = discord_compute_permission(da, user, channel);

						/* must have READ_MESSAGES */
						if ((permission & PERM_VIEW_CHANNEL)) {
							if (user->id == da->self_user_id) {
								purple_chat_conversation_set_nick(chat, nickname);
							}

							PurpleChatUserFlags cbflags = discord_get_user_flags_from_permissions(user, permission);
							purple_chat_conversation_add_user(chat, nickname, NULL, cbflags, FALSE);
						}

					}
				}
			}
			g_free(nickname);

		} else if (username) {
			const gchar *status = json_object_get_string_member(data, "status");
			purple_protocol_got_user_status(da->account, username, status, "message", user->game ? user->game : user->custom_status, NULL);
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
				purple_protocol_got_user_status(da->account, new_username_full, status, "message", user->game ? user->game : user->custom_status, NULL);
				purple_protocol_got_user_idle(da->account, new_username_full, idle_since ? TRUE : FALSE, 0);
				purple_protocol_got_user_status(da->account, username, "offline", NULL);

				const gchar *old_alias = purple_buddy_get_local_alias(old_buddy);
				if (old_alias != NULL && *old_alias) {
					purple_buddy_set_local_alias(buddy, old_alias);
				}
			}
		}

		g_free(username);
	} else if (purple_strequal(type, "GUILD_MEMBER_LIST_UPDATE")) {

		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		JsonArray *ops = json_object_get_array_member(data, "ops");
		int ops_len = json_array_get_length(ops);
		guint max_synced = 0;

		for (int i = 0; i < ops_len; i++) {
			JsonObject *op = json_array_get_object_element(ops, i);
			const gchar *optype = json_object_get_string_member(op, "op");

			if (purple_strequal(optype, "UPDATE") || purple_strequal(optype, "INSERT")) {
				JsonObject *item = json_object_get_object_member(op, "item");
				JsonObject *member = json_object_get_object_member(item, "member");

				if (member != NULL) {
					discord_handle_guild_member_update(da, guild_id, member);
				}

			} else if (purple_strequal(optype, "SYNC")) {
				JsonArray  *range = json_object_get_array_member(op, "range");
				guint synced_range_max = json_array_get_int_element(range, 1) + 1;

				if (synced_range_max > max_synced) {
					max_synced = synced_range_max;
				}

				JsonArray *items = json_object_get_array_member(op, "items");
				int items_len = json_array_get_length(items);
				for (int j = 0; j < items_len; j++) {
					JsonObject *item = json_array_get_object_element(items, j);
					JsonObject *member = json_object_get_object_member(item, "member");

					if (member != NULL) {
						discord_handle_guild_member_update(da, guild_id, member);
					}
				}
			}
		}

		DiscordGuild *guild = discord_get_guild(da, guild_id);
		if (max_synced >= guild->next_mem_to_sync) { // Should always be true for max_synced != 0, but just in case
			guint member_count = json_object_get_int_member(data, "member_count");
			guint online_count = json_object_get_int_member(data, "online_count");
			guint max_count = purple_account_get_int(da->account, "max-guild-presences", 200) > 0 ?
				(guint)(purple_account_get_int(da->account, "max-guild-presences", 200)-1) :
				G_MAXUINT;
			guint head_count = member_count > DISCORD_MAX_LARGE_THRESHOLD ? MIN(max_count, online_count) : MIN(max_count, member_count);
			if (guild && (head_count > guild->next_mem_to_sync)) {
				discord_send_lazy_guild_request(da, guild);
			} else if (guild && (head_count > guild->next_mem_to_sync - 100)) {
				guild->next_mem_to_sync = floor((gdouble)head_count / 100.0) * 100 + 100;
			}
		}


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
		DiscordChannel *channel = discord_get_channel_global_int_guild(da, to_int(channel_id), &guild);

		guint64 tmp = to_int(channel_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(tmp));

		if (!chatconv) {
			return;
		}

		JsonObject *json = json_object_get_object_member(data, "author");

		if (!json) {
			return;
		}

		gchar *n = discord_create_nickname_from_id(da, guild, channel, to_int(json_object_get_string_member(json, "id")));

		struct discord_group_typing_data ctx = {
			.da = da,
			.channel_id = tmp,
			.username = n,
			.set = FALSE,
			.free_me = FALSE
		};

		discord_set_group_typing(&ctx);

		g_free(n);
	} else if (purple_strequal(type, "MESSAGE_DELETE") || purple_strequal(type, "MESSAGE_DELETE_BULK")) {

		const gchar *channel_id = json_object_get_string_member(data, "channel_id");

		if (!channel_id) {
			return;
		}

		gchar *msg_times;
		if (purple_strequal(type, "MESSAGE_DELETE_BULK")) {
			JsonArray *ids = json_object_get_array_member(data, "ids");
			guint num_msgs = json_array_get_length(ids);
			guint printed_msgs = 2;
			if (num_msgs > 10) {
				msg_times = g_strdup_printf(_("%u messages between "), num_msgs);
			} else {
				printed_msgs = num_msgs;
				msg_times = g_strdup_printf(_("%u messages at "), num_msgs);
			}
			const gchar *comma = printed_msgs > 2 ? ", " : " ";

			for (guint n = 0; n < printed_msgs-1; n++) {
				const gchar *id = json_array_get_string_element(ids, n);
				gchar *timestring = discord_parse_timestamp(discord_time_from_snowflake(to_int(id)));
				gchar *tmp = g_strdup_printf("%s%s%s", msg_times, timestring, comma);
				g_free(timestring);
				g_free(msg_times);
				msg_times = tmp;
			}
			const gchar *id = json_array_get_string_element(ids, num_msgs-1);
			gchar *timestring = discord_parse_timestamp(discord_time_from_snowflake(to_int(id)));
			gchar *tmp = g_strdup_printf(_("%sand %s were deleted"), msg_times, timestring);
			g_free(timestring);
			g_free(msg_times);
			msg_times = tmp;
		} else {
			const gchar *id = json_object_get_string_member(data, "id");
			gchar *timestring = discord_parse_timestamp(discord_time_from_snowflake(to_int(id)));
			msg_times = g_strdup_printf(_("Message at %s was deleted"), timestring);
			g_free(timestring);
		}

		PurpleConversation *conv;
		if (g_hash_table_contains(da->one_to_ones, channel_id)) {
			gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id);
			PurpleIMConversation *imconv = purple_conversations_find_im_with_account(username, da->account);
			conv = PURPLE_CONVERSATION(imconv);

		} else {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(to_int(channel_id)));
			conv = PURPLE_CONVERSATION(chatconv);
		}
		if (conv == NULL) {
			g_free(msg_times);
			return;
		}

		purple_conversation_write_system_message(conv, msg_times, PURPLE_MESSAGE_SYSTEM);
		g_free(msg_times);

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
		if (channel == NULL) {
			DiscordChannel *thread = discord_get_thread_global_int_guild(da, to_int(channel_id), NULL);
			if (thread) {
				channel = discord_get_channel_global_int(da, thread->parent_id);
			}
		}

		if (channel != NULL) {
			DiscordGuild *guild = discord_get_guild(da, channel->guild_id);
			gchar *username = discord_create_nickname_from_id(da, guild, channel, user_id);

			struct discord_group_typing_data set = {
				.da = da,
				.channel_id = to_int(channel_id),
				.username = username,
				.set = TRUE,
				.free_me = FALSE
			};

			discord_set_group_typing(&set);

			struct discord_group_typing_data *clear = g_memdup2(&set, sizeof(set));
			clear->set = FALSE;
			clear->free_me = TRUE;

			g_timeout_add_seconds(10, discord_set_group_typing, clear);
		} else {
			DiscordUser *user = discord_get_user(da, user_id);
			gchar *merged_username = discord_create_fullname(user);

			purple_serv_got_typing(da->pc, merged_username, 10, PURPLE_IM_TYPING);

			g_free(merged_username);
		}
	} else if (purple_strequal(type, "CHANNEL_CREATE") || purple_strequal(type, "THREAD_CREATE")) {
		const gchar *channel_id = json_object_get_string_member(data, "id");
		gint64 channel_type = json_object_get_int_member(data, "type");
		const gchar *last_message_id = json_object_get_string_member(data, "last_message_id");

		if (channel_type == CHANNEL_DM) {
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
		} else if (channel_type == CHANNEL_GROUP_DM) {
			discord_got_group_dm(da, data);
		} else if (channel_type == CHANNEL_GUILD_TEXT || channel_type == CHANNEL_GUILD_NEWS || (channel_type >= CHANNEL_GUILD_NEWS_THREAD && channel_type != CHANNEL_GUILD_STAGE_VOICE)) {
			const gchar *guild_id = json_object_get_string_member(data, "guild_id");
			DiscordGuild *guild = discord_get_guild(da, to_int(guild_id));
			if (guild != NULL) {
				DiscordChannel *channel;
				if (channel_type < CHANNEL_GUILD_NEWS_THREAD) {
					channel = discord_add_channel(da, guild, data, guild->id);
				} else {
					const gchar *parent_id = json_object_get_string_member(data, "parent_id");
					DiscordChannel *parent = discord_get_channel_global_int(da, to_int(parent_id));
					discord_add_thread(da, guild, parent, data, guild->id);
					return;
				}

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
					if ((permission & PERM_VIEW_CHANNEL)) {
						discord_add_channel_to_blist(da, channel, NULL);
					}
				}
			}
		}

	} else if (purple_strequal(type, "CHANNEL_UPDATE") || purple_strequal(type, "THREAD_UPDATE")) {
		guint64 channel_id = to_int(json_object_get_string_member(data, "id"));
		gint64 channel_type = json_object_get_int_member(data, "type");

		if ((channel_type == CHANNEL_GUILD_TEXT && json_object_has_member(data, "topic")) || channel_type == CHANNEL_GROUP_DM) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));

			if (chatconv) {
				const gchar *new_topic = json_object_get_string_member(data, (channel_type == CHANNEL_GROUP_DM ? "name" : "topic"));
				purple_chat_conversation_set_topic(chatconv, NULL, new_topic);
			}
		}
	} else if (purple_strequal(type, "THREAD_LIST_SYNC")) {
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);
		JsonArray *threads = json_object_get_array_member(data, "threads");

		for (guint i = 0; i < json_array_get_length(threads); i++) {
			JsonObject *thread = json_array_get_object_element(threads, i);
			guint64 thread_id = to_int(json_object_get_string_member(thread, "id"));
			guint64 parent_id = to_int(json_object_get_string_member(thread, "parent_id"));
			DiscordChannel *parent = discord_get_channel_global_int(da, parent_id);

			if (parent && !g_hash_table_contains_int64(parent->threads, thread_id)) {
				discord_add_thread(da, guild, parent, thread, guild_id);
			}
		}

	} else if (purple_strequal(type, "RELATIONSHIP_ADD")) {
		discord_create_relationship(da, data);
	} else if (purple_strequal(type, "RELATIONSHIP_REMOVE")) {
		guint64 user_id = to_int(json_object_get_string_member(data, "id"));
		DiscordUser *user = discord_get_user(da, user_id);

		if (user) {
			gchar *username = discord_create_fullname(user);
			gint64 relationship_type = json_object_get_int_member(data, "type");

			if (username != NULL) {
				if (relationship_type == RELATIONSHIP_BLOCKED) {
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

		// New ready-handshake has membership of a guild outside of that guild
		// hack it back in so that the existing code can cope with it
		if (json_object_has_member(data, "merged_members")) {
			JsonArray *merged_members = json_object_get_array_member(data, "merged_members");
			JsonArray *guilds = json_object_get_array_member(data, "guilds");

			for (int i = json_array_get_length(merged_members) - 1; i >= 0; i--) {
				JsonArray *members = json_array_get_array_element(merged_members, i);
				JsonObject *guild = json_array_get_object_element(guilds, i);

				json_array_ref(members);
				json_object_set_array_member(guild, "members", members);
			}
		}

		discord_got_initial_load_users(da, json_object_get_member(data, "users"), NULL);
		discord_got_relationships(da, json_object_get_member(data, "relationships"), NULL);
		discord_got_private_channels(da, json_object_get_member(data, "private_channels"), NULL);
		discord_got_presences(da, json_object_get_member(data, "presences"), NULL);
		discord_got_guilds(da, json_object_get_member(data, "guilds"), NULL);
		discord_got_guild_settings(da, json_object_get_member(data, "user_guild_settings"));
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
		if (purple_account_get_bool(da->account, "populate-blist", TRUE)) {
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, da->new_guilds);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				DiscordGuild *guild = value;

				discord_buddy_guild(da, guild);
			}
		}

		if (json_object_has_member(data, "resume_gateway_url")) {
			const gchar *resume_gateway_url = json_object_get_string_member(data, "resume_gateway_url");
			if (strncmp(resume_gateway_url, "wss://", 6) == 0) {
				g_free(da->gateway_url);
				da->gateway_url = g_strdup(&resume_gateway_url[6]);
			}
		}

	} else if (purple_strequal(type, "READY_SUPPLEMENTAL")) {

		discord_got_presences(da, json_object_get_member(data, "merged_presences"), NULL);

		// Server membership for users other than ourselves comes through here

		if (json_object_has_member(data, "merged_members")) {
			JsonArray *merged_members = json_object_get_array_member(data, "merged_members");
			JsonArray *guilds = json_object_get_array_member(data, "guilds");

			for (int i = json_array_get_length(merged_members) - 1; i >= 0; i--) {
				JsonArray *members = json_array_get_array_element(merged_members, i);
				JsonObject *guild_obj = json_array_get_object_element(guilds, i);
				const gchar *guild_id_str = json_object_get_string_member(guild_obj, "guild_id");
				guint64 guild_id = to_int(guild_id_str);

				DiscordGuild *guild = discord_get_guild(da, guild_id);

				if (guild == NULL) {
					continue;
				}

				for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
					JsonObject *member = json_array_get_object_element(members, j);
					const gchar *user_id = json_object_get_string_member(member, "user_id");
					DiscordUser *u = discord_get_user(da, to_int(user_id));

					if (u == NULL) {
						continue;
					}

					DiscordGuildMembership *membership = discord_new_guild_membership(guild_id, member);
					g_hash_table_replace_int64(u->guild_memberships, membership->id, membership);
					g_hash_table_replace_int64(guild->members, u->id, NULL);

					g_free(discord_alloc_nickname(u, guild, membership->nick));

					JsonArray *roles = json_object_get_array_member(member, "roles");
					int roles_len = json_array_get_length(roles);
					for (int k = 0; k < roles_len; k++) {
						guint64 role = to_int(json_array_get_string_element(roles, k));
						g_array_append_val(membership->roles, role);
					}
				}
			}
		}

	} else if (purple_strequal(type, "GUILD_SYNC") || purple_strequal(type, "GUILD_CREATE") || purple_strequal(type, "GUILD_MEMBERS_CHUNK")) {
		const gchar *guild_id_str = json_object_get_string_member(data, "id");
		if (!guild_id_str || !*guild_id_str) {
			guild_id_str = json_object_get_string_member(data, "guild_id");
		}

		if (purple_strequal(type, "GUILD_CREATE")) {
			discord_populate_guild(da, data);
			discord_guild_get_offline_users(da, guild_id_str);
		}

		JsonArray *presences = json_object_get_array_member(data, "presences");
		JsonArray *members = json_object_get_array_member(data, "members");
		guint64 guild_id = to_int(guild_id_str);

		DiscordGuild *guild = discord_get_guild(da, guild_id);

		if (!guild) {
			purple_debug_error("discord", "Unknown guild %" G_GUINT64_FORMAT "\n", guild_id);
			return;
		}

		/* all members in small groups, online in large */
		for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
			JsonObject *member = json_array_get_object_element(members, j);
			DiscordUser *u = NULL;
			JsonObject *user = json_object_get_object_member(member, "user");
			if (user == NULL) {
				const gchar *user_id = json_object_get_string_member(member, "user_id");
				u = discord_get_user(da, to_int(user_id));
			} else {
				u = discord_upsert_user(da->new_users, user);
			}
			if (u == NULL) {
				continue;
			}

			DiscordGuildMembership *membership = discord_new_guild_membership(guild_id, member);
			g_hash_table_replace_int64(u->guild_memberships, membership->id, membership);
			g_hash_table_replace_int64(guild->members, u->id, NULL);

			g_free(discord_alloc_nickname(u, guild, membership->nick));

			JsonArray *roles = json_object_get_array_member(member, "roles");
			int roles_len = json_array_get_length(roles);
			for (int k = 0; k < roles_len; k++) {
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
				if ((permission & PERM_VIEW_CHANNEL)) {
					PurpleChatUserFlags cbflags = discord_get_user_flags_from_permissions(user, permission);
					gchar *nickname = discord_create_nickname(user, guild, channel);

					if (nickname != NULL) {
						users = g_list_prepend(users, nickname);
						flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
					}

					if (user->id == da->self_user_id) {
						purple_chat_conversation_set_nick(chat, nickname);
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
	} else if (purple_strequal(type, "GUILD_DELETE")) {
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);

		if (!guild) {
			purple_debug_error("discord", "Unknown guild %" G_GUINT64_FORMAT "\n", guild_id);
			return;
		}

		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, guild->channels);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			DiscordChannel *channel = value;

			PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));
			if (chat == NULL) {
				//Skip over closed chats
				continue;
			}

			purple_serv_got_chat_left(da->pc, discord_chat_hash(channel->id));
		}

		g_hash_table_remove_int64(da->new_guilds, guild_id);
		//TODO remove this guild's channels from the buddy list

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
		g_hash_table_replace_int64(guild->members, user->id, NULL);

		g_free(discord_alloc_nickname(user, guild, membership->nick));

		JsonArray *roles = json_object_get_array_member(data, "roles");
		int roles_len = json_array_get_length(roles);
		for (int k = 0; k < roles_len; k++) {
			guint64 role = to_int(json_array_get_string_element(roles, k));
			g_array_append_val(membership->roles, role);
		}

	} else if (purple_strequal(type, "GUILD_MEMBER_UPDATE")) {
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));

		discord_handle_guild_member_update(da, guild_id, json_object_get_object_member(data, "user"));

	} else if (purple_strequal(type, "GUILD_MEMBER_REMOVE")) {
		DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);

		if (!guild) {
			purple_debug_error("discord", "Unknown guild %" G_GUINT64_FORMAT "\n", guild_id);
			return;
		}

		const gchar *nickname = g_hash_table_lookup_int64(guild->nicknames, user->id);

		if (nickname != NULL) {

			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, guild->channels);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				DiscordChannel *channel = value;

				PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(channel->id));
				if (chat == NULL) {
					//Skip over closed chats
					continue;
				}

				purple_chat_conversation_remove_user(chat, nickname, NULL);
				g_hash_table_remove_int64(channel->permission_user_overrides, user->id);
			}

			g_hash_table_remove(guild->nicknames_rev, nickname);
		}

		g_hash_table_remove_int64(guild->members, user->id);
		g_hash_table_remove_int64(guild->nicknames, user->id);

		g_hash_table_remove_int64(user->guild_memberships, guild_id);

	} else if (purple_strequal(type, "GUILD_JOIN_REQUEST_UPDATE")) {
		gchar *info = NULL;
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);
		if (!guild) {
			return;
		}
		const gchar *status = json_object_get_string_member(data, "status");
		if (purple_strequal(status, "APPROVED")) {
			info = g_strdup_printf(_("Your request to join the server %s has been approved!"), guild->name);
		} else {
			JsonObject *request = json_object_get_object_member(data, "request");
			const gchar *rejection_reason = json_object_get_string_member(request, "rejection_reason");
			if (rejection_reason == NULL) {
				// Probably pending
				info = g_strdup_printf(_("Your request to join the server %s is currently pending. You will be notified of any updates regarding your request."), guild->name);
			} else {
				info = g_strdup_printf(_("Your request to join the server %s was rejected. The reason given was:\n\n%s"), guild->name, rejection_reason);
			}
		}

		purple_notify_info(
			da->pc,
			_("Server Join Request Update"),
			guild->name,
			info
		);
		g_free(info);

	} else if (purple_strequal(type, "CHANNEL_RECIPIENT_ADD") || purple_strequal(type, "CHANNEL_RECIPIENT_REMOVE")) {
		DiscordUser *user = discord_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		guint64 room_id = to_int(json_object_get_string_member(data, "channel_id"));
		PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, discord_chat_hash(room_id));

		DiscordGuild *guild = NULL;
		DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

		if (channel != NULL) {
			gchar *name = discord_create_nickname(user, guild, channel);

			gboolean joining = purple_strequal(type, "CHANNEL_RECIPIENT_ADD");

			if (joining) {
				if (user->id == da->self_user_id) {
					purple_chat_conversation_set_nick(chat, name);
				}
				PurpleChatUserFlags cbflags = discord_get_user_flags(da, guild, user);
				purple_chat_conversation_add_user(chat, name, NULL, cbflags, TRUE);
			} else {
				purple_chat_conversation_remove_user(chat, name, NULL);
			}

			/* We need to update the nicknames set for group DMs */

			if (channel->type == CHANNEL_GROUP_DM)
				discord_got_group_dm_name(channel, user, joining);

			g_free(name);
		}

	} else if (purple_strequal(type, "USER_GUILD_SETTINGS_UPDATE")) {
		discord_got_guild_setting(da, data);

	} else if (purple_strequal(type, "GUILD_ROLE_CREATE")) {
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		JsonObject *role = json_object_get_object_member(data, "role");
		DiscordGuild *guild = discord_get_guild(da, guild_id);

		if (guild != NULL && role != NULL) {
			discord_add_guild_role(guild, role);
		}

	} else if (purple_strequal(type, "GUILD_EMOJIS_UPDATE")) {
		guint64 guild_id = to_int(json_object_get_string_member(data, "guild_id"));
		DiscordGuild *guild = discord_get_guild(da, guild_id);
		JsonArray *emojis = json_object_get_array_member(data, "emojis");

		if (guild != NULL) {
			g_hash_table_remove_all(guild->emojis);
			for (int i = json_array_get_length(emojis) - 1; i >= 0; i--) {
				JsonObject *emoji = json_array_get_object_element(emojis, i);

				gchar *id = g_strdup(json_object_get_string_member(emoji, "id"));
				gchar *name = g_strdup(json_object_get_string_member(emoji, "name"));
				g_hash_table_replace(guild->emojis, name, id);
			}
		}

	} else if (purple_strequal(type, "MESSAGE_REACTION_ADD")) {

		const gchar *channel_id_s = json_object_get_string_member(data, "channel_id");
		guint64 channel_id = to_int(channel_id_s);
		guint64 message_id = to_int(json_object_get_string_member(data, "message_id"));
		guint64 user_id = to_int(json_object_get_string_member(data, "user_id"));
		JsonObject *emoji = json_object_get_object_member(data, "emoji");
		const gchar *emoji_name = json_object_get_string_member(emoji, "name");
		const gchar *emoji_id = json_object_get_string_member(emoji, "id");
		if (emoji_name == NULL) {
			emoji_name = "?";
		}

		PurpleConversation *conv;

		if (channel_id_s && g_hash_table_contains(da->one_to_ones, channel_id_s)) {
			PurpleIMConversation *imconv;

			gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
			imconv = purple_conversations_find_im_with_account(username, da->account);
			conv = PURPLE_CONVERSATION(imconv);
		} else {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
			conv = PURPLE_CONVERSATION(chatconv);
		}

		DiscordReaction *reaction;
		reaction = g_new0(DiscordReaction, 1);
		reaction->conv = conv;
		reaction->user_id = user_id;
		reaction->msg_time = discord_time_from_snowflake(message_id);
		reaction->msg_txt = NULL;
		reaction->is_me = user_id == da->self_user_id ? TRUE : FALSE;
		reaction->count = 1;
		reaction->reaction = (emoji_id != NULL) ? g_strdup_printf("&lt;:%s:%s&gt;", emoji_name, emoji_id) : g_strdup(emoji_name);
		reaction->is_unreact = FALSE;

		// Get array of messages because single-message endpoint is bot-only
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=5&after=%" G_GUINT64_FORMAT, channel_id, message_id-1);
		discord_fetch_url(da, url, NULL, discord_react_cb, reaction);
		g_free(url);


	} else if (purple_strequal(type, "MESSAGE_REACTION_REMOVE")) {

		const gchar *channel_id_s = json_object_get_string_member(data, "channel_id");
		guint64 channel_id = to_int(channel_id_s);
		guint64 message_id = to_int(json_object_get_string_member(data, "message_id"));
		guint64 user_id = to_int(json_object_get_string_member(data, "user_id"));
		JsonObject *emoji = json_object_get_object_member(data, "emoji");
		const gchar *emoji_name = json_object_get_string_member(emoji, "name");
		const gchar *emoji_id = json_object_get_string_member(emoji, "id");
		if (emoji_name == NULL) {
			emoji_name = "?";
		}

		PurpleConversation *conv;

		if (channel_id_s && g_hash_table_contains(da->one_to_ones, channel_id_s)) {
			PurpleIMConversation *imconv;

			gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
			imconv = purple_conversations_find_im_with_account(username, da->account);
			conv = PURPLE_CONVERSATION(imconv);
		} else {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(channel_id));
			conv = PURPLE_CONVERSATION(chatconv);
		}

		DiscordReaction *reaction;
		reaction = g_new0(DiscordReaction, 1);
		reaction->conv = conv;
		reaction->user_id = user_id;
		reaction->msg_time = discord_time_from_snowflake(message_id);
		reaction->msg_txt = NULL;
		reaction->is_me = user_id == da->self_user_id ? TRUE : FALSE;
		reaction->count = 1;
		reaction->reaction = (emoji_id != NULL) ? g_strdup_printf("&lt;:%s:%s&gt;", emoji_name, emoji_id) : g_strdup(emoji_name);
		reaction->is_unreact = TRUE;

		// Get array of messages because single-message endpoint is bot-only
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=5&after=%" G_GUINT64_FORMAT, channel_id, message_id-1);
		discord_fetch_url(da, url, NULL, discord_react_cb, reaction);
		g_free(url);

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

/* Should the channel be visible via permissions? */

static gboolean
discord_is_channel_visible(DiscordAccount *da, DiscordUser *user, DiscordChannel *channel)
{
	/* Fail gracefully */
	if (!user)
		return TRUE;

	/* We can always see non-guild (e.g. group DMs) */
	if (!channel->guild_id)
		return TRUE;

	/* Ensure that we actually have permissions for this channel */
	guint64 permission = discord_compute_permission(da, user, channel);

	/* must have READ_MESSAGES */
	if (!(permission & PERM_VIEW_CHANNEL))
		return FALSE;

	/* Drop voice channels since we don't support them anyway */
	if (channel->type == CHANNEL_VOICE || channel->type == CHANNEL_GUILD_STAGE_VOICE)
		return FALSE;

	/* Channel categories become new PurpleGroups so we don't
	 * handle explicitly */
	if (channel->type == CHANNEL_GUILD_CATEGORY)
		return FALSE;

	/* Other channels are visible */
	return TRUE;
}

static PurpleRoomlistRoom *
discord_get_room_category(DiscordAccount *da, GHashTable *id_to_category, guint64 parent_id, PurpleRoomlist *roomlist, PurpleRoomlistRoom *parent)
{
	/* No category -> no category */
	if (!parent_id)
		return parent;

	/* Lookup first */
	PurpleRoomlistRoom *room = g_hash_table_lookup_int64(id_to_category, parent_id);

	if (room)
		return room;

	/* Otherwise, let's create */
	DiscordChannel *channel = discord_get_channel_global_int(da, parent_id);

	if (!channel)
		return parent;

	room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, channel->name, parent);
	purple_roomlist_room_add_field(roomlist, room, (gpointer) channel->name);
	purple_roomlist_room_add(roomlist, room);

	/* Record it */
	g_hash_table_replace_int64(id_to_category, parent_id, room);
	return room;
}

static void
discord_roomlist_got_list(DiscordAccount *da, DiscordGuild *guild, gpointer user_data)
{
	PurpleRoomlist *roomlist = user_data;
	const gchar *guild_name = guild ? guild->name : _("Group DMs");
	PurpleRoomlistRoom *category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, guild_name, NULL);
	purple_roomlist_room_add_field(roomlist, category, (gpointer) guild_name);
	purple_roomlist_room_add_field(roomlist, category, (gpointer) NULL);
	purple_roomlist_room_add(roomlist, category);

	DiscordUser *user = discord_get_user(da, da->self_user_id);

	GHashTableIter iter;
	gpointer key, value;

	if (guild != NULL) {
		g_hash_table_iter_init(&iter, guild->channels);
	} else {
		g_hash_table_iter_init(&iter, da->group_dms);
	}

	GHashTable *id_to_category = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;
		PurpleRoomlistRoom *room;

		if (channel->type == CHANNEL_GUILD_CATEGORY)
			continue;

		if (!discord_is_channel_visible(da, user, channel))
			continue;

		gchar *channel_id = from_int(channel->id);

		/* Try to find the category */
		PurpleRoomlistRoom *local_category =
			discord_get_room_category(da, id_to_category, channel->parent_id, roomlist, category);

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, channel->name, local_category);
		purple_roomlist_room_add_field(roomlist, room, channel_id);
		purple_roomlist_room_add_field(roomlist, room, channel->topic);

		purple_roomlist_room_add(roomlist, room);
		g_free(channel_id);
	}

	g_hash_table_unref(id_to_category);
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

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Topic"), "topic", FALSE);
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
	const gchar *message = purple_status_get_attr_string(status, "message");

	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	JsonArray *activities = json_array_new();

	if (g_str_has_prefix(status_id, "set-")) {
		status_id = &status_id[4];
	}

	json_object_set_int_member(obj, "op", OP_PRESENCE_UPDATE);
	json_object_set_string_member(data, "status", status_id);
	json_object_set_int_member(data, "since", 0);

	if (message && *message) {
		JsonObject *game = json_object_new();

		if (purple_account_get_bool(account, "use-status-as-game", FALSE)) {
			json_object_set_int_member(game, "type", GAME_TYPE_PLAYING);
			json_object_set_string_member(game, "name", message);
		} else {
			json_object_set_int_member(game, "type", GAME_TYPE_CUSTOM_STATUS);
			json_object_set_string_member(game, "name", "Custom Status");
			json_object_set_string_member(game, "state", message);
		}

		json_array_add_object_element(activities, game);
	}

	json_object_set_array_member(data, "activities", activities);
	json_object_set_boolean_member(data, "afk", FALSE);
	json_object_set_string_member(data, "status", status_id);
	json_object_set_object_member(obj, "d", data);

	discord_socket_write_json(ya, obj);

	data = json_object_new();
	json_object_set_string_member(data, "status", status_id);

	if (message && *message) {
		JsonObject *custom_status = json_object_new();
		json_object_set_string_member(custom_status, "text", message);
		json_object_set_object_member(data, "custom_status", custom_status);

	} else {
		json_object_set_null_member(data, "custom_status");
	}

	postdata = json_object_to_string(data);

	discord_fetch_url_with_method(ya, "PATCH", "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/settings", postdata, NULL, NULL);

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

	json_object_set_int_member(obj, "op", OP_PRESENCE_UPDATE);
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

	for (
		node = purple_blist_get_root();
		node != NULL;
		node = purple_blist_node_next(node, TRUE)
	) {
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
static gboolean discord_capture_join_part(PurpleConversation *conv, const char *name, PurpleChatUserFlags flags, GHashTable *users);
static gulong join_signal = 0;
static gulong part_signal = 0;

typedef struct {
	DiscordAccount *da;
	DiscordUser *user;
} DiscordUserInviteResponseStore;

/* Always be quiet */

static gboolean
discord_capture_join_part(PurpleConversation *conv, const char *name, PurpleChatUserFlags flags, GHashTable *users)
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

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
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

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);

	g_free(store);
}

static void
discord_create_relationship(DiscordAccount *da, JsonObject *json)
{
	DiscordUser *user;
	if (json_object_has_member(json, "user")) {
		user = discord_upsert_user(da->new_users, json_object_get_object_member(json, "user"));
	} else {
		user = discord_get_user(da, to_int(json_object_get_string_member(json, "user_id")));
	}
	g_return_if_fail(user != NULL);

	gint64 type = json_object_get_int_member(json, "type");
	gchar *merged_username = discord_create_fullname(user);

	if (type == RELATIONSHIP_PENDING_INCOMING) {
		/* request add */
		DiscordUserInviteResponseStore *store = g_new0(DiscordUserInviteResponseStore, 1);

		store->da = da;
		store->user = user;

		purple_account_request_authorization(da->account, merged_username, NULL, NULL, NULL, FALSE, discord_friends_auth_accept, discord_friends_auth_reject, store);
	} else if (type == RELATIONSHIP_FRIEND) {
		/* buddy on list */
		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, merged_username);

		if (buddy == NULL) {
			PurpleContact *buddy_contact = NULL;
			PurpleGroup *buddy_group = discord_get_or_create_default_group();

			// Special case: Check we're not migrating a friend from #0000 to just the username, so we can keep logs
			if (user->discriminator == 0) {
				gchar *old_username = g_strdup_printf("%s#0000", user->name);
				PurpleBuddy *old_buddy = purple_blist_find_buddy(da->account, old_username);
				if (old_buddy != NULL) {
					buddy_contact = purple_buddy_get_contact(old_buddy);
					buddy_group = purple_buddy_get_group(old_buddy);
				}
				g_free(old_username);
			}
			buddy = purple_buddy_new(da->account, merged_username, user->name);
			purple_blist_add_buddy(buddy, buddy_contact, buddy_group, NULL);
		}

		discord_get_avatar(da, user, TRUE);

	} else if (type == RELATIONSHIP_BLOCKED) {
		/* blocked buddy */
		purple_account_privacy_deny_add(da->account, merged_username, TRUE);

	} else if (type == RELATIONSHIP_PENDING_OUTGOING) {
		/* pending buddy */
	}

	g_free(merged_username);
}

static void
discord_got_initial_load_users(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *users = json_node_get_array(node);
	guint len = json_array_get_length(users);

	for (int i = len - 1; i >= 0; i--) {
		discord_upsert_user(da->new_users, json_array_get_object_element(users, i));
	}
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
			gchar *merged_username = NULL;

			/* One-to-one DM */
			if (recipients == NULL) {
				//New API
				recipients = json_object_get_array_member(channel, "recipient_ids");
				const gchar *user_id = json_array_get_string_element(recipients, 0);

				DiscordUser *user = discord_get_user(da, to_int(user_id));
				merged_username = discord_create_fullname(user);

			} else {
				// Old API
				JsonObject *user = json_array_get_object_element(recipients, 0);
				const gchar *username = json_object_get_string_member(user, "username");
				const gchar *discriminator = json_object_get_string_member(user, "discriminator");
				merged_username = discord_combine_username(username, discriminator);

			}

			if (merged_username != NULL) {
				g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(merged_username));
				g_hash_table_replace(da->one_to_ones_rev, g_strdup(merged_username), g_strdup(room_id));
				g_hash_table_replace(da->last_message_id_dm, g_strdup(room_id), g_strdup(last_message_id));

				g_free(merged_username);
			}
		} else if (room_type == 3) {
			discord_got_group_dm(da, channel);
		}
	}
}

static void
discord_got_presences(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	if(node == NULL) {
		return;
	}

	if (json_node_get_object(node)) {
		JsonObject *presences_obj = json_node_get_object(node);
		if (json_object_has_member(presences_obj, "friends")) {
			node = json_object_get_member(presences_obj, "friends");
		} else {
			return;
		}
	}
	JsonArray *presences = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(presences);

	for (i = len - 1; i >= 0; i--) {
		/* TODO convert to user object */
		JsonObject *presence = json_array_get_object_element(presences, i);
		const gchar *status = json_object_get_string_member(presence, "status");
		gchar *merged_username = NULL;
		JsonObject *game = NULL;

		if (json_object_has_member(presence, "user")) {
			//Old API
			JsonObject *user = json_object_get_object_member(presence, "user");
			const gchar *username = json_object_get_string_member(user, "username");
			const gchar *discriminator = json_object_get_string_member(user, "discriminator");
			merged_username = discord_combine_username(username, discriminator);

			game = json_object_get_object_member(presence, "game");

		} else {
			const gchar *user_id = json_object_get_string_member(presence, "user_id");
			DiscordUser *user = discord_get_user(da, to_int(user_id));
			merged_username = discord_create_fullname(user);

			JsonArray *activities = json_object_get_array_member(presence, "activities");
			if (json_array_get_length(activities) > 0) {
				game = json_array_get_object_element(activities, 0);
			}

		}
		const gchar *game_id = game ? json_object_get_string_member(game, "id") : "null";
		const gchar *game_name = game ? json_object_get_string_member(game, "name") : "";

		if (purple_strequal(game_id, "custom")) {
			game_name = json_object_get_string_member(game, "state");
		}

		purple_protocol_got_user_status(da->account, merged_username, status, "message", game_name, NULL);
		purple_protocol_got_user_idle(da->account, merged_username, purple_strequal(status, "idle"), 0);

		g_free(merged_username);
	}
}

static PurpleGroup *
discord_grab_group(const char *guild_name, const char *category_name, const gchar *category_id)
{
	/* Create the combined name */

	PurpleGroup *group = NULL;
	gchar *combined_name = NULL;
	g_return_val_if_fail(guild_name != NULL, NULL);

	if (category_name)
		combined_name = g_strdup_printf("%s: %s", guild_name, category_name);
	else
		combined_name = g_strdup(guild_name);

	for (PurpleBlistNode *node = purple_blist_get_root(); node != NULL; node = purple_blist_node_get_sibling_next(node)) {
		if (!PURPLE_BLIST_NODE_IS_GROUP(node)) {
			continue;
		}

		const gchar *id = purple_blist_node_get_string(node, "id");
		if (id == NULL && purple_strequal(combined_name, PURPLE_GROUP(node)->name)) {
			purple_blist_node_set_string(node, "id", category_id);
			group = PURPLE_GROUP(node);
			break;
		}
		if (purple_strequal(category_id, id)) {
			group = PURPLE_GROUP(node);
			if (!purple_strequal(combined_name, purple_group_get_name(group))) {
				purple_blist_rename_group(group, combined_name);
			}
			break;
		}
	}

	/* Make a group */
	if (!group) {
		group = purple_group_new(combined_name);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(group), "id", category_id);

		if (!group) {
			g_free(combined_name);
			return NULL;
		}
		purple_blist_add_group(group, NULL);
	}

	g_free(combined_name);
	return group;
}

static void
discord_buddy_guild(DiscordAccount *da, DiscordGuild *guild)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	DiscordUser *user = discord_get_user(da, da->self_user_id);

	if (!user) {
		purple_debug_info("discord", "Null user; aborting blist population\n");
		return;
	}

	g_hash_table_iter_init(&iter, guild->channels);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;

		if (!discord_is_channel_visible(da, user, channel))
			continue;

		/* Find/make a group */
		gchar *category_id = from_int(channel->parent_id);
		gchar *category_name = NULL;
		DiscordChannel *cat = g_hash_table_lookup_int64(guild->channels, channel->parent_id);

		if (cat)
			category_name = cat->name;
		if (purple_strequal(category_id, "0")) {
			g_free(category_id);
			category_id = from_int(guild->id);
		}

		gchar *namepref_id = g_strdup_printf("%" G_GUINT64_FORMAT "-abbr", guild->id);
		const gchar *guild_name = purple_account_get_string(da->account, namepref_id, guild->name);
		g_free(namepref_id);

		PurpleGroup *group = discord_grab_group(guild_name, category_name, category_id);
		g_free(category_id);

		if (!group)
			continue;

		discord_add_channel_to_blist(da, channel, group);
	}
}

void discord_guild_member_screening(DiscordAccount *da, JsonNode *node, gpointer user_data);

static void
discord_populate_guild(DiscordAccount *da, JsonObject *guild)
{
	DiscordGuild *g = discord_upsert_guild(da->new_guilds, guild);

	JsonArray *channels = json_object_get_array_member(guild, "channels");
	JsonArray *guild_roles = json_object_get_array_member(guild, "roles");
	JsonArray *members = json_object_get_array_member(guild, "members");

	for (int j = json_array_get_length(guild_roles) - 1; j >= 0; j--) {
		JsonObject *role = json_array_get_object_element(guild_roles, j);
		discord_add_guild_role(g, role);
	}

	for (int j = json_array_get_length(channels) - 1; j >= 0; j--) {
		JsonObject *channel = json_array_get_object_element(channels, j);

		DiscordChannel *c = discord_add_channel(da, g, channel, g->id);

		JsonArray *permission_overrides = json_object_get_array_member(channel, "permission_overwrites");

		for (int k = json_array_get_length(permission_overrides) - 1; k >= 0; k--) {
			JsonObject *permission_override = json_array_get_object_element(permission_overrides, k);
			discord_add_permission_override(c, permission_override);
		}
	}

	for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
		JsonObject *member = json_array_get_object_element(members, j);

		DiscordUser *u = NULL;
		JsonObject *user = json_object_get_object_member(member, "user");
		if (user == NULL) {
			const gchar *user_id = json_object_get_string_member(member, "user_id");
			u = discord_get_user(da, to_int(user_id));
		} else {
			u = discord_upsert_user(da->new_users, user);
		}
		if (u == NULL) {
			continue;
		}

		DiscordGuildMembership *membership = discord_new_guild_membership(g->id, member);
		g_hash_table_replace_int64(u->guild_memberships, membership->id, membership);
		g_hash_table_replace_int64(g->members, u->id, NULL);

		g_free(discord_alloc_nickname(u, g, membership->nick));

		JsonArray *roles = json_object_get_array_member(member, "roles");
		int roles_len = json_array_get_length(roles);
		for (int k = 0; k < roles_len; k++) {
			guint64 role = to_int(json_array_get_string_element(roles, k));
			g_array_append_val(membership->roles, role);
		}

		if (u->id == da->self_user_id && json_object_has_member(member, "pending")) {
			gboolean pending = json_object_get_boolean_member(member, "pending");
			if (pending) {
				gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/guilds/%" G_GUINT64_FORMAT "/member-verification?with_guild=false", g->id);
				discord_fetch_url_with_method(da, "GET", url, NULL, discord_guild_member_screening, g);
				g_free(url);
			}
		}
	}

	if (json_object_has_member(guild, "system_channel_id")) {
		g->system_channel_id = to_int(json_object_get_string_member(guild, "system_channel_id"));
	}
}

static void
discord_send_lazy_guild_request(DiscordAccount *da, DiscordGuild *guild)
{

	JsonObject *obj;
	JsonObject *d;

	gchar *guild_id = from_int(guild->id);
	guint last_synced = guild->next_mem_to_sync;

	d = json_object_new();
	json_object_set_string_member(d, "guild_id", guild_id);
	json_object_set_boolean_member(d, "typing", TRUE);
	json_object_set_boolean_member(d, "activities", TRUE);
	json_object_set_boolean_member(d, "threads", TRUE);
	json_object_set_array_member(d, "members", json_array_new());


	JsonObject *channels = json_object_new();
	DiscordUser *user = discord_get_user(da, da->self_user_id);

	// We can only request status updates for one channel at a time, try:
	//  1. the 'system_channel_id'
	//  2. the default channel when creating a server
	//  3. the first visible server

	DiscordChannel *channel = NULL;

	if (guild->system_channel_id) {
		channel = g_hash_table_lookup_int64(guild->channels, guild->system_channel_id);
	}
	if (!channel || !discord_is_channel_visible(da, user, channel)) {
		channel = g_hash_table_lookup_int64(guild->channels, guild->id);
	}
	if (!channel || !discord_is_channel_visible(da, user, channel)) {
		GHashTableIter iter;
		gpointer key;
		gpointer value;
		g_hash_table_iter_init(&iter, guild->channels);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			DiscordChannel *iter_channel = value;

			if (iter_channel->type == CHANNEL_GUILD_TEXT && discord_is_channel_visible(da, user, iter_channel)) {
				channel = iter_channel;
				break;
			}
		}
	}

	if (channel && discord_is_channel_visible(da, user, channel)) {
		JsonArray *user_ranges = json_array_new();
		if (last_synced > 0) {
			JsonArray *user_range = json_array_new();
			json_array_add_int_element(user_range, 0);
			json_array_add_int_element(user_range, 99);
			json_array_add_array_element(user_ranges, user_range);
		}
		for (guint i = last_synced; i < 200 + last_synced; i += 100) {
			JsonArray *user_range = json_array_new();
			json_array_add_int_element(user_range, i);
			json_array_add_int_element(user_range, i + 99);
			json_array_add_array_element(user_ranges, user_range);
		}

		gchar *channel_id = from_int(channel->id);
		json_object_set_array_member(channels, channel_id, user_ranges);
		g_free(channel_id);
	}

	json_object_set_object_member(d, "channels", channels);

	obj = json_object_new();
	json_object_set_int_member(obj, "op", OP_LAZY_GUILD_REQUEST);
	json_object_set_object_member(obj, "d", d);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);

	guild->next_mem_to_sync = 200 + last_synced;

	g_free(guild_id);
}

static void
discord_guild_get_offline_users(DiscordAccount *da, const gchar *guild_id)
{
	/*JsonObject *obj;
	JsonObject *d;

	// Try to request all offline users in this guild
	d = json_object_new();
	json_object_set_string_member(d, "guild_id", guild_id);
	json_object_set_string_member(d, "query", "");
	json_object_set_int_member(d, "limit", 0);
	json_object_set_boolean_member(d, "presences", TRUE);

	obj = json_object_new();
	json_object_set_int_member(obj, "op", OP_REQUEST_GUILD_MEMBERS);
	json_object_set_object_member(obj, "d", d);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);*/

	DiscordGuild *guild = discord_get_guild(da, to_int(guild_id));
	if (guild == NULL) {
		return;
	}

	discord_send_lazy_guild_request(da, guild);
}

static void
discord_got_guilds(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *guilds = json_node_get_array(node);
	guint len = json_array_get_length(guilds);
	JsonArray *guild_ids = json_array_new();
	//JsonObject *obj;

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *guild = json_array_get_object_element(guilds, i);
		const gchar *guild_id = json_object_get_string_member(guild, "id");
		discord_populate_guild(da, guild);

		if (guild_id != NULL) {
			json_array_add_string_element(guild_ids, guild_id);

			discord_guild_get_offline_users(da, guild_id);
		}
	}

	discord_print_guilds(da->new_guilds);

	/* Request more info about guilds (online/offline buddy status) */
	//XXX disable for now as it causes the websocket to disconnect with error 4001
	/*obj = json_object_new();
	json_object_set_int_member(obj, "op", OP_GUILD_SYNC);
	json_object_set_array_member(obj, "d", guild_ids);

	discord_socket_write_json(da, obj);

	json_object_unref(obj);*/

	/* XXX remove this in case above json_object_set_array_member is enabled again */
	json_array_unref(guild_ids);
}

/* If count is explicitly specified, use a static request (DMs).
 * If it is not, use a dynamic request (rooms).
 * TODO: Possible edge case if there are over 100 incoming DMs?
 */

static gboolean discord_get_room_history_limiting(DiscordAccount *da, guint64 id);

static void
discord_get_history(DiscordAccount *da, const gchar *channel_id, const gchar *last, int count)
{
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%s/messages?limit=%d&after=%s", channel_id, count ? count : 100, last);
	DiscordChannel *channel = discord_get_channel_global(da, channel_id);
	gboolean is_limited = discord_get_room_history_limiting(da, to_int(channel_id));

	if (channel && !is_limited) {
		discord_fetch_url(da, url, NULL, discord_got_history_of_room, channel);
	} else if (channel) {
		discord_fetch_url(da, url, NULL, discord_got_history_static, channel);
	} else {
		discord_fetch_url(da, url, NULL, discord_got_history_static, NULL);
	}

	g_free(url);
}


static guint64 discord_get_room_last_id(DiscordAccount *da, guint64 id);
static void discord_set_room_last_id(DiscordAccount *da, guint64 channel_id, guint64 last_id);

static void
discord_got_read_states(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *data = json_node_get_object(node);
	JsonArray *states = json_object_get_array_member(data, "entries");
	guint len = json_array_get_length(states);

	g_return_if_fail(purple_account_get_bool(da->account, "fetch-unread-on-start", TRUE));

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *state = json_array_get_object_element(states, i);

		const gchar *channel = json_object_get_string_member(state, "id");
		guint64 last_id = discord_get_room_last_id(da, to_int(channel));
		if (last_id == 0)
			last_id = da->last_load_last_message_id;
		gchar *last_id_s = from_int(last_id);
		gint mentions = json_object_get_int_member(state, "mention_count");

		if (channel) {
			gboolean isDM = g_hash_table_contains(da->one_to_ones, channel);

			if (isDM && mentions) {
				discord_get_history(da, channel, last_id_s, mentions * 2);
			} else if (!isDM) {
				DiscordGuild *dguild = NULL;
				DiscordChannel *dchannel = discord_get_channel_global_int_guild(da, to_int(channel), &dguild);
				guint64 remote_last_id = 0;
				if (dchannel)
					remote_last_id = dchannel->last_message_id;

				if (
					last_id < remote_last_id &&
					(
						discord_treat_room_as_small(da, to_int(channel), dguild) ||
						(
							mentions &&
							purple_account_get_bool(da->account, "open-chat-on-mention", TRUE)
						)
					)
				) {

					// It's easier if we make use of the join_chat_by_id call in
					// process_message, so retrieve a single message to send over there
					gchar *tmp = from_int(remote_last_id - 1);
					discord_get_history(da, channel, tmp, 1);
					g_free(tmp);

				} else if (mentions) {
					purple_debug_misc("discord", "%d unhandled mentions in channel %s\n", mentions, dchannel ? dchannel->name : channel);
				}
			}
		}

		g_free(last_id_s);
	}
}

static void
discord_got_guild_setting(DiscordAccount *da, JsonObject *settings)
{
	/* Lookup the guild in question */
	guint64 guild_id = to_int(json_object_get_string_member(settings, "guild_id"));
	DiscordGuild *guild = discord_get_guild(da, guild_id);

	if (!guild)
		return;

	/* Grab global settings */
	gboolean all_mute = json_object_get_boolean_member(settings, "muted");
	gboolean all_suppressed = json_object_get_boolean_member(settings, "suppress_everyone");
	DiscordNotificationLevel all_notification = json_object_get_int_member(settings, "message_notifications");

	/* Apply the guild-global settings */
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	g_hash_table_iter_init(&iter, guild->channels);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *channel = value;
		channel->muted = all_mute;
		channel->suppress_everyone = all_suppressed;
		channel->notification_level = all_notification;
	}

	/* Apply per-channel overrides */
	JsonArray *overrides = json_object_get_array_member(settings, "channel_overrides");
	guint olen = json_array_get_length(overrides);

	for (int j = olen - 1; j >= 0; j--) {
		JsonObject *override = json_array_get_object_element(overrides, j);

		/* Lookup overridden channel */
		guint64 channel_id = to_int(json_object_get_string_member(override, "channel_id"));
		DiscordChannel *channel = g_hash_table_lookup_int64(guild->channels, channel_id);

		if (!channel)
			continue;

		/* Apply overrides */
		channel->muted = json_object_get_boolean_member(override, "muted");
		purple_debug_info("discord", "%s: %smute\n", channel->name, channel->muted ? "" : "un");
		DiscordNotificationLevel level = json_object_get_int_member(override, "message_notifications");

		if (level != NOTIFICATIONS_INHERIT)
			channel->notification_level = level;
	}
}

static void
discord_got_guild_settings(DiscordAccount *da, JsonNode *node)
{
	JsonObject *data = json_node_get_object(node);
	JsonArray *guilds = json_object_get_array_member(data, "entries");
	guint len = json_array_get_length(guilds);

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *settings = json_array_get_object_element(guilds, i);
		discord_got_guild_setting(da, settings);
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
	discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/auth/mfa/totp", str, discord_login_response, NULL);

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

			purple_request_input(
				da->pc,
				_("Two-factor authentication"),
				_("Enter Discord auth code"),
				_("You can get this token from your two-factor authentication mobile app."),
				NULL, FALSE, FALSE, "",
				_("_Login"), G_CALLBACK(discord_mfa_text_entry),
				_("_Cancel"), G_CALLBACK(discord_mfa_cancel),
				purple_request_cpar_from_connection(da->pc),
				da
			);
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

		if (json_object_has_member(response, "captcha_key")) {
			/* Probably an error about needing CAPTCHA */
			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Need CAPTCHA to login. Consider using Harmony first, then retry."));
			return;
		}

		// {"message": "Invalid Form Body", "code": 50035, "errors": {"email": {"_errors": [{"code": "ACCOUNT_COMPROMISED_RESET_PASSWORD", "message": "Please reset your password to log in."}]}}}
		if (json_object_has_member(response, "errors")) {
			JsonObject *errors = json_object_get_object_member(response, "errors");
			if (json_object_has_member(errors, "email")) {
				JsonObject *email = json_object_get_object_member(errors, "email");
				if (json_object_has_member(email, "_errors")) {
					JsonArray *email_errors = json_object_get_array_member(email, "_errors");
					JsonObject *email_error = json_array_get_object_element(email_errors, 0);
					//const gchar *code = json_object_get_string_member(email_error, "code");
					const gchar *message = json_object_get_string_member(email_error, "message");

					purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, message);
					return;
				}
			}
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
	pc_flags &= ~PURPLE_CONNECTION_FLAG_NO_IMAGES;
	purple_connection_set_flags(pc, pc_flags);

	da = g_new0(DiscordAccount, 1);
	purple_connection_set_protocol_data(pc, da);
	da->account = account;
	da->pc = pc;
	da->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	da->http_keepalive_pool = purple_http_keepalive_pool_new();

	da->last_load_last_message_id = (guint64) purple_account_get_int(account, "last_message_id_high", 0);

	if (da->last_load_last_message_id != 0) {
		da->last_load_last_message_id = (da->last_load_last_message_id << 32) | ((guint64) purple_account_get_int(account, "last_message_id_low", 0) & 0xFFFFFFFF);
	}

	da->gateway_url = g_strdup(DISCORD_GATEWAY_SERVER);
	da->gateway_bucket = g_new0(DiscordTokenBucket, 1);
	da->gateway_bucket->num_tokens = 120;
	da->gateway_bucket->max_tokens = 120;
	da->gateway_bucket->time_interval = 60; //seconds
	da->gateway_bucket->prev_time = time(NULL);

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

	const gchar *account_password = purple_connection_get_password(da->pc);
	if (da->token) {
		discord_start_socket(da);

	} else if (account_password && *account_password) {
		JsonObject *data = json_object_new();
		gchar *str;

		json_object_set_string_member(data, "email", purple_account_get_username(account));
		json_object_set_string_member(data, "password", account_password);

		str = json_object_to_string(data);
		discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/auth/login", str, discord_login_response, NULL);

		g_free(str);
		json_object_unref(data);

	} else {
#ifdef	USE_QRCODE_AUTH
		//start auth websocket
		da->running_auth_qrcode = TRUE;
		da->compress = FALSE;
		discord_start_socket(da);
#endif
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
	if (da->five_minute_restart) {
		g_source_remove(da->five_minute_restart);
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
	g_hash_table_unref(da->group_dms);
	da->group_dms = NULL;
	g_queue_free(da->received_message_queue);
	da->received_message_queue = NULL;

	purple_http_conn_cancel_all(pc);
	purple_http_keepalive_pool_unref(da->http_keepalive_pool);

	while (da->pending_writes) {
		json_object_unref(da->pending_writes->data);
		da->pending_writes = g_slist_delete_link(da->pending_writes, da->pending_writes);
	}

	g_free(da->gateway_bucket);
	g_free(da->gateway_url);

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

#ifdef USE_QRCODE_AUTH

static void
discord_fetch_token_and_start_socket(DiscordAccount *da, JsonNode *node,
                                     G_GNUC_UNUSED gpointer user_data)
{
	if (node == NULL) {
		purple_debug_error("discord", "no json node\n");
		return;
	}

	JsonObject *response = json_node_get_object(node);
	const gchar *encrypted_token = json_object_get_string_member(response,
	                                                             "encrypted_token");
	if (strlen(encrypted_token) == 0) {
		purple_debug_error("discord", "Got empty token\n");
		return;
	}

	gchar *token = (gchar *) discord_qrauth_decrypt(da, encrypted_token, NULL);
	purple_account_set_string(da->account, "token", token);
	discord_qrauth_free_keys(da);

	da->token = g_strdup(token);
	purple_request_close_with_handle(da->pc);

	da->running_auth_qrcode = FALSE;
	da->compress = TRUE;
	discord_start_socket(da);
}

static gboolean
discord_process_qrcode_auth_frame(DiscordAccount *da, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;

	purple_debug_info("discord", "got auth frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame, -1, NULL)) {
		purple_debug_error("discord", "Error parsing response: %s\n", frame);
		return FALSE;
	}

	root = json_parser_get_root(parser);

	if (root != NULL) {
		JsonObject *obj = json_node_get_object(root);
		const gchar *op = json_object_get_string_member(obj, "op");

		if (purple_strequal(op, "hello")) {
			//Send ping every heartbeat_interval milliseconds
			gint64 heartbeat_interval = json_object_get_int_member(obj, "heartbeat_interval");

			if (da->heartbeat_timeout) {
				g_source_remove(da->heartbeat_timeout);
			}

			if (heartbeat_interval) {
				da->heartbeat_timeout = g_timeout_add(heartbeat_interval, discord_send_heartbeat, da);
			} else {
				da->heartbeat_timeout = 0;
			}

			//connected all ok
			discord_qrauth_generate_keys(da);
			gchar *pubkey_base64 = discord_qrauth_get_pubkey_base64(da);
			//discord_base64_make_urlsafe(pubkey_base64);

			//send it
			obj = json_object_new();
			json_object_set_string_member(obj, "op", "init");
			json_object_set_string_member(obj, "encoded_public_key", pubkey_base64);

			discord_socket_write_json(da, obj);

			json_object_unref(obj);
			g_free(pubkey_base64);

		} else if (purple_strequal(op, "nonce_proof")) {
			//sever created a proof, send one back
			const gchar *encrypted_nonce = json_object_get_string_member(obj, "encrypted_nonce");

			gsize decrypted_nonce_len = 0;
			guchar *decrypted_nonce = discord_qrauth_decrypt(da, encrypted_nonce, &decrypted_nonce_len);

			// sha256 it
			const guchar *proof_hash = discord_sha256(decrypted_nonce, decrypted_nonce_len);
			gchar *proof_base64 = g_base64_encode(proof_hash, 32);
			discord_base64_make_urlsafe(proof_base64);

			// send it
			obj = json_object_new();
			json_object_set_string_member(obj, "op", "nonce_proof");
			json_object_set_string_member(obj, "proof", proof_base64);

			discord_socket_write_json(da, obj);

			json_object_unref(obj);
			g_free(proof_base64);
			g_free(decrypted_nonce);

		} else if (purple_strequal(op, "pending_remote_init")) {
			// display the QR code to the user now
			const gchar *fingerprint = json_object_get_string_member(obj, "fingerprint");

			gchar *qrcode_url = g_strconcat("https://" DISCORD_API_SERVER "/ra/", fingerprint, NULL);
			guchar *qrcode_image = NULL;
			gsize qrcode_image_len = 0;
			gchar *qrcode_utf8 = NULL;

			QRcode *qrcode = QRcode_encodeString(qrcode_url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
			qrcode_utf8 = qrcode_utf8_output(qrcode);
			qrcode_image = qrcode_tga_output(qrcode, &qrcode_image_len);

			discord_display_qrcode(da->pc, qrcode_url, qrcode_utf8, qrcode_image, qrcode_image_len);

			g_free(qrcode_url);
			g_free(qrcode_image);
			g_free(qrcode_utf8);

		} else if (purple_strequal(op, "pending_ticket")) {
			// the app scanned, and is just confirming everything is OK

		} else if (purple_strequal(op, "pending_login")) {
			// the app confirmed, grab the token and LETS DO THIS THING
			const gchar *ticket = json_object_get_string_member(obj, "ticket");
			JsonObject *data = json_object_new();
			json_object_set_string_member(data, "ticket", ticket);
			gchar *postdata = json_object_to_string(data);

			discord_fetch_url(da,
			                  "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/remote-auth/login",
			                  postdata, discord_fetch_token_and_start_socket,
			                  NULL);
			g_free(postdata);
			json_object_unref(data);
		} else if (purple_strequal(op, "cancel")) {
			// they bailed on us!  how rude!
			purple_debug_info("discord", "User cancelled the auth\n");

			purple_request_close_with_handle(da->pc);

			purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Cancelled QR Code auth"));
			discord_qrauth_free_keys(da);

		} else {
			purple_debug_info("discord", "Unhandled auth op '%s'\n", op);
		}
	}

	g_object_unref(parser);
	return TRUE;
}
#endif

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
		case OP_DISPATCH: { /* Dispatch */
			const gchar *type = json_object_get_string_member(obj, "t");
			gint64 seq = json_object_get_int_member(obj, "s");

			da->seq = seq;
			discord_process_dispatch(da, type, json_object_get_object_member(obj, "d"));

			break;
		}

		case OP_RECONNECT: { /* Reconnect */
			discord_start_socket(da);
			break;
		}

		case OP_INVALID_SESSION: { /* Invalid session */
			da->seq = 0;
			g_free(da->session_id);
			da->session_id = NULL;

			discord_send_auth(da);
			break;
		}

		case OP_HELLO: { /* Hello */
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

		case OP_HEARTBEAT_ACK: { /* Heartbeat ACK */
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

static gboolean
discord_take_token_from_bucket(DiscordTokenBucket *bucket) {
	time_t current = time(NULL);
	guint interval = (guint) (current - bucket->prev_time);
	guint tokens = MIN(bucket->max_tokens, bucket->num_tokens + interval*(bucket->max_tokens/bucket->time_interval));

	bucket->prev_time = current;

	if (tokens > 0) {
		bucket->num_tokens -= 1;
		return TRUE;
	}
	return FALSE;
}

static guchar *
discord_websocket_mask(const guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void discord_socket_write_data(DiscordAccount *ya, guchar *data, gsize data_len, guchar type);

typedef struct {
	DiscordAccount *ya;
	guchar *data;
	gsize data_len;
	guchar type;
} DiscordSocketInfo;

static gboolean
discord_socket_write_data_delay_cb(gpointer user_data)
{
	DiscordSocketInfo *info = user_data;

	discord_socket_write_data(info->ya, info->data, info->data_len, info->type);
	g_free(info);

	return FALSE;
}

static void
discord_socket_delay_write_data(DiscordAccount *ya, guchar *data, gsize data_len, guchar type)
{
	DiscordSocketInfo *info = g_new0(DiscordSocketInfo, 1);
	info->ya = ya;
	info->data = data;
	info->data_len = data_len;
	info->type = type;

	// Set timer for when to check the bucket again. Could probably make this more intelligent.
	purple_timeout_add(1000, discord_socket_write_data_delay_cb, info);
}

static void
discord_socket_write_data(DiscordAccount *ya, guchar *data, gsize data_len, guchar type)
{
	if (!discord_take_token_from_bucket(ya->gateway_bucket)) {
		discord_socket_delay_write_data(ya, data, data_len, type);
		return;
	}

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

	do {
		ret = purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
		if (ret < 0 && errno != EAGAIN) {
			purple_debug_error("discord", "websocket sending error: %d\n", errno);
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Websocket failed to send"));

			// We can't just restart the socket because that would mean we lose this packet as a pending write
			//discord_start_socket(ya);
		}
	} while(ret < 0 && errno == EAGAIN);

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
		decomp_len = zs->avail_out;
		gzres = inflate(zs, Z_SYNC_FLUSH);
		decomp_len -= zs->avail_out;

		// Quieten static analysis
		zs->next_out = NULL;
		zs->avail_out = 0;

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

static gboolean discord_five_minute_restart(gpointer data);

static void
discord_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	DiscordAccount *ya = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;

	g_return_if_fail(conn == ya->websocket);

	if (G_UNLIKELY(!ya->websocket_header_received)) {
		gint nlbr_count = 0;
		gchar nextchar;

		while (nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1) == 1) {
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

			ya->five_minute_restart = g_timeout_add_seconds(5 * 60, discord_five_minute_restart, ya);
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
						purple_ssl_read(conn, &ping_frame_len, 2);
						ping_frame_len = GUINT16_FROM_BE(ping_frame_len);
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
				purple_ssl_read(conn, &ya->frame_len, 2);
				ya->frame_len = GUINT16_FROM_BE(ya->frame_len);
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
			gboolean success;

			if (ya->compress) {
				gchar *temp = discord_inflate(ya, ya->frame, ya->frame_len);
				g_free(ya->frame);
				ya->frame = temp;
			}

#ifdef USE_QRCODE_AUTH
			if (ya->running_auth_qrcode) {
				success = discord_process_qrcode_auth_frame(ya, ya->frame);
			} else
#endif
			success = discord_process_frame(ya, ya->frame);
			g_free(ya->frame);
			ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			ya->frames_since_reconnect++;

			if (G_UNLIKELY(ya->websocket == NULL || success == FALSE || ya->websocket != conn)) {
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
	const gchar *server;

	g_return_if_fail(conn == da->websocket);

	purple_ssl_input_add(da->websocket, discord_socket_got_data, da);

	server = da->gateway_url ? da->gateway_url : DISCORD_GATEWAY_SERVER;

	websocket_header = g_strdup_printf(
		"GET %s%s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: Upgrade\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache\r\n"
		"Upgrade: websocket\r\n"
		"Origin: https://discord.com\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"User-Agent: " DISCORD_USERAGENT "\r\n"
		"\r\n",
#ifdef USE_QRCODE_AUTH
		da->running_auth_qrcode ? DISCORD_QRCODE_AUTH_SERVER_PATH :
#endif
		DISCORD_GATEWAY_SERVER_PATH, da->compress ? "&compress=zlib-stream" : "",
#ifdef USE_QRCODE_AUTH
		da->running_auth_qrcode ? DISCORD_QRCODE_AUTH_SERVER :
#endif
		server, websocket_key
	);

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
	const gchar *server;

	if (da->heartbeat_timeout) {
		g_source_remove(da->heartbeat_timeout);
	}
	if (da->five_minute_restart) {
		g_source_remove(da->five_minute_restart);
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

#ifdef USE_QRCODE_AUTH
	if (da->running_auth_qrcode) {
		da->websocket = purple_ssl_connect(da->account, DISCORD_QRCODE_AUTH_SERVER, DISCORD_QRCODE_AUTH_SERVER_PORT, discord_socket_connected, discord_socket_failed, da);
	} else {
#endif

	server = da->gateway_url ? da->gateway_url : DISCORD_GATEWAY_SERVER;
	da->websocket = purple_ssl_connect(da->account, server, DISCORD_GATEWAY_PORT, discord_socket_connected, discord_socket_failed, da);

#ifdef USE_QRCODE_AUTH
	}
#endif
}

static gboolean
discord_five_minute_restart(gpointer data)
{
	DiscordAccount *da = data;

	discord_start_socket(da);

	return FALSE;
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
discord_thread_parent_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	if (node == NULL) {
		return;
	}
	JsonArray *messages = json_node_get_array(node);
	guint len = json_array_get_length(messages);

	if (len == 0) {
		return;
	}

	JsonObject *message = json_array_get_object_element(messages, len-1);
	gchar *thread_id = (gchar *)user_data;

	const gchar *old_id = json_object_get_string_member(message, "channel_id");
	json_object_set_string_member(message, "channel_id", thread_id);

	discord_process_message(da, message, DISCORD_MESSAGE_NORMAL);

	json_object_set_string_member(message, "channel_id", old_id);
	g_free(thread_id);
}

static void
discord_send_react_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *messages = json_node_get_array(node);
	guint len = json_array_get_length(messages);
	JsonObject *message = json_array_get_object_element(messages, len-1);
	const gchar *channel_id = json_object_get_string_member(message, "channel_id");
	const gchar *msg_id = json_object_get_string_member(message, "id");
	time_t msg_time = discord_time_from_snowflake(to_int(msg_id));

	DiscordReaction *react  = (DiscordReaction *)user_data;
	gchar *emoji = react->reaction;
	time_t intended_time = react->msg_time;
	const gchar *method = react->is_unreact ? "DELETE" : "PUT";

	if (msg_time != intended_time) {
		discord_free_reaction(react);
		return;
	}


	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%s/messages/%s/reactions/%s/%%40me", channel_id, msg_id, purple_url_encode(emoji));
	discord_fetch_url_with_method(da, method, url, "{}", NULL, NULL);
	g_free(url);
	discord_free_reaction(react);
}

static void
discord_react_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *data_items = json_node_get_array(node);
	guint len = json_array_get_length(data_items);
	JsonObject *data = json_array_get_object_element(data_items, len-1);
	DiscordReaction *react = user_data;
	PurpleConversation *conv = react->conv;
	guint64 reactor_id = react->user_id;

	if (node == NULL) {
		discord_free_reaction(react);
		return;
	}

	const gchar *channel_id_s = json_object_get_string_member(data, "channel_id");
	JsonObject *author_obj = json_object_get_object_member(data, "author");
	guint64 author_id = to_int(json_object_get_string_member(author_obj, "id"));

	react->msg_txt = g_strdup(json_object_get_string_member(data, "content"));
	const gchar *msg_id = json_object_get_string_member(data, "id");
	react->msg_time = discord_time_from_snowflake(to_int(msg_id));

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, to_int(channel_id_s), &guild);
	DiscordUser *reactor = discord_get_user(da, reactor_id);

	gchar *reactor_nick = reactor_id == da->self_user_id ? g_strdup(_("You")) : discord_get_display_name_or_unk(da, guild, channel, reactor, NULL);

	gchar *author_nick;
	if (author_id == da->self_user_id) {
		author_nick = g_strdup("SELF"); //placeholder
	} else {
		DiscordUser *author = discord_get_user(da, author_id);
		author_nick = discord_get_display_name_or_unk(da, guild, channel, author, author_obj);
	}

	gchar *react_text = discord_get_react_text(da, author_nick, reactor_nick, react);
	g_free(author_nick);
	g_free(reactor_nick);

	purple_conversation_write_system_message(conv, react_text, PURPLE_MESSAGE_SYSTEM);

	g_free(react_text);
	discord_free_reaction(react);
}

static void
discord_got_pinned(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	PurpleChatConversation *chatconv = user_data;
	PurpleConversation *conv = PURPLE_CONVERSATION(chatconv);

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
		purple_conversation_write_system_message(conv, _("No pinned messages"), PURPLE_MESSAGE_NO_LOG);
	}
}

static void
discord_chat_pinned_by_room_id(PurpleConnection *pc, PurpleChatConversation *chatconv, guint64 room_id)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/pins", room_id);
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

static void
discord_chat_threads(PurpleConnection *pc, int id, const gchar *filter)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	if (channel == NULL) {
		return;
	}

	//gchar *url;

	GHashTableIter thread_iter;
	gpointer key, value;
	/* TODO: get archived thread data */
	g_hash_table_iter_init(&thread_iter, channel->threads);

	gchar *threads_list = g_strdup(_("Active Threads:\n<pre>Creation Time       | Last Message Time   | Name"));

	while (g_hash_table_iter_next(&thread_iter, &key, &value)) {
		DiscordChannel *thread = value;
		if (thread) {
			GDateTime* creation_time = g_date_time_new_from_unix_local(discord_time_from_snowflake(thread->id));
			gchar *creation_time_s = g_date_time_format(creation_time, "%F %T");
			GDateTime* last_message_time = g_date_time_new_from_unix_local(discord_time_from_snowflake(thread->last_message_id));
			gchar *last_message_time_s;
			if (thread->last_message_id == DISCORD_EPOCH_MS/1000)
				last_message_time_s = g_strdup("(null)             ");
			else
				last_message_time_s = g_date_time_format(last_message_time, "%F %T");

			gchar *tmp = g_strdup_printf("%s\n %s | %s | %s", threads_list, creation_time_s, last_message_time_s, thread->name);
			g_free(threads_list);
			threads_list = tmp;

			g_free(creation_time_s);
			g_free(last_message_time_s);
			g_date_time_unref(creation_time);
			if (last_message_time)
				g_date_time_unref(last_message_time);
		}
	}

	gchar *tmp = g_strdup_printf("%s</pre>", threads_list);
	g_free(threads_list);
	threads_list = tmp;

	purple_conversation_write_system_message(PURPLE_CONVERSATION(chatconv), threads_list, PURPLE_MESSAGE_NO_LOG);

}

static void
discord_chat_roles(PurpleConnection *pc, int id)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		/* TODO FIXME? */
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);

	if (guild != NULL) {
		PurpleConversation *conv = PURPLE_CONVERSATION(chatconv);

		if (g_hash_table_size(guild->roles)) {
			GHashTableIter role_iter;
			gpointer key, value;

			purple_conversation_write_system_message(conv, _("Server Roles:"), PURPLE_MESSAGE_NO_LOG);
			g_hash_table_iter_init(&role_iter, guild->roles);

			while (g_hash_table_iter_next(&role_iter, &key, &value)) {
				DiscordGuildRole *role = value;
				gchar *role_text = g_strdup_printf("%" G_GUINT64_FORMAT " - %s", role->id, role->name);
				purple_conversation_write_system_message(conv, role_text, PURPLE_MESSAGE_NO_LOG);
			}

		} else {
			/* Don't make the user think we forget about them */
			purple_conversation_write_system_message(conv, _("No server roles"), PURPLE_MESSAGE_NO_LOG);
		}
	}
}

/* Invite to a _group DM_
 * The API for inviting to a guild is different, TODO implement that one too */

static void
discord_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	DiscordAccount *da;
	guint64 room_id;
	PurpleChatConversation *chatconv;
	DiscordUser *user;

	da = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if(!room_id_ptr) {
		return;
	}

	room_id = *room_id_ptr;
	user = discord_get_user_fullname(da, who);

	if (!user) {
		purple_debug_info("discord", "Missing user in invitation for %s\n", who);
		return;
	}

	if (g_hash_table_contains_int64(da->group_dms, id)) {
		JsonObject *data = json_object_new();
		json_object_set_string_member(data, "recipient", from_int(user->id));
		gchar *postdata = json_object_to_string(data);

		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/recipients/%" G_GUINT64_FORMAT, room_id, user->id);
		discord_fetch_url_with_method(da, "PUT", url, postdata, NULL, NULL);
		g_free(url);

		g_free(postdata);
		json_object_unref(data);

	} else {
		//TODO /channels/{channel.id}/invites
		//TODO max_age, max_uses, temporary, unique options
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/invites", room_id);
		discord_fetch_url_with_method(da, "POST", url, "{}", NULL, NULL);
		g_free(url);

	}

}

static void
discord_chat_nick(PurpleConnection *pc, int id, const gchar *new_nick)
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

		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/guilds/%" G_GUINT64_FORMAT "/members/@me/nick", guild->id);
		discord_fetch_url_with_method(da, "PATCH", url, postdata, NULL, NULL);

		g_free(url);
		g_free(postdata);
		json_object_unref(data);

		/* Propagate locally as well */
		const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, da->self_user_id);
		discord_got_nick_change(da, discord_get_user(da, da->self_user_id), guild, new_nick, old_nick, TRUE);
	}
}

static void
discord_chat_kick_username(PurpleConnection *pc, int id, const gchar *username)
{
	PurpleChatConversation *chatconv;

	g_return_if_fail(username && *username);

	/* TODO check source */
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	g_return_if_fail(room_id);

	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);

	if (guild != NULL) {
		DiscordUser *user = discord_get_user_fullname(da, username);
		guint64 user_id = 0;

		if (user != NULL) {
			user_id = user->id;
		} else {
			guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, username);

			if (uid) {
				user_id = *uid;
			}
		}

		if (user_id) {
			gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/guilds/%" G_GUINT64_FORMAT "/members/%" G_GUINT64_FORMAT, guild->id, user_id);
			discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
			g_free(url);
		}
	}
}

static void
discord_chat_ban_username(PurpleConnection *pc, int id, const gchar *username)
{
	PurpleChatConversation *chatconv;

	g_return_if_fail(username && *username);

	/* TODO check source */
	chatconv = purple_conversations_find_chat(pc, id);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	if (!room_id) {
		room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
	}

	g_return_if_fail(room_id);

	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, room_id, &guild);

	if (guild != NULL) {
		DiscordUser *user = discord_get_user_fullname(da, username);
		guint64 user_id = 0;

		if (user != NULL) {
			user_id = user->id;
		} else {
			guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, username);

			if (uid) {
				user_id = *uid;
			}
		}

		if (user_id) {
			JsonObject *data = json_object_new();
			//json_object_set_string_member(data, "reason", reason);
			//json_object_set_int_member(data, "delete-message-days", numdays);
			gchar *postdata = json_object_to_string(data);

			gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/guilds/%" G_GUINT64_FORMAT "/bans/%" G_GUINT64_FORMAT, guild->id, user_id);
			discord_fetch_url_with_method(da, "PUT", url, postdata, NULL, NULL);

			g_free(url);
			g_free(postdata);
			json_object_unref(data);
		}
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

#if defined(__GNUC__) && !defined(__clang__)
#define optnone optimize("O0")
#endif

static __attribute__((optnone)) GHashTable *
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
	DiscordChannel *channel = user_data;
	g_return_if_fail(channel);
	if (json_node_get_node_type(node) != JSON_NODE_ARRAY) {
		// Null object?
		return;
	}
	JsonArray *messages = json_node_get_array(node);

	gint i, len = json_array_get_length(messages);
	guint64 last_message = channel->last_message_id;
	guint64 rolling_last_message_id = 0;

	/* latest are first */
	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
		guint64 id = to_int(json_object_get_string_member(message, "id"));

		if (id <= last_message) {
			rolling_last_message_id = discord_process_message(da, message, DISCORD_MESSAGE_NORMAL);
		}
	}

	if (rolling_last_message_id != 0) {
		discord_set_room_last_id(da, channel->id, rolling_last_message_id);

		if (rolling_last_message_id < last_message) {
			/* Request the next 100 messages */
			gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, channel->id, rolling_last_message_id);

			discord_fetch_url_with_delay(da, url, NULL, discord_got_history_of_room, channel, 1000);

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

static gboolean
discord_get_room_force_large(DiscordAccount *da, guint64 id)
{
	PurpleBlistNode *blistnode = NULL;
	gboolean is_large = FALSE;
	gchar *channel_id = from_int(id);

	if (channel_id) {
		if (g_hash_table_contains(da->one_to_ones, channel_id)) {
			g_free(channel_id);
			return FALSE;
		}

		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));

		if (blistnode != NULL) {
			is_large = purple_blist_node_get_bool(blistnode, "large_channel");
		}
		g_free(channel_id);
	}

	return is_large;
}

static gboolean
discord_get_room_force_small(DiscordAccount *da, guint64 id)
{
	PurpleBlistNode *blistnode = NULL;
	gboolean is_small = FALSE;
	gchar *channel_id = from_int(id);

	if (channel_id) {
		if (g_hash_table_contains(da->one_to_ones, channel_id)) {
			g_free(channel_id);
			return FALSE;
		}
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));

		if (blistnode != NULL) {
			is_small = purple_blist_node_get_bool(blistnode, "small_channel");
		}
		g_free(channel_id);
	}

	return is_small;
}

static gboolean
discord_get_room_history_limiting(DiscordAccount *da, guint64 id)
{
	PurpleBlistNode *blistnode = NULL;
	gboolean is_limited = FALSE;
	gchar *channel_id = from_int(id);

	if (g_hash_table_contains(da->one_to_ones, channel_id)) {
		// Don't limit DM's
	} else {
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));
	}

	if (blistnode != NULL) {
		is_limited = purple_blist_node_get_bool(blistnode, "limit_history");
	}

	g_free(channel_id);
	return is_limited;
}

/* libpurple can't store a 64bit int on a 32bit machine, so convert to
 * something more usable instead (puke). also needs to work cross platform, in
 * case the accounts.xml is being shared (double puke)
 */

static guint64
discord_get_room_last_id(DiscordAccount *da, guint64 id)
{
	guint64 last_message_id = 0;
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
		}

		last_message_id = last_room_id ? last_room_id : 0;
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
		guint64 last_id_saved = purple_blist_node_get_int(blistnode, "last_message_id_high");
		if (last_id_saved) {
			last_id_saved = (last_id_saved << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_id_low") & 0xFFFFFFFF);
		}

		if (last_id > last_id_saved) {
			purple_blist_node_set_int(blistnode, "last_message_id_high", last_id >> 32);
			purple_blist_node_set_int(blistnode, "last_message_id_low", last_id & 0xFFFFFFFF);
		}
	}

	da->last_message_id = MAX(da->last_message_id, last_id);
	purple_account_set_int(da->account, "last_message_id_high", last_id >> 32);
	purple_account_set_int(da->account, "last_message_id_low", last_id & 0xFFFFFFFF);

	g_free(channel_id);
}

/* TODO: Cache better, sane defaults */

/* https://support.discord.com/hc/en-us/articles/206141927-How-is-the-permission-hierarchy-structured- */

static guint64
discord_permission_role(DiscordGuild *guild, guint64 r, guint64 permission)
{
	g_return_val_if_fail(guild, permission);

	DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, r);
	return role ? (permission | role->permissions) : permission;
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

		if (guild && user->id == guild->owner)
			return G_MAXUINT64; // All permissions for the server owner

		// Calculate the server permissions
		/* @everyone */
		permissions = discord_permission_role(guild, channel->guild_id, permissions);

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 r = g_array_index(guild_membership->roles, guint64, i);
			permissions = discord_permission_role(guild, r, permissions);
		}

		if (permissions & PERM_ADMINISTRATOR)
			return G_MAXUINT64; // All permissions for admins

		// Calculate the channel permissions

		// @everyone
		DiscordPermissionOverride *ro = g_hash_table_lookup_int64(channel->permission_role_overrides, channel->guild_id);
		if (ro != NULL) {
			permissions = ((permissions & ~(ro->deny)) | ro->allow);
		}

		guint64 channel_deny = 0;
		guint64 channel_allow = 0;

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 role = g_array_index(guild_membership->roles, guint64, i);

			ro = g_hash_table_lookup_int64(channel->permission_role_overrides, role);
			if (ro != NULL) {
				channel_deny |= ro->deny;
				channel_allow |= ro->allow;
			}
		}

		permissions = ((permissions & ~(channel_deny)) | channel_allow);
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

	guint64 int_id = to_int(id);
	DiscordChannel *chan = discord_get_channel_global_int(da, int_id);
	chatconv = purple_conversations_find_chat(da->pc, discord_chat_hash(int_id));

	if (chatconv == NULL) {
		return;
	}

	if (json_object_has_member(channel, "topic")) {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "topic"));
	} else {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "name"));
	}

	if (json_object_has_member(channel, "last_pin_timestamp")) {
		guint64 last_message_id = discord_get_room_last_id(da, int_id);
		time_t last_message_time = discord_time_from_snowflake(last_message_id);

		const gchar *last_pin = json_object_get_string_member(channel, "last_pin_timestamp");
		time_t pin_time = discord_str_to_time(last_pin);

		if (pin_time > last_message_time) {
				purple_conversation_write_system_message(PURPLE_CONVERSATION(chatconv), "This channel's pinned messages have been updated. Type \"/pinned\" to see them.", PURPLE_MESSAGE_SYSTEM);
		}
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
			gchar *name = discord_create_nickname(user, NULL, chan);

			if (name != NULL) {
				users = g_list_prepend(users, name);
				flags = g_list_prepend(flags, GINT_TO_POINTER(PURPLE_CHAT_USER_NONE));
			}
		}

		// Add self
		DiscordUser *self = discord_get_user(da, da->self_user_id);
		gchar *self_name = discord_create_nickname(self, NULL, chan);
		users = g_list_prepend(users, self_name);
		flags = g_list_prepend(flags, GINT_TO_POINTER(PURPLE_CHAT_USER_NONE));
		purple_chat_conversation_set_nick(chatconv, self_name);

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

		if (guild != NULL) {
			PurpleChatConversation *chat = chatconv;
			GList *users = NULL, *flags = NULL;
			GHashTableIter iter;
			gpointer key, value;

			g_hash_table_iter_init (&iter, guild->members);
			while (g_hash_table_iter_next (&iter, &key, &value)) {
				guint64 uid = *(gint64 *)key;
				DiscordUser *user = discord_get_user(da, uid);

				if (!user) {
					continue;
				}

				/* Ensure that we actually have permissions for this channel */
				guint64 permission = discord_compute_permission(da, user, chan);

				/* must have READ_MESSAGES */
				if ((permission & PERM_VIEW_CHANNEL)) {
					PurpleChatUserFlags cbflags = discord_get_user_flags_from_permissions(user, permission);
					gchar *nickname = discord_create_nickname(user, guild, chan);

					if (nickname != NULL) {
						if (uid == da->self_user_id) {
							purple_chat_conversation_set_nick(chatconv, nickname);
						}

						if ((user->status ^ USER_MOBILE) != USER_OFFLINE) {
							users = g_list_prepend(users, nickname);
							flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
						} else {
							g_free(nickname);
						}
					}
				}
			}

			if (users != NULL) {
				purple_chat_conversation_clear_users(chat);
				purple_chat_conversation_add_users(chat, users, NULL, flags, FALSE);

				while (users != NULL) {
					g_free(users->data);
					users = g_list_delete_link(users, users);
				}
			}

			g_list_free(flags);
		}
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

	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_memdup2(&(id), sizeof(guint64)));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "msg_timestamp_map", (GList*)NULL);

	/* Get info about the channel */
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT, id);
	discord_fetch_url(da, url, NULL, discord_got_channel_info, channel);
	g_free(url);

	if (guild != NULL) {
		gchar *name = discord_create_nickname_from_id(da, guild, channel, da->self_user_id);
		purple_chat_conversation_set_nick(chatconv, name);
		g_free(name);
	}

	return channel;
}

static gboolean
discord_join_chat_by_id(DiscordAccount *da, guint64 id, gboolean present)
{
	/* Only returns channel when chat was not already joined */
	DiscordChannel *channel = discord_open_chat(da, id, present);

	if (!channel) {
		return FALSE;
	}

	/* Get any missing messages */
	guint64 last_message_id = discord_get_room_last_id(da, id);
	gboolean is_limited = discord_get_room_history_limiting(da, id);

	if (last_message_id == 0) {
		// There's a problem retrieving the last message id, load last 100 messages
		is_limited = TRUE;
	} else if (channel->last_message_id <= last_message_id) {
		return FALSE;
	}

	if (is_limited) {
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=100&before=%" G_GUINT64_FORMAT, id, channel->last_message_id);
		discord_fetch_url(da, url, NULL, discord_got_history_static, channel);
		g_free(url);
		return TRUE;
	} else {
		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, id, last_message_id);
		discord_fetch_url(da, url, NULL, discord_got_history_of_room, channel);
		g_free(url);
		return TRUE;
	}
	return FALSE;
}

static void
discord_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	guint64 id = to_int(g_hash_table_lookup(chatdata, "id"));

	discord_join_chat_by_id(da, id, TRUE);
}

static void
discord_got_ack_token(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *ack_response = json_node_get_object(node);
	const gchar *token = json_object_get_string_member(ack_response, "token");

	if (token != NULL) {
		g_free(da->ack_token);
		da->ack_token = g_strdup(token);
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
		gchar *channel_str = from_int(channel_id);
		gchar *msg = g_hash_table_lookup(da->last_message_id_dm, channel_str);
		g_free(channel_str);

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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages/%" G_GUINT64_FORMAT "/ack", channel_id, last_message_id);
	gchar *postdata = g_strconcat("{\"token\":\"", da->ack_token ? da->ack_token : "null", "\"}", NULL);
	discord_fetch_url(da, url, postdata, discord_got_ack_token, NULL);
	g_free(postdata);
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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/typing", room_id);
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

static void
discord_conversation_send_image(DiscordAccount *da, guint64 room_id, PurpleImage *image)
{
	GString *postdata;
	gchar *filename;
	gchar *mimetype;
	gchar *url;
	gchar *nonce;

	nonce = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());
	g_hash_table_insert(da->sent_message_ids, nonce, nonce);

	filename = (gchar *)purple_image_get_path(image);
	if (filename != NULL) {
		filename = g_path_get_basename(filename);
	} else {
		filename = g_strdup_printf("purple%u.%s", g_random_int(), purple_image_get_extension(image));
	}
	mimetype = g_strdup(purple_image_get_mimetype(image));

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "------PurpleBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n", purple_url_encode(filename), mimetype);
	g_string_append_len(postdata, purple_image_get_data(image), purple_image_get_data_size(image));
	g_string_append_printf(postdata, "\r\n------PurpleBoundary\r\nContent-Disposition: form-data; name=\"payload_json\"\r\n\r\n{\"content\":\"\",\"nonce\":\"%s\",\"tts\":false}\r\n", nonce);
	g_string_append(postdata, "------PurpleBoundary--\r\n");

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages", room_id);

	discord_fetch_url_with_method_len(da, "POST", url, postdata->str, postdata->len, NULL, NULL);

	g_free(mimetype);
	g_free(url);
	g_string_free(postdata, TRUE);
}

static void
discord_conversation_check_message_for_images(DiscordAccount *da, guint64 room_id, const gchar *message)
{
	const gchar *img;

	if ((img = strstr(message, "<img ")) || (img = strstr(message, "<IMG "))) {
		const gchar *id, *src;
		const gchar *close = strchr(img, '>');

		if (((id = strstr(img, "ID=\"")) || (id = strstr(img, "id=\""))) &&
				id < close) {
			int imgid = atoi(id + 4);
			PurpleImage *image = purple_image_store_get(imgid);

			if (image != NULL) {
				discord_conversation_send_image(da, room_id, image);
			}
		} else if (((src = strstr(img, "SRC=\"")) || (src = strstr(img, "src=\""))) &&
				src < close) {
			// purple3 embeds images using src="purple-image:1"
			if (strncmp(src + 5, "purple-image:", 13) == 0) {
				int imgid = atoi(src + 5 + 13);
				PurpleImage *image = purple_image_store_get(imgid);

				if (image != NULL) {
					discord_conversation_send_image(da, room_id, image);
				}
			}
		}
	}
}

static gint
discord_conversation_send_message(DiscordAccount *da, guint64 room_id, const gchar *message, const gchar *ref_id)
{
	JsonObject *data = json_object_new();
	gchar *nonce;
	gchar *marked;
	gchar *stripped;
	gchar *final;
	gint final_len;

	discord_conversation_check_message_for_images(da, room_id, message);

	nonce = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());

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
	if (final_len <= 2000 && final_len > 0) {
		gchar *url;
		gchar *postdata;
		json_object_set_string_member(data, "content", final);
		json_object_set_string_member(data, "nonce", nonce);
		json_object_set_boolean_member(data, "tts", FALSE);

		if (ref_id != NULL) {
			JsonObject *ref_obj = json_object_new();
			json_object_set_string_member(ref_obj, "message_id", ref_id);
			json_object_set_object_member(data, "message_reference", ref_obj);
		}

		g_hash_table_insert(da->sent_message_ids, nonce, nonce);

		url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages", room_id);
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
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

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
	ret = discord_conversation_send_message(da, room_id, d_message, NULL);

	if (ret > 0) {
		gchar *tmp = g_regex_replace_eval(emoji_regex, d_message, -1, 0, 0, discord_replace_emoji, PURPLE_CONVERSATION(chatconv), NULL);

		if (tmp != NULL) {
			g_free(d_message);
			d_message = tmp;
		}

		d_message = discord_replace_mentions_bare(da, guild, d_message);

		gchar *name = discord_create_nickname_from_id(da, guild, channel, da->self_user_id);
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
	gint64 result_code;

	if (node == NULL) {
		purple_conversation_present_error(who, da->account, _("Could not create conversation"));
		purple_message_destroy(msg);
		return;
	}

	result = json_node_get_object(node);
	result_code = json_object_get_int_member(result, "code");

	if (result_code / 10000 == 4 || result_code / 10000 == 5) {
		const gchar *result_message = json_object_get_string_member(result, "message");
		if (!result_message || !*result_message) result_message = _("Could not send message to this user");

		purple_conversation_present_error(who, da->account, result_message);
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
		discord_conversation_send_message(da, to_int(room_id), message, NULL);
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

			discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/channels", postdata, discord_created_direct_message_send, msg);

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

	return discord_conversation_send_message(da, to_int(room_id), message, NULL);
}

static void
discord_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	/* PATCH https:// DISCORD_API_SERVER /api/" DISCORD_API_VERSION "/channels/%s channel */
	/*{ "name" : "test", "position" : 1, "topic" : "new topic", "bitrate" : 64000, "user_limit" : 0 } */
}

static void
discord_got_avatar(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordUser *user = user_data;

	if (node != NULL) {
		gchar *username = discord_create_fullname(user);
		JsonObject *response = json_node_get_object(node);
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;

		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup2(response_str, response_len);

		if (user->id == da->self_user_id) {
			purple_buddy_icons_set_account_icon(da->account, response_dup, response_len);
			purple_account_set_string(da->account, "avatar_checksum", user->avatar);
		} else {
			purple_buddy_icons_set_for_user(da->account, username, response_dup, response_len, user->avatar);
		}

		g_free(username);
	}

}

static void
discord_get_avatar(DiscordAccount *da, DiscordUser *user, gboolean is_buddy)
{
	if (!user || !user->avatar) {
		return;
	}

	/* bitlbee is allergic to pictures */
	if (purple_strequal(purple_core_get_ui(), "BitlBee"))
		return;

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

	GString *url = g_string_new("https://" DISCORD_CDN_SERVER "/avatars/");
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

	usersplit = g_strsplit_set(buddy_name, "#", 2);
	data = json_object_new();
	json_object_set_string_member(data, "username", g_strstrip(usersplit[0]));
	if (usersplit[1] && *usersplit[1]) {
		json_object_set_string_member(data, "discriminator", g_strstrip(usersplit[1]));
	} else {
		json_object_set_null_member(data, "discriminator");
	}

	postdata = json_object_to_string(data);

	discord_fetch_url(da, "https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships", postdata, discord_add_buddy_cb, buddy);

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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
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
	gchar *status_strings[8] = {
		_("Online"),
		_("Idle"),
		_("Offline"),
		_("Do Not Disturb"),
		_("Mobile - Online"),
		_("Mobile - Idle"),
		_("Mobile - Offline"),
		_("Mobile - Do Not Disturb")
	};

	purple_notify_user_info_add_pair_html(user_info, _("Status"), status_strings[user->status]);

	if (user->game != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Playing"), user->game);
	}
	if (user->custom_status != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Custom Status"), user->custom_status);
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

		purple_notify_user_info_add_pair_plaintext(user_info, type, name);
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

			for (guint j = 0; j < membership->roles->len; j++) {
				guint64 role_id = g_array_index(membership->roles, guint64, j);
				DiscordGuildRole *role = g_hash_table_lookup_int64(guild->roles, role_id);

				if (role) {
					g_string_append_printf(role_str, " [" COLOR_START "%s" COLOR_END "]", role->color, role->name);
				}
			}

			purple_notify_user_info_add_pair_html(user_info, guild->name, role_str->str);
			g_string_free(role_str, TRUE);
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
		PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
		purple_notify_user_info_add_pair_html(user_info, _("Unknown user"), username);
		purple_notify_userinfo(pc, username, user_info, NULL, NULL);
		return;
	}

	/* TODO string format fix */
	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/%" G_GUINT64_FORMAT "/profile", user->id);
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

	/* Other people can have an in-game display */
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, TRUE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "idle", _("Idle"), TRUE, TRUE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "dnd", _("Do Not Disturb"), TRUE, TRUE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, "set-invisible", _("Invisible"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, FALSE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_MOBILE, "mobile", _("Mobile"), TRUE, FALSE, TRUE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);



	// Legacy statuses - add last for backwards compat, without the UI trying to use them
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "set-online", _("Online"), TRUE, FALSE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "set-idle", _("Idle"), TRUE, FALSE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, "set-dnd", _("Do Not Disturb"), TRUE, FALSE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "set-offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_MOBILE, "set-mobile", _("Mobile"), TRUE, FALSE, TRUE);
	types = g_list_append(types, status);

	return types;
}

static void
discord_toggle_large_handling(PurpleBlistNode *node, gpointer userdata)
{
	DiscordAccount *da = (DiscordAccount *) userdata;
	PurpleChat *chat = PURPLE_CHAT(node);

	DiscordChannel *channel = discord_channel_from_chat(da, chat);

	if (channel == NULL) {
		return;
	}

	/* Toggle the large flag */
	gboolean is_large = purple_blist_node_get_bool(node, "large_channel");
	purple_blist_node_set_bool(node, "large_channel", !is_large);
	if (!is_large) { // Unset small flag if we're setting the large flag
		purple_blist_node_set_bool(node, "small_channel", FALSE);
	}
}

static void
discord_toggle_small_handling(PurpleBlistNode *node, gpointer userdata)
{
	DiscordAccount *da = (DiscordAccount *) userdata;
	PurpleChat *chat = PURPLE_CHAT(node);

	DiscordChannel *channel = discord_channel_from_chat(da, chat);

	if (channel == NULL) {
		return;
	}

	/* Toggle the small flag */
	gboolean is_small = purple_blist_node_get_bool(node, "small_channel");
	purple_blist_node_set_bool(node, "small_channel", !is_small);
	if (!is_small) { // Unset small flag if we're setting the small flag
		purple_blist_node_set_bool(node, "large_channel", FALSE);
	}
}

static void
discord_toggle_history_limit(PurpleBlistNode *node, gpointer userdata)
{
	DiscordAccount *da = (DiscordAccount *) userdata;
	PurpleChat *chat = PURPLE_CHAT(node);

	DiscordChannel *channel = discord_channel_from_chat(da, chat);

	if (channel == NULL) {
		return;
	}

	/* Toggle the history limit */
	gboolean is_limited = purple_blist_node_get_bool(node, "limit_history");
	purple_blist_node_set_bool(node, "limit_history", !is_limited);
}

/* If a channel is muted, unmute it, or vice verse */

static void
discord_toggle_mute(PurpleBlistNode *node, gpointer userdata)
{
	DiscordAccount *da = (DiscordAccount *) userdata;
	PurpleChat *chat = PURPLE_CHAT(node);

	DiscordChannel *channel = discord_channel_from_chat(da, chat);

	if (channel == NULL) {
		return;
	}

	/* Toggle the mute */
	channel->muted = !channel->muted;

	/* PATCH /users/@me/guilds/[guild id]/settings
	 * {"channel_overrides": {"channel_id": {"muted": true}}} */

	DiscordGuild *guild = discord_get_guild(da, channel->guild_id);

	if (guild != NULL) {
		gchar *channel_id = from_int(channel->id);

		JsonObject *data = json_object_new();
		JsonObject *override = json_object_new();
		JsonObject *setting = json_object_new();

		json_object_set_boolean_member(setting, "muted", channel->muted);
		json_object_set_object_member(override, channel_id, setting);
		json_object_set_object_member(data, "channel_overrides", override);

		gchar *postdata = json_object_to_string(data);

		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/guilds/%" G_GUINT64_FORMAT "/settings", guild->id);
		discord_fetch_url_with_method(da, "PATCH", url, postdata, NULL, NULL);

		g_free(channel_id);
		g_free(url);
		g_free(postdata);

		json_object_unref(setting);
		json_object_unref(override);
		json_object_unref(data);
	}
}

static GList *
discord_blist_node_menu(PurpleBlistNode *node)
{
	/* We only have a menu for chats */
	if (!PURPLE_IS_CHAT(node))
		return NULL;

	GList *m = NULL;
	GList *m_size = NULL;

	/* Grab a DiscordAccount */
	PurpleChat *chat = PURPLE_CHAT(node);
	PurpleAccount *acct = purple_chat_get_account(chat);
	PurpleConnection *pc = purple_account_get_connection(acct);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	/* Find the associated channel */
	DiscordChannel *channel = discord_channel_from_chat(da, chat);

	if (channel != NULL) {
		/* Make a menu */
		const char *mute_toggle = channel->muted ? _("Unmute") : _("Mute");
		PurpleMenuAction *act = purple_menu_action_new(mute_toggle, PURPLE_CALLBACK(discord_toggle_mute), da, NULL);
		m = g_list_append(m, act);

		gboolean is_limited = purple_blist_node_get_bool(node, "limit_history");
		const char *hist_limit_toggle = is_limited ? _("Grab Full History") : _("Limit Grabbed History");
		act = purple_menu_action_new(hist_limit_toggle, PURPLE_CALLBACK(discord_toggle_history_limit), da, NULL);
		m = g_list_append(m, act);

		gboolean is_large = purple_blist_node_get_bool(node, "large_channel");
		const char *large_handle_toggle = is_large ? _("Default") : _("Large Channel");
		act = purple_menu_action_new(large_handle_toggle, PURPLE_CALLBACK(discord_toggle_large_handling), da, NULL);
		//m = g_list_append(m, act);
		m_size = g_list_append(m_size, act);

		gboolean is_small = purple_blist_node_get_bool(node, "small_channel");
		const char *small_handle_toggle = is_small ? _("Default") : _("Small Channel");
		act = purple_menu_action_new(small_handle_toggle, PURPLE_CALLBACK(discord_toggle_small_handling), da, NULL);
		//m = g_list_append(m, act);
		m_size = g_list_append(m_size, act);

		const char *size_handle_toggles = _("Force Treat as...");
		act = purple_menu_action_new(size_handle_toggles, NULL, da, m_size);
		m = g_list_append(m, act);
	}

	return m;
}

static gchar *
discord_status_text(PurpleBuddy *buddy)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (purple_account_is_connected(account)) {
		PurpleConnection *pc = purple_account_get_connection(account);
		DiscordAccount *da = purple_connection_get_protocol_data(pc);
		DiscordUser *user = discord_get_user_fullname(da, purple_buddy_get_name(buddy));

		if (user == NULL) {
			return NULL;
		}

		if (user->game != NULL) {
			return g_markup_printf_escaped(_("Playing %s"), user->game);
		} else if (user->custom_status != NULL) {
			return g_markup_printf_escaped(_("%s"), user->custom_status);
		}
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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	discord_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);
}

static gboolean
discord_offline_messaging(const PurpleBuddy *buddy)
{
	return TRUE;
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

	purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));

	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (purple_account_is_connected(account)) {
		PurpleConnection *pc = purple_account_get_connection(account);
		DiscordAccount *da = purple_connection_get_protocol_data(pc);
		DiscordUser *user = discord_get_user_fullname(da, purple_buddy_get_name(buddy));

		if (user != NULL) {
			if (user->game != NULL) {
				gchar *escaped = g_markup_printf_escaped("%s", user->game);
				purple_notify_user_info_add_pair_html(user_info, _("Playing"), escaped);
				g_free(escaped);
			}
			if (user->custom_status != NULL) {
				gchar *escaped = g_markup_printf_escaped("%s", user->custom_status);
				purple_notify_user_info_add_pair_html(user_info, _("Custom Status"), escaped);
				g_free(escaped);
			}
		}
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

	option = purple_account_option_bool_new(_("Display images in conversations"), "display-images", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Display images in large servers"), "display-images-large-servers", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_int_new(_("Max displayed image width (0 disables)"), "image-size", 0);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Display custom emoji as inline images"), "show-custom-emojis", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_int_new(_("Approximate max number of users to keep track of, per server (0 disables)"), "max-guild-presences", 200);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Fetch names for reactors to backlogged messages (can be spammy)"), "fetch-react-backlog", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Fetch unread chat messages when account connects"), "fetch-unread-on-start", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(_("Open chat when you are @mention'd"), "open-chat-on-mention", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_string_new(_("Indicate thread replies with this prefix: "), "thread-indicator", "⤷ ");
	account_options = g_list_append(account_options, option);

	option = purple_account_option_string_new(_("Indicate thread parent messages with this prefix: "), "parent-indicator", "◈ ");
	account_options = g_list_append(account_options, option);

	// Only show the token auth input for non-Pidgin clients
	if (!purple_strequal(purple_core_get_ui(), "gtk-gaim")) {
		option = purple_account_option_string_new(_("Auth token"), "token", "");
		account_options = g_list_append(account_options, option);
	}

	return account_options;
}

void
discord_guild_member_screening_cb(gpointer user_data, PurpleRequestFields *fields)
{
	DiscordAccountGuildData *data = user_data;
	DiscordAccount *da = data->account;
	DiscordGuild *guild = data->guild;
	JsonObject *json_form = data->user_data;

	if(!purple_request_fields_all_required_filled(fields)) {
		// TODO: Notify user that we've rejected them
		return;
	}

	JsonArray *json_fields = json_object_get_array_member(json_form, "form_fields");
	gint form_len = json_array_get_length(json_fields);
	for (gint n = 0; n < form_len; n++) {
		JsonObject *json_field = json_array_get_object_element(json_fields, n);
		gchar *id = g_strdup_printf("field-%d", n);
		PurpleRequestField *field = purple_request_fields_get_field(fields, id);
		PurpleRequestFieldType type = purple_request_field_get_type(field);
		switch (type) { // This will get longer whenever Discord updates this stuff
		case PURPLE_REQUEST_FIELD_BOOLEAN: {
			gboolean response = purple_request_field_bool_get_value(field);
			json_object_set_boolean_member(json_field, "response", response);
			break;
		}
		default:
			break;
		}
	}
	gchar *postdata = json_object_to_string(json_form);
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/guilds/%" G_GUINT64_FORMAT "/requests/@me", guild->id);
	discord_fetch_url_with_method(da, "PUT", url, postdata, NULL, NULL);
	g_free(url);
	g_free(postdata);
	json_object_unref(json_form);
}

void
discord_guild_member_screening(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordGuild *guild = user_data;
	JsonObject *form = json_node_get_object(node);
	const gchar *form_desc = json_object_get_string_member(form, "description");
	JsonArray *form_fields = json_object_get_array_member(form, "form_fields");
	gint form_len = json_array_get_length(form_fields);
	gchar *secondary = NULL;

	PurpleRequestFields *fields = purple_request_fields_new();
	PurpleRequestFieldGroup *group = purple_request_field_group_new(NULL);

	for (gint n = 0; n < form_len; n++) {
		JsonObject *form_field = json_array_get_object_element(form_fields, n);
		const gchar *field_type = json_object_get_string_member(form_field, "field_type");
		if (!purple_strequal(field_type, "TERMS")) {
			// Currently Discord only has this one type
			continue;
		}
		gboolean required = json_object_get_boolean_member(form_field, "required");
		const gchar *label = json_object_get_string_member(form_field, "label");
		JsonArray *rules = json_object_get_array_member(form_field, "values");
		gint rules_len = json_array_get_length(rules);
		gchar *rule_string = g_strdup("");
		for (gint i = 0; i < rules_len; i++) {
			const gchar *rule_str = json_array_get_string_element(rules, i);
			gchar *tmp = g_strdup_printf("%s%d.  %s\n", rule_string, i+1, rule_str);
			g_free(rule_string);
			rule_string = tmp;
		}
		// Hack that will break if/when discord updates their screening api
		if (secondary != NULL) {
			g_free(secondary);
		}
		secondary = g_strdup_printf("%s\n\n%s:\n%s", form_desc, _("Server Rules"), rule_string);

		gchar *id = g_strdup_printf("field-%d", n);
		PurpleRequestField *field = purple_request_field_bool_new(id, label, FALSE);
		purple_request_field_set_required(field, required);
		purple_request_field_group_add_field(group, field);
		g_free(id);
	}
	purple_request_fields_add_group(fields, group);
	gchar *title = g_strdup_printf(_("%s Member Screening"), guild->name);

	DiscordAccountGuildData *data = g_new0(DiscordAccountGuildData, 1);
	data->account = da;
	data->guild = guild;
	data->user_data = json_object_ref(form);

	purple_request_fields(
		da->pc,
		title,
		title,
		secondary, //form_desc,
		fields,
		_("_OK"), G_CALLBACK(discord_guild_member_screening_cb),
		_("_Cancel"), NULL,
		purple_request_cpar_from_connection(da->pc),
		data
	);
}

static void
discord_check_invite_response(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *response = json_node_get_object(node);
	// A successful join will have "code" as a string, which converts to a 0 int
	gint code = json_object_get_int_member(response, "code");
	gchar *invite_code = user_data;

	if (code != 0) {
		const gchar *message = json_object_get_string_member(response, "message");
		gchar *error = g_strdup_printf(_("Error with invite code %s"), invite_code);

		purple_notify_error(da->pc, NULL, error, message, purple_request_cpar_from_connection(da->pc));

		g_free(error);
	}

	g_free(invite_code);
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

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/invites/%s", purple_url_encode(invite_code));

	discord_fetch_url(da, url, "{\"session_id\":null}", discord_check_invite_response, g_strdup(invite_code));

	g_free(url);
}

void
discord_join_server(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	purple_request_input(
		pc,
		_("Join a server"),
		_("Join a server"),
		_("Enter the join URL here"),
		NULL, FALSE, FALSE, "https://discord.gg/ABC123",
		_("_Join"), G_CALLBACK(discord_join_server_text),
		_("_Cancel"), NULL,
		purple_request_cpar_from_connection(pc),
		da
	);
}

void
discord_leaving_guild(gpointer user_data, int action)
{
	DiscordAccountGuild *acc_guild = user_data;
	DiscordAccount *da = acc_guild->account;
	DiscordGuild *guild = acc_guild->guild;

	purple_debug_info("discord", "Leaving guild %s\n", guild->name);
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/users/@me/guilds/%" G_GUINT64_FORMAT, guild->id);
	discord_fetch_url_with_method(da, "DELETE", url, "{}", NULL, NULL);
	g_free(url);
	// TODO: free guild?
}

void
discord_manage_servers_cb(gpointer user_data, PurpleRequestFields *fields)
{
	DiscordAccount *da = user_data;


	const GList *cur;
	for (cur = purple_request_fields_get_groups(fields); cur != NULL; cur = g_list_next(cur)) {
		const GList *prefs;
		for (prefs = purple_request_field_group_get_fields(cur->data); g_list_next(prefs) != NULL; prefs = g_list_next(prefs)) {
			PurpleRequestField *field = prefs->data;
			gchar *id = field->id;
			PurpleRequestFieldType type = purple_request_field_get_type(field);
			switch (type) {
			case PURPLE_REQUEST_FIELD_STRING: {
				const gchar *value = purple_request_field_string_get_value(field);
				purple_account_set_string(da->account, id, value);
				break;
			}
			case PURPLE_REQUEST_FIELD_INTEGER: {
				gint value = purple_request_field_int_get_value(field);
				purple_account_set_int(da->account, id, value);
				break;
			}
			case PURPLE_REQUEST_FIELD_CHOICE: {
				gint value = purple_request_field_choice_get_value(field);
				purple_account_set_int(da->account, id, value);
				break;
			}
			case PURPLE_REQUEST_FIELD_BOOLEAN: {
				gboolean value = purple_request_field_bool_get_value(field);
				purple_account_set_bool(da->account, id, value);
				break;
			}
			default:
				break;
			}
		}

		/* Handle leaving guild bool */
		PurpleRequestField *field = prefs->data;
		gboolean value = purple_request_field_bool_get_value(field);

		if (value == 0) {
			continue;
		}

		gchar **guild_id_tokens = g_strsplit(purple_request_field_get_id(field), "-", 2);
		gchar *guild_id = guild_id_tokens[0];
		DiscordGuild *guild = discord_get_guild(da, to_int(guild_id));
		g_strfreev(guild_id_tokens);
		DiscordAccountGuild *acc_guild = g_new0(DiscordAccountGuild, 1);
		acc_guild->account = da;
		acc_guild->guild = guild;
		gchar *question = g_strdup_printf(_("Are you sure you want to leave the server %s?"), guild->name);

		purple_request_yes_no(
			da->pc,
			_("Leaving Server!"),
			_("Leaving Server!"),
			question,
			1, da->account, NULL, NULL,
			acc_guild,
			G_CALLBACK(discord_leaving_guild),
			NULL
		);
		g_free(question);
	}
}

void
discord_manage_servers(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleRequestFields *fields = purple_request_fields_new();

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordGuild *guild = value;

		if (!guild) {
			continue;
		}

		PurpleRequestFieldGroup *group = purple_request_field_group_new(guild->name);

		/* Guild Abbreviation for Blist Groups */
		gchar *id = g_strdup_printf("%" G_GUINT64_FORMAT "-abbr", guild->id);
		const gchar *default_text = purple_account_get_string(da->account, id, guild->name);
		PurpleRequestField *field = purple_request_field_string_new(id, _("Buddy List Abbreviation"), default_text, FALSE);
		purple_request_field_group_add_field(group, field);
		g_free(id);

		/* Whether Guild is Considered Large or Small */
		id = g_strdup_printf("%" G_GUINT64_FORMAT "-size", guild->id);
		gint default_choice = purple_account_get_int(da->account, id, 0);
		field = purple_request_field_choice_new(id, _("Effective Guild Size"), default_choice);
		purple_request_field_choice_add(field, _("Default"));
		purple_request_field_choice_add(field, _("Large"));
		purple_request_field_choice_add(field, _("Small"));
		purple_request_field_group_add_field(group, field);
		g_free(id);

		/* LEAVE SERVER */
		id = g_strdup_printf("%" G_GUINT64_FORMAT "-leave", guild->id);
		field = purple_request_field_bool_new(id, _("Leave this server"), FALSE);
		purple_request_field_group_add_field(group, field);
		g_free(id);

		purple_request_fields_add_group(fields, group);
	}

	purple_request_fields(
		pc,
		_("Manage discord servers"),
		_("Manage discord servers"),
		_("Edit per-server settings"),
		fields,
		_("_OK"), G_CALLBACK(discord_manage_servers_cb),
		_("_Cancel"), NULL,
		purple_request_cpar_from_connection(pc),
		da
	);
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
	act = purple_protocol_action_new(_("Manage servers..."), discord_manage_servers);
	m = g_list_append(m, act);

	return m;
}

static void
discord_reply_cb(DiscordAccount *da, JsonNode *node, gpointer user_data)
{
	DiscordReply *reply = user_data;
	time_t intended_time = reply->msg_time;
	gchar *msg_txt = reply->msg_txt;
	guint64 room_id = reply->room_id;
	PurpleConversation *conv = reply->conv;

	PurpleConnection *pc = purple_conversation_get_connection(conv);

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	JsonArray *messages = json_node_get_array(node);
	guint len = json_array_get_length(messages);
	JsonObject *referenced_message = json_array_get_object_element(messages, len-1);
	const gchar *msg_id = json_object_get_string_member(referenced_message, "id");
	time_t msg_time = discord_time_from_snowflake(to_int(msg_id));

	if (msg_time != intended_time) {
		g_free(msg_txt);
		return;
	}

	gint ret = discord_conversation_send_message(da, room_id, msg_txt, msg_id);
	if (ret <= 0) {
		g_free(msg_txt);
		return;
	}

	gchar *reply_txt = discord_get_reply_text(da, guild, channel, referenced_message);

	purple_conversation_write(conv, NULL, reply_txt, PURPLE_MESSAGE_SYSTEM, time(NULL));
	g_free(reply_txt);

	gchar *tmp = g_regex_replace_eval(emoji_regex, msg_txt, -1, 0, 0, discord_replace_emoji, conv, NULL);

	if (tmp != NULL) {
		g_free(msg_txt);
		msg_txt = tmp;
	}

	msg_txt = discord_replace_mentions_bare(da, guild, msg_txt);

	if (guild) {
		gchar *name = discord_create_nickname_from_id(da, guild, channel, da->self_user_id);
		purple_serv_got_chat_in(pc, discord_chat_hash(room_id), name, PURPLE_MESSAGE_SEND, msg_txt, time(NULL));
		g_free(name);
	}

	g_free(reply);
	g_free(msg_txt);

}

static gchar *
discord_get_thread_id_from_timestamp(DiscordAccount *da, PurpleConversation *conv, const gchar *timestamp)
{
	guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");
	if (!room_id_ptr) {
		return NULL;
	}
	guint64 room_id = *room_id_ptr;
	DiscordChannel *channel = discord_get_channel_global_int(da, room_id);
	if (!channel) {
		return NULL;
	}

	time_t thread_time = discord_parse_timestring(timestamp);
	if (!thread_time) {
		return NULL;
	}

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, channel->threads);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		DiscordChannel *thread = value;
		time_t elem_time = discord_time_from_snowflake(thread->id);
		if (elem_time == thread_time)
			return from_int(thread->id);
	}

	purple_debug_info("discord", "Can't find thread at %ld\n", thread_time);
	return NULL;
}

static gboolean
discord_chat_thread_history(DiscordAccount *da, PurpleConversation *conv, guint64 room_id, gchar **args)
{
	/* Get referenced thread id */
	gchar *thread_id = discord_get_thread_id_from_timestamp(da, conv, args[0]);
	if (thread_id == NULL) {
		return FALSE;
	}
	DiscordChannel *thread = discord_get_thread_global_int_guild(da, to_int(thread_id), NULL);
	if (thread == NULL) {
		g_free(thread_id);
		return FALSE;
	}

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%s/messages?limit=100&after=1", thread_id);
	discord_fetch_url(da, url, NULL, discord_got_history_of_room, thread);
	g_free(url);
	g_free(thread_id);

	return TRUE;
}

static gboolean
discord_chat_thread_reply(DiscordAccount *da, PurpleConversation *conv, guint64 room_id, gchar **args)
{

	PurpleConnection *pc = purple_conversation_get_connection(conv);
	gchar *msg_txt = g_strdup(args[1]);
	gchar *thread_id;
	gint ret;

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	/* Format outgoing message */
	msg_txt = discord_make_mentions(da, guild, msg_txt);

	if (guild) {
		gchar *tmp = g_regex_replace_eval(emoji_natural_regex, msg_txt, -1, 0, 0, discord_replace_natural_emoji, guild, NULL);

		if (tmp != NULL) {
			g_free(msg_txt);
			msg_txt = tmp;
		}
	}
	g_return_val_if_fail(discord_get_channel_global_int(da, room_id), FALSE); /* TODO rejoin room? */

	/* Get referenced thread id */
	thread_id = discord_get_thread_id_from_timestamp(da, conv, args[0]);
	if (thread_id == NULL) {
		g_free(msg_txt);
		return FALSE;
	}

	ret = discord_conversation_send_message(da, to_int(thread_id), msg_txt, NULL);
	if (ret > 0 && guild) {
		gchar *name = discord_create_nickname_from_id(da, guild, channel, da->self_user_id);

		/* Handle thread formatting */
		time_t ts = discord_time_from_snowflake(to_int(thread_id));
		const gchar *color = "#606060";
		const gchar *indicator = purple_account_get_string(da->account, "thread-indicator", "⤷ ");

		gchar *thread_ts = discord_get_formatted_thread_timestamp(ts);

		if (msg_txt && *msg_txt) {
			gchar *tmp = g_strdup_printf(
				"%s%s: <font color=\"%s\">%s</font>",
				indicator,
				thread_ts,
				color,
				msg_txt
			);
			g_free(msg_txt);
			msg_txt = tmp;
		}
		g_free(thread_ts);

		purple_serv_got_chat_in(pc, discord_chat_hash(room_id), name, PURPLE_MESSAGE_SEND, msg_txt, time(NULL));
		g_free(name);
	}

	g_free(msg_txt);
	g_free(thread_id);

	return TRUE;
}

/*static gboolean
discord_chat_thread_new(DiscordAccount *da, PurpleConversation *conv, guint64 room_id, gchar **args)
{

	gchar *title_txt = g_strdup(args[1]);
	gchar *msg_id;
	gint ret;

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);
	//discord_get_channel_global_int_guild(da, room_id, &guild);

	// Format outgoing message
	title_txt = discord_make_mentions(da, guild, title_txt);

	if(guild) {
		gchar *tmp = g_regex_replace_eval(emoji_natural_regex, title_txt, -1, 0, 0, discord_replace_natural_emoji, guild, NULL);

		if (tmp != NULL) {
			g_free(title_txt);
			title_txt = tmp;
		}
	}

	g_return_val_if_fail(discord_get_channel_global_int(da, room_id), FALSE); // TODO rejoin room?

	// Get referenced thread id
	msg_id = discord_get_message_id_from_timestamp(conv, args[0]);
	if (msg_id == NULL) {
		g_free(title_txt);
		return FALSE;
	}

	ret = discord_conversation_send_message(da, to_int(msg_id), title_txt, NULL);
	if (ret > 0 && guild) {
		gchar *name = discord_create_nickname_from_id(da, guild, channel, da->self_user_id);
		//purple_serv_got_chat_in(pc, discord_chat_hash(room_id), name, PURPLE_MESSAGE_SEND, title_txt, time(NULL));
		g_free(name);
	}

	g_free(title_txt);
	g_free(thread_id);

	return TRUE;
}*/

static void
discord_chat_get_history(gpointer user_data, int action)
{
	PurpleConversation *conv = user_data;
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, NULL);
	if (channel == NULL) {
		return;
	}

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=1", room_id);
	discord_fetch_url(da, url, NULL, discord_got_history_of_room, channel);
	g_free(url);

	return;
}



static gboolean
discord_chat_reply(DiscordAccount *da, PurpleConversation *conv, guint64 room_id, gchar **args)
{

	gchar *msg_txt = g_strdup(args[1]);

	DiscordGuild *guild = NULL;
	//DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);
	discord_get_channel_global_int_guild(da, room_id, &guild);

	/* Format outgoing message */
	msg_txt = discord_make_mentions(da, guild, msg_txt);

	if(guild) {
		gchar *tmp = g_regex_replace_eval(emoji_natural_regex, msg_txt, -1, 0, 0, discord_replace_natural_emoji, guild, NULL);

		if (tmp != NULL) {
			g_free(msg_txt);
			msg_txt = tmp;
		}
	}

	g_return_val_if_fail(discord_get_channel_global_int(da, room_id), FALSE); /* TODO rejoin room? */

	DiscordReply *reply = g_new0(DiscordReply, 1);
	reply->room_id = room_id;
	reply->msg_txt = g_strdup(msg_txt);
	reply->conv = conv;

	time_t msg_time;
	if (strchr(args[0], ':')) {
		msg_time = discord_parse_timestring(args[0]);
	} else {
		gchar *msg_id = g_strdup(args[0]);
		msg_time = discord_time_from_snowflake(to_int(msg_id));
		g_free(msg_id);
	}
	reply->msg_time = msg_time;

	guint64 placeholder_id = discord_snowflake_from_time(msg_time);
	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=5&after=%" G_GUINT64_FORMAT, room_id, placeholder_id);
	discord_fetch_url(da, url, NULL, discord_reply_cb, reply);
	g_free(url);
	g_free(msg_txt);

	return TRUE;
}

static gboolean
discord_chat_react(DiscordAccount *da, PurpleConversation *conv, guint64 id, gboolean is_unreact, gchar **args)
{
	const gchar *raw_emoji = args[1];
	gchar *emoji = NULL;
	if (g_str_has_prefix(raw_emoji, ":") && g_str_has_suffix(raw_emoji, ":")) {
		gchar **emoji_parts = g_strsplit(args[1], ":", -1);
		emoji = g_strdup(emoji_parts[1]);
		g_strfreev(emoji_parts);
	} else {
		emoji = g_strdup(raw_emoji);
	}

	DiscordGuild *guild = NULL;
	discord_get_channel_global_int_guild(da, id, &guild);
	gchar *emoji_id = NULL;
	if (guild != NULL) {
		emoji_id = g_hash_table_lookup(guild->emojis, emoji);
	}

	if (emoji_id != NULL) {
		gchar *tmp = g_strdup_printf("%s:%s", emoji, emoji_id);
		if (emoji != NULL)
			g_free(emoji);
		emoji = tmp;
	}

	if (emoji == NULL) {
		return FALSE;
	}

	/* Get referenced message id */
	if (strchr(args[0], ':')) {
		time_t msg_time = discord_parse_timestring(args[0]);
		guint64 placeholder_id = discord_snowflake_from_time(msg_time);
		DiscordReaction *send_react = g_new0(DiscordReaction, 1);
		send_react->conv = conv;
		send_react->msg_time = msg_time;
		send_react->reaction = (gpointer) emoji;
		send_react->is_unreact = is_unreact;
		send_react->msg_txt = g_strdup("");

		gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages?limit=5&after=%" G_GUINT64_FORMAT, id, placeholder_id);
		discord_fetch_url(da, url, NULL, discord_send_react_cb, send_react);
		g_free(url);
		return TRUE;
	}

	gchar *msg_id = g_strdup(args[0]);

	gchar *url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages/%s/reactions/%s/%%40me", id, msg_id, purple_url_encode(emoji));
	discord_fetch_url_with_method(da, "PUT", url, "{}", NULL, NULL);
	g_free(url);
	g_free(msg_id);
	g_free(emoji);
	return TRUE;

}

static gchar **
discord_parse_wS_args(gchar **args)
{
	gchar *new = purple_markup_strip_html(args[0]);
	gchar **in_progress = g_strsplit(new, " ", 2);
	gchar **matcher = g_strsplit(args[0], " ", -1);

	if (g_strv_length(matcher) < 2) {
		g_strfreev(matcher);
		g_strfreev(in_progress);
		return NULL;
	}

	gchar *remaining = NULL;
	for (gchar **iter = matcher + 1; **iter != '\0'; iter++) {
		remaining = g_strjoinv(" ", iter);
		gchar *match = purple_markup_strip_html(remaining);

		if (purple_strequal(match, in_progress[1])) {
			break;
		}

		g_free(match);
		g_free(remaining);
		remaining = NULL;
	}

	gchar *tmp;
	if (remaining == NULL) {
		tmp = g_strjoin(" ", in_progress[0], in_progress[1], NULL);
	} else {
		tmp = g_strjoin(" ", in_progress[0], remaining, NULL);
	}

	gchar **parsed_args = g_strsplit(tmp, " ", 2);
	g_free(tmp);
	g_strfreev(matcher);
	g_strfreev(in_progress);
	return parsed_args;

}

static PurpleCmdRet
discord_cmd_reply(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)room_id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}
	gchar **parsed_args = discord_parse_wS_args(args);
	if (parsed_args == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}

	gboolean is_okay = discord_chat_reply(da, conv, room_id, parsed_args);

	g_strfreev(parsed_args);

	if (is_okay)
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet
discord_cmd_react(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}


	gboolean is_okay = discord_chat_react(da, conv, id, FALSE, args);

	if (is_okay)
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet
discord_cmd_unreact(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}


	gboolean is_okay = discord_chat_react(da, conv, id, TRUE, args);

	if (is_okay)
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
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
discord_cmd_roles(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_roles(pc, id);

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

static PurpleCmdRet
discord_cmd_kick(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_kick_username(pc, id, args[0]);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_ban(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_ban_username(pc, id, args[0]);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_threads(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	discord_chat_threads(pc, id, args[0]);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_thread(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)room_id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}
	gchar **parsed_args = discord_parse_wS_args(args);
	if (parsed_args == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}

	gboolean is_okay = discord_chat_thread_reply(da, conv, room_id, parsed_args);

	g_strfreev(parsed_args);

	if (is_okay) {
		return PURPLE_CMD_RET_OK;
	}
	return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet
discord_cmd_thread_history(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)room_id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	gboolean is_okay = discord_chat_thread_history(da, conv, room_id, args);

	if (is_okay) {
		return PURPLE_CMD_RET_OK;
	}
	return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet
discord_cmd_get_history(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)room_id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	purple_request_yes_no(
		da->pc,
		_("Warning"),
		_("Warning"),
		_("Fetching a channel's entire history can take a lot of memory and time to complete. Are you sure you want to continue?"),
		1, da->account, NULL, NULL,
		conv,
		G_CALLBACK(discord_chat_get_history),
		NULL
	);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_get_server_name(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	guint64 room_id = *(guint64 *) purple_conversation_get_data(conv, "id");

	if (pc == NULL || (int)room_id == -1) {
		return PURPLE_CMD_RET_FAILED;
	}

	DiscordGuild *guild = NULL;
	DiscordChannel *channel = discord_get_channel_global_int_guild(da, room_id, &guild);

	if (channel == NULL || guild == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}

	gchar *server_msg = g_strdup_printf(_("Server Name: %s"), guild->name);
	purple_conversation_write_system_message(conv, server_msg, PURPLE_MESSAGE_SYSTEM);
	g_free(server_msg);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
discord_cmd_join_server(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);

	discord_join_server_text(da, args[0]);

	return PURPLE_CMD_RET_OK;
}

#if !PURPLE_VERSION_CHECK(3, 0, 0)
static void
discord_xfer_free(PurpleXfer *xfer) {
	// we only need to free the user data
	g_free(purple_xfer_get_protocol_data(xfer));
	purple_debug_info("discord", "ref count %d\n", xfer->ref);
}

static void
discord_xfer_cancel_send(PurpleXfer *xfer) {
	DiscordTransfer *dt = purple_xfer_get_protocol_data(xfer);
	if (dt->canceleable) {
		// prevents segfault from freeing an xfer that is in use
		purple_xfer_ref(xfer);
		PurpleConnection *pc = purple_account_get_connection(purple_xfer_get_account(xfer));
		purple_notify_error(pc, _("Can't Cancel Upload"), _("Cannot Cancel Discord Upload After Start"), NULL, purple_get_cpar_from_connection(pc));
	} else {
		discord_xfer_free(xfer);
	}
}

static void
purple_xfer_update_cb(DiscordAccount *da, JsonNode *node, gpointer userdata) {
	PurpleXfer *xfer = (PurpleXfer *) userdata;
	purple_xfer_ref(xfer);
	
	DiscordTransfer *dt = purple_xfer_get_protocol_data(xfer);
	PurpleAccount *acct = purple_xfer_get_account(xfer);
	PurpleConnection *pc = purple_account_get_connection(acct);
	const gchar *who = purple_xfer_get_remote_user(xfer);

	// couldn't find a libpurple/glib standard buf size, this should be fine
	gchar xfer_info[1024];
	g_snprintf(xfer_info, 1024, "Upload From: %s\n To: %s", purple_account_get_name_for_display(acct), who);

	// The following may say the xfer is canceled when it isn't, but it's
	// the best we can do
	if (node == NULL) {
		purple_notify_error(pc, _("Connection Error"), NULL, xfer_info, purple_get_cpar_from_connection(pc));

		purple_xfer_unref(xfer);
		dt->canceleable = TRUE;
		purple_xfer_cancel_remote(xfer);
		return;
	} else {
		JsonObject *result = json_node_get_object(node);

		gchar *json_str;
		JsonGenerator *jg;

		jg = json_generator_new();
		json_generator_set_root(jg, node);
		json_str = json_generator_to_data(jg, NULL);
		purple_debug_info("discord", "xfer/http upload returned:\n %s\n", json_str);

		g_free(json_str);
		g_object_unref(jg);

		const gchar *body = json_object_get_string_member(result, "body");
		if (body != NULL) {
			purple_notify_error(pc, _("Malformed Response"), _("Check Debug Logs For More Info") , xfer_info, purple_get_cpar_from_connection(pc));
			purple_xfer_unref(xfer);
			dt->canceleable = TRUE;
			purple_xfer_cancel_remote(xfer);
			return;
		}

		// if there any error codes that are worth it to work around we
		// can put them here
		JsonNode *code_node = json_object_get_member(result, "code");
		if (code_node != NULL) {
			gint64 result_code = json_node_get_int(code_node);
			gchar code_str[1024];
			g_snprintf(code_str, 1024, "%" G_GINT64_FORMAT, result_code);
			const gchar *result_msg = json_object_get_string_member(result, "message");
			purple_debug_error("discord", "xfer/http upload returned code: %s and message:\n%s\n", code_str, result_msg);
			purple_notify_error(pc, code_str, result_msg, xfer_info, purple_get_cpar_from_connection(pc));
			purple_xfer_unref(xfer);
			dt->canceleable = TRUE;
			purple_xfer_cancel_remote(xfer);
			return;
		}

		// we could also update the bytes sent with the last two
		// exceptions, but it isn't necessarily true or helpful
		purple_xfer_set_bytes_sent(xfer, purple_xfer_get_size(xfer));
		// updating the progress after setting the bytes sent is not
		// necessary for pidgin, but it may be for other clients
		purple_xfer_update_progress(xfer);
		purple_xfer_unref(xfer);
		purple_xfer_set_completed(xfer, TRUE);
		purple_xfer_end(xfer);
	}
}

// TODO progress, true cancel
static void
discord_xfer_send_init(PurpleXfer *xfer)
{
	gchar *filename;
	gchar *url;
	gchar *nonce;
	gchar *mimetype;
	GMappedFile *file;
	GString *postdata;

	purple_xfer_ref(xfer);

	PurpleAccount *acct = purple_xfer_get_account(xfer);
	PurpleConnection *pc = purple_account_get_connection(acct);
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	DiscordTransfer *dt = purple_xfer_get_protocol_data(xfer);

	const gchar* fullpath = purple_xfer_get_local_filename(xfer);

	GError *load_error = NULL;

	file = g_mapped_file_new(fullpath, FALSE, &load_error);
	if (load_error != NULL) {
		purple_debug_error("discord", "Couldn't load file to send: %s\n", load_error->message);
		purple_xfer_error(PURPLE_XFER_SEND, acct, purple_xfer_get_remote_user(xfer), _("Couldn't load file"));
		// TODO afaik there's no way to get pidgin to close after a
		// non-complete xfer :(
		purple_xfer_cancel_local(xfer);
		g_mapped_file_unref(file);
		g_free(load_error);
		return;
	}
	g_free(load_error);

	goffset file_len = g_mapped_file_get_length(file);
	if (file_len > 25000000) {
		purple_xfer_error(PURPLE_XFER_SEND, acct, purple_xfer_get_remote_user(xfer), _("Maximum file size is 25MB"));
		// "just for show"
		purple_xfer_cancel_local(xfer);
		g_mapped_file_unref(file);
		return;
	}
	purple_xfer_set_size(xfer, file_len);

	// though the gtk glib docs say otherwise, it appears that the contents
	// are NOT the responsibility of the caller
	gchar *contents = g_mapped_file_get_contents(file);

	gboolean guessing;
	mimetype = g_content_type_guess(fullpath, (guchar *) contents, file_len, &guessing);
	if (guessing)
		purple_notify_info(da, fullpath, _("Guessing file type is:"), mimetype);

	filename = g_path_get_basename(fullpath);
	purple_xfer_set_filename(xfer, filename);

	// We don't insert this into sent messages because that will prevent it
	// from appearing in our client
	nonce = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "------PurpleBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n", purple_url_encode(filename), mimetype);
	g_string_append_len(postdata, contents, file_len);
	g_string_append_printf(postdata, "\r\n------PurpleBoundary\r\nContent-Disposition: form-data; name=\"payload_json\"\r\n\r\n{\"content\":\"\",\"nonce\":\"%s\",\"tts\":false}\r\n", nonce);
	g_string_append(postdata, "------PurpleBoundary--\r\n");

	url = g_strdup_printf("https://" DISCORD_API_SERVER "/api/" DISCORD_API_VERSION "/channels/%" G_GUINT64_FORMAT "/messages", dt->room_id);

	// This and a lot of status updates are "just for show" here, they only
	// help other programs/the user guess at what we're doing
	purple_xfer_start(xfer, -1, NULL, -1);
	purple_xfer_ui_ready(xfer);
	purple_xfer_update_progress(xfer);

	dt->canceleable = TRUE;
	discord_fetch_url_with_method_len(da, "POST", url, postdata->str, postdata->len, purple_xfer_update_cb, xfer);

	purple_xfer_unref(xfer);

	g_free(filename);
	g_free(url);
	g_free(nonce);
	g_free(mimetype);
	g_mapped_file_unref(file);
	g_string_free(postdata, TRUE);
}

// This is not hooked into 'new_xfer' like you may see in other prpl's
static PurpleXfer *
discord_create_xfer(PurpleConnection *pc, guint64 room_id, const gchar *receiver) 
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleXfer *xfer;

	xfer = purple_xfer_new(da->account, PURPLE_XFER_SEND, receiver);

	DiscordTransfer *dt = g_new(DiscordTransfer, 1);
	dt->room_id = room_id;
	dt->canceleable = FALSE;
	purple_xfer_set_protocol_data(xfer, dt);

	purple_xfer_set_init_fnc(xfer, discord_xfer_send_init);
	purple_xfer_set_end_fnc(xfer, discord_xfer_free);
	purple_xfer_set_cancel_send_fnc(xfer, discord_xfer_cancel_send);

	return xfer;
}

static void
discord_send_file(PurpleConnection *pc, const gchar *who, const gchar *filename) 
{
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	gchar *room_id_str = g_hash_table_lookup(da->one_to_ones_rev, who);
	if (room_id_str == NULL) {
		// AFAIK creating new DM's seems to be somewhat broken, so
		// sending a regular message might not work, but that issue
		// isn't really in the scope of adding a file upload option
		purple_notify_error(da, _("DM Does Not Exist"), _("DM does not exist"), _("Try Sending A Regular Message First"), 
			purple_request_cpar_from_connection(pc));
		return;
	}
	guint64 room_id = g_ascii_strtoull(room_id_str, NULL, 10);

	PurpleXfer *xfer = discord_create_xfer(pc, room_id, who);

	if (filename && *filename)
		purple_xfer_request_accepted(xfer, filename);
	else
		purple_xfer_request(xfer);
}

static void
discord_chat_send_file(PurpleConnection *pc, int id, const gchar *filename) {
	DiscordAccount *da = purple_connection_get_protocol_data(pc);
	PurpleConvChat *chatconv = purple_conversations_find_chat(pc, id);
	PurpleConversation *conv = PURPLE_CONVERSATION(chatconv);
	guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");

	if (room_id_ptr == NULL) {
			purple_debug_error("discord", "Couldn't find room id of chat: %s\n", conv->name);
			purple_notify_error(da, conv->name, _("Couldn't find room id"), _("Check debug messages for more info"), 
				purple_request_cpar_from_connection(pc));
			return;
	}

	PurpleXfer *xfer = discord_create_xfer(pc, *room_id_ptr, conv->name);

	// Pidgin itself doesn't actually let you drag and drop files into
	// conversations, but this is in case any other client does (or Pidgin
	// ends up supporting it)
	if (filename && *filename)
		purple_xfer_request_accepted(xfer, filename);
	else
		purple_xfer_request(xfer);
}

static gboolean
discord_can_receive_file(PurpleConnection *pc, const gchar *who) 
{
	if (!who || g_str_equal(who, purple_account_get_username(purple_connection_get_account(pc))))
		return FALSE;

	return TRUE;
}

static gboolean
discord_chat_can_receive_file(PurpleConnection *pc, int id) {
	// As of now, I don't forsee any conditions under which we'd like to
	// prematurely disable the save function, but I'll leave this here just
	// in case
	return TRUE;
}
#endif

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
	discord_mention_regex = g_regex_new("(?:^|\\s)@([^\\s@]+)\\b", G_REGEX_OPTIMIZE, 0, NULL);
	discord_spaced_mention_regex = g_regex_new("(?:^|\\s)@([^\\s@]+ [^\\s@]+)\\b", G_REGEX_OPTIMIZE, 0, NULL);

	purple_cmd_register(
		"reply", "S", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_reply,
		_("reply &lt;timestamp&gt; &lt;message&gt;:  Replies to the message at &lt;timestamp&gt; with &lt;message&gt;<br />Accepted timestamp formats: YYYY-MM-DDthh:mm:ss, YYYY-MM-DDThh:mm:ss, hh:mm:ss"), NULL
	);

	purple_cmd_register(
		"react", "ws", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_react,
		_("react &lt;timestamp&gt; &lt;emoji&gt;:  Reacts to the message at &lt;timestamp&gt; with &lt;emoji&gt;<br />Accepted timestamp formats: YYYY-MM-DDthh:mm:ss, YYYY-MM-DDThh:mm:ss, hh:mm:ss"), NULL
	);

	purple_cmd_register(
		"unreact", "ws", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_unreact,
		_("unreact &lt;timestamp&gt; &lt;emoji&gt;:  Removes the reaction &lt;emoji&gt; from the message at &lt;timestamp&gt;<br />Accepted timestamp formats: YYYY-MM-DDthh:mm:ss, YYYY-MM-DDThh:mm:ss, hh:mm:ss"), NULL
	);

	purple_cmd_register(
		"nick", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_nick,
		_("nick &lt;new nickname&gt;:  Changes nickname on a server"), NULL
	);

	purple_cmd_register(
		"kick", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_kick,
		_("kick &lt;username&gt;:  Remove someone from a server"), NULL
	);

	purple_cmd_register(
		"ban", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_ban,
		_("ban &lt;username&gt;:  Remove someone from a server and prevent them rejoining"), NULL
	);

	purple_cmd_register(
		"leave", "", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_leave,
		_("leave:  Leave the channel"), NULL
	);

	purple_cmd_register(
		"part", "", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_leave,
		_("part:  Leave the channel"), NULL
	);

	purple_cmd_register(
		"pinned", "", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_pinned,
		_("pinned:  Display pinned messages"), NULL
	);

	purple_cmd_register(
		"roles", "", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_roles,
		_("roles:  Display server roles"), NULL
	);

	purple_cmd_register(
		"thread", "S", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_cmd_thread,
		_("thread &lt;timestamp&gt; &lt;message&gt;:  Sends message to thread<br />Accepted timestamp formats: YYYY-MM-DDthh:mm:ss, YYYY-MM-DDThh:mm:ss, hh:mm:ss"), NULL
	);

	purple_cmd_register(
			"threads", "", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_threads,
						_("threads:  Display active channel threads"), NULL
	);

	purple_cmd_register(
			"threadhistory", "w", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_thread_history,
						_("threadhistory &lt;timestamp&gt;:  Retrieves full history of thread"), NULL
	);

	purple_cmd_register(
			"thist", "w", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_thread_history,
						_("thist &lt;timestamp&gt;:  Retrieves full history of thread.<br />Alias of threadhistory"), NULL
	);

	purple_cmd_register(
			"grabhistory", "", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						DISCORD_PLUGIN_ID, discord_cmd_get_history,
						_("grabhistory:  Retrieves full history of channel. Intended for rules channels and the like. Using this on old, highly active channels is not recommended"), NULL
	);

	purple_cmd_register(
			"hist", "", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						DISCORD_PLUGIN_ID, discord_cmd_get_history,
						_("hist:  Retrieves full history of channel. Intended for rules channels and the like. Using this on old, highly active channels is not recommended.<br />Alias of grabhistory"), NULL
	);

	purple_cmd_register(
			"servername", "", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						DISCORD_PLUGIN_ID, discord_cmd_get_server_name,
						_("servername:  Displays the name of the server for the current channel."), NULL
	);

	purple_cmd_register(
			"server", "", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						DISCORD_PLUGIN_ID, discord_cmd_get_server_name,
						_("servername:  Displays the name of the server for the current channel."), NULL
	);

	purple_cmd_register(
			"joinserver", "s", PURPLE_CMD_P_PLUGIN,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						DISCORD_PLUGIN_ID, discord_cmd_join_server,
						_("joinserver &lt;invite code/URL&gt;:   Joins a new server using the invite code or URL."), NULL
	);

#if 0
	purple_cmd_register(
		"mute", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_slash_command,
		_("mute <username>:  Mute someone in channel"), NULL
	);

	purple_cmd_register(
		"unmute", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_slash_command,
		_("unmute <username>:  Un-mute someone in channel"), NULL
	);

	purple_cmd_register(
		"topic", "s", PURPLE_CMD_P_PLUGIN,
		PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
		DISCORD_PLUGIN_ID, discord_slash_command,
		_("topic <description>:  Set the channel topic description"), NULL
	);
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
	g_regex_unref(discord_spaced_mention_regex);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)


// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();

	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();

	return plugin_unload(plugin, NULL);
}

// Add forwards-compatibility for newer libpurple's when compiling on older ones
typedef struct 
{
	PurplePluginProtocolInfo parent;

	#if !PURPLE_VERSION_CHECK(2, 14, 0)
		char *(*get_cb_alias)(PurpleConnection *gc, int id, const char *who);
		gboolean (*chat_can_receive_file)(PurpleConnection *, int id);
		void (*chat_send_file)(PurpleConnection *, int id, const char *filename);
	#endif
} PurplePluginProtocolInfoExt;


static void
plugin_init(PurplePlugin *plugin)
{

#ifdef ENABLE_NLS
	bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

	PurplePluginInfo *info;
	PurplePluginProtocolInfoExt *prpl_info_ext = g_new0(PurplePluginProtocolInfoExt, 1);
	PurplePluginProtocolInfo *prpl_info = (PurplePluginProtocolInfo *) prpl_info_ext;

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

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME | OPT_PROTO_IM_IMAGE | OPT_PROTO_PASSWORD_OPTIONAL;
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
	prpl_info->blist_node_menu = discord_blist_node_menu;
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

	prpl_info->send_file = discord_send_file;
	prpl_info->can_receive_file = discord_can_receive_file;
	#if PURPLE_VERSION_CHECK(2, 14, 0)
		prpl_info->chat_send_file = discord_chat_send_file;
		prpl_info->chat_can_receive_file = discord_chat_can_receive_file;
	#else
		prpl_info_ext->chat_send_file = discord_chat_send_file;
		prpl_info_ext->chat_can_receive_file = discord_chat_can_receive_file;
	#endif

	prpl_info->roomlist_get_list = discord_roomlist_get_list;
	prpl_info->roomlist_room_serialize = discord_roomlist_serialize;

	prpl_info->offline_message = discord_offline_messaging;
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
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME | OPT_PROTO_PASSWORD_OPTIONAL;
	info->account_options = discord_add_account_options(info->account_options);
}

static void
discord_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = discord_login;
	prpl_info->close = discord_close;
	prpl_info->status_types = discord_status_types;
	prpl_info->blist_node_menu = discord_blist_node_menu;
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
		"flags",
		PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(discord, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
