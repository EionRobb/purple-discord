/*
 *   Discord plugin for libpurple
 *   Copyright (C) 2016-2017 Eion Robb
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

#include <purple.h>
#if PURPLE_VERSION_CHECK(3, 0, 0)
#include <http.h>
#endif

#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#ifdef _WIN32
#include <win32/win32dep.h>
#endif

// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_connection_error purple_connection_error_reason
#define purple_connection_get_protocol purple_connection_get_prpl
#define PURPLE_CONNECTION_CONNECTING PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED PURPLE_CONNECTED
#define PURPLE_CONNECTION_FLAG_HTML PURPLE_CONNECTION_HTML
#define PURPLE_CONNECTION_FLAG_NO_BGCOLOR PURPLE_CONNECTION_NO_BGCOLOR
#define PURPLE_CONNECTION_FLAG_NO_FONTSIZE PURPLE_CONNECTION_NO_FONTSIZE
#define PURPLE_CONNECTION_FLAG_NO_IMAGES PURPLE_CONNECTION_NO_IMAGES
#define purple_connection_set_flags(pc, f) ((pc)->flags = (f))
#define purple_connection_get_flags(pc) ((pc)->flags)
#define purple_blist_find_group purple_find_group
#define purple_protocol_action_get_connection(action) ((PurpleConnection *) (action)->context)
#define purple_protocol_action_new purple_plugin_action_new
#define purple_protocol_get_id purple_plugin_get_id
#define PurpleProtocolAction PurplePluginAction
#define PurpleProtocolChatEntry struct proto_chat_entry
#define PurpleChatConversation PurpleConvChat
#define PurpleIMConversation PurpleConvIm
#define purple_conversations_find_chat_with_account(id, account) \
	PURPLE_CONV_CHAT(purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, id, account))
#define purple_chat_conversation_has_left purple_conv_chat_has_left
#define PurpleConversationUpdateType PurpleConvUpdateType
#define PURPLE_CONVERSATION_UPDATE_UNSEEN PURPLE_CONV_UPDATE_UNSEEN
#define PURPLE_IS_IM_CONVERSATION(conv) (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
#define PURPLE_IS_CHAT_CONVERSATION(conv) (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
#define PURPLE_CONVERSATION(chatorim) ((chatorim) == NULL ? NULL : (chatorim)->conv)
#define PURPLE_IM_CONVERSATION(conv) PURPLE_CONV_IM(conv)
#define PURPLE_CHAT_CONVERSATION(conv) PURPLE_CONV_CHAT(conv)
#define purple_conversation_present_error purple_conv_present_error
#define purple_serv_got_joined_chat(pc, id, name) PURPLE_CONV_CHAT(serv_got_joined_chat(pc, id, name))
static inline PurpleConvChat *
purple_conversations_find_chat(PurpleConnection *pc, int id)
{
	PurpleConversation *conv = purple_find_chat(pc, id);

	if (conv != NULL) {
		return PURPLE_CONV_CHAT(conv);
	}

	return NULL;
}
#define purple_serv_got_chat_in serv_got_chat_in
#define purple_chat_conversation_add_user purple_conv_chat_add_user
#define purple_chat_conversation_add_users purple_conv_chat_add_users
#define purple_chat_conversation_remove_user purple_conv_chat_remove_user
#define purple_chat_conversation_clear_users purple_conv_chat_clear_users
#define purple_chat_conversation_has_user purple_conv_chat_find_user
#define purple_chat_conversation_rename_user purple_conv_chat_rename_user
#define purple_chat_conversation_get_topic purple_conv_chat_get_topic
#define purple_chat_conversation_set_topic purple_conv_chat_set_topic
#define purple_chat_conversation_set_nick purple_conv_chat_set_nick
#define PurpleChatUserFlags PurpleConvChatBuddyFlags
#define PURPLE_CHAT_USER_NONE PURPLE_CBFLAGS_NONE
#define PURPLE_CHAT_USER_OP PURPLE_CBFLAGS_OP
#define PURPLE_CHAT_USER_FOUNDER PURPLE_CBFLAGS_FOUNDER
#define PURPLE_CHAT_USER_TYPING PURPLE_CBFLAGS_TYPING
#define PURPLE_CHAT_USER_AWAY PURPLE_CBFLAGS_AWAY
#define PURPLE_CHAT_USER_HALFOP PURPLE_CBFLAGS_HALFOP
#define PURPLE_CHAT_USER_VOICE PURPLE_CBFLAGS_VOICE
#define PURPLE_CHAT_USER_TYPING PURPLE_CBFLAGS_TYPING
#define PurpleChatUser PurpleConvChatBuddy
static inline PurpleChatUser *
purple_chat_conversation_find_user(PurpleChatConversation *chat, const char *name)
{
	PurpleChatUser *cb = purple_conv_chat_cb_find(chat, name);

	if (cb != NULL) {
		g_dataset_set_data(cb, "chat", chat);
	}

	return cb;
}
#define purple_chat_user_get_flags(cb) purple_conv_chat_user_get_flags(g_dataset_get_data((cb), "chat"), (cb)->name)
#define purple_chat_user_set_flags(cb, f) purple_conv_chat_user_set_flags(g_dataset_get_data((cb), "chat"), (cb)->name, (f))
#define purple_chat_user_set_alias(cb, a) (g_free((cb)->alias), (cb)->alias = g_strdup(a))
#define PurpleIMTypingState PurpleTypingState
#define PURPLE_IM_NOT_TYPING PURPLE_NOT_TYPING
#define PURPLE_IM_TYPING PURPLE_TYPING
#define PURPLE_IM_TYPED PURPLE_TYPED
#define purple_conversation_get_connection purple_conversation_get_gc
#define purple_conversation_write_system_message(conv, message, flags) purple_conversation_write((conv), NULL, (message), ((flags) | PURPLE_MESSAGE_SYSTEM), time(NULL))
#define purple_chat_conversation_get_id purple_conv_chat_get_id
#define PURPLE_CMD_FLAG_PROTOCOL_ONLY PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_IS_BUDDY PURPLE_BLIST_NODE_IS_BUDDY
#define PURPLE_IS_CHAT PURPLE_BLIST_NODE_IS_CHAT
#define purple_chat_get_name_only purple_chat_get_name
#define purple_blist_find_buddy purple_find_buddy
#define purple_serv_got_alias serv_got_alias
#define purple_account_set_private_alias purple_account_set_alias
#define purple_account_get_private_alias purple_account_get_alias
#define purple_protocol_got_user_status purple_prpl_got_user_status
#define purple_protocol_got_user_idle purple_prpl_got_user_idle
#define purple_serv_got_im serv_got_im
#define purple_serv_got_typing serv_got_typing
#define purple_conversations_find_im_with_account(name, account) \
	PURPLE_CONV_IM(purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account))
#define purple_im_conversation_new(account, from) PURPLE_CONV_IM(purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from))
#define PurpleMessage PurpleConvMessage
#define purple_message_set_time(msg, time) ((msg)->when = (time))
#define purple_conversation_write_message(conv, msg) purple_conversation_write(conv, msg->who, msg->what, msg->flags, msg->when)
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

#define purple_message_get_recipient(message) (message->who)
#define purple_message_get_contents(message) (message->what)
#if !PURPLE_VERSION_CHECK(2, 12, 0)
#define PURPLE_MESSAGE_REMOTE_SEND 0x10000
#endif

#define purple_account_privacy_deny_add purple_privacy_deny_add
#define purple_account_privacy_deny_remove purple_privacy_deny_remove
#define PurpleHttpConnection PurpleUtilFetchUrlData
#define purple_buddy_set_name purple_blist_rename_buddy
#define purple_request_cpar_from_connection(a) purple_connection_get_account(a), NULL, NULL
#define purple_notify_user_info_add_pair_html purple_notify_user_info_add_pair

#ifdef purple_notify_error
#undef purple_notify_error
#endif
#define purple_notify_error(handle, title, primary, secondary, cpar)  \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_ERROR, (title), \
						  (primary), (secondary), NULL, NULL)

// Kinda gross, since we can technically use the glib mainloop from purple2
#define g_timeout_add_seconds  purple_timeout_add_seconds
#define g_timeout_add          purple_timeout_add
#define g_source_remove        purple_timeout_remove

#else
// Purple3 helper functions
#define purple_conversation_set_data(conv, key, value) g_object_set_data(G_OBJECT(conv), key, value)
#define purple_conversation_get_data(conv, key) g_object_get_data(G_OBJECT(conv), key)
#define purple_message_destroy g_object_unref
#define purple_chat_user_set_alias(cb, alias) g_object_set((cb), "alias", (alias), NULL)
#define purple_chat_get_alias(chat) g_object_get_data(G_OBJECT(chat), "alias")
#define purple_protocol_action_get_connection(action) ((action)->connection)
#define PURPLE_TYPE_STRING G_TYPE_STRING
//TODO remove this when dx adds this to the PurpleMessageFlags enum
#define PURPLE_MESSAGE_REMOTE_SEND 0x10000
#endif
