# purple-discord
A libpurple/Pidgin plugin for Discord

( For free/libre software that allows you to create/manage your account with Discord, check out [Harmony](https://github.com/taylordotfish/harmony) )

Windows
-------
Windows nightly builds from [here](https://eion.robbmob.com/libdiscord.dll)

The plugin requires libjson-glib which can be downloaded [from github](https://github.com/EionRobb/skype4pidgin/raw/master/skypeweb/libjson-glib-1.0.dll) and copied to the Program Files\Pidgin folder (not the plugins subfolder).

Fedora/CentOS/RHEL
---------
On Fedora you can install [package](https://apps.fedoraproject.org/packages/purple-discord) from Fedora's main repository:

```bash
	sudo dnf install purple-discord pidgin-discord
```

On CentOS/RHEL you can install [package](https://apps.fedoraproject.org/packages/purple-discord) from Fedora's [EPEL7](https://fedoraproject.org/wiki/EPEL) repository:

```bash
	sudo yum install purple-discord pidgin-discord
```

Thank you to Vitaly Zaitsev for this package.

Gentoo
--------

Extract [purple-discord-9999.ebuild](https://github.com/EionRobb/purple-discord/files/994369/ebuild.zip) and copy it to `/usr/local/portage/x11-plugins/purple-discord` with folders created as necessary.

```bash
    mkdir -p /usr/local/portage/x11-plugins/purple-discord
	cp purple-discord-9999.ebuild /usr/local/portage/x11-plugins/purple-discord
	cd /usr/local/portage/x11-plugins/purple-discord
	ebuild purple-discord-9999.ebuild manifest
	eix-update; eix-diff # only if eix is installed
	emerge purple-discord
```

Thank you to Penaz for this package.

Compiling
---------
Requires devel headers/libs for libpurple and libjson-glib [libglib2.0-dev, libjson-glib-dev and libpurple-dev], [libnss3-dev and libqrencode-dev] (for QR Code authentication), as well as ImageMagick [imagemagick] (to build icons) and [gettext] (for translations).
```bash
	git clone https://github.com/EionRobb/purple-discord.git
	cd purple-discord
	make
	sudo make install
```

Slash Commands
--------------
Purple-discord supports the following slash commands:

| Command | Usage | Description |
| ------- | ----- | ----------- |
| nick | `/nick <new nickname>` | Changes nickname on a server. |
| kick | `/kick <username>` | Remove someone from a server. |
| ban | `/ban <username>` | Remove someone from a server and prevent them from rejoining. |
| leave | `/leave` | Leave the channel. |
| part | `/part`  | Leave the channel. |
| pinned | `/pinned` | Display pinned messages. |
| roles | `/roles` | Display server roles. |
| threads | `/threads` | Display active channel threads. |
| thread | `/thread <timestamp> <message>` | Sends message to thread. |
| react | `/react <timestamp> <emoji>` | Reacts to message at timestamp with emoji. |
| unreact | `/unreact <timestamp> <emoji>` | Removes the reaction emoji from the message at timestamp. |
| reply | `/reply <timestamp> <message>` | Replies to message at timestamp. |
| threadhistory | `/threadhistory <timestamp>` | Retrieves full history of thread. |
| thist | `/thist <timestamp>` | Alias of threadhistory. |
| grabhistory | `/grabhistory` | Retrieves full history of channel. Intended for rules channels and the like. Using this on old, highly active channels is not recommended. |
| hist | `/hist` | Alias of grabhistory. |

For commands that take a timestamp argument, the valid timestamp formats are
`YYYY-MM-DDthh:mm:ss`, `YYYY-MM-DDThh:mm:ss`, and `hh:mm:ss`. For example:

```
/reply 14:46:38 This is a reply to a message
/react 2022-02-02t14:46:38 :rwgrimNice:
/thread 2022-02-02T14:46:38 I am sending a message to a thread
```

Advanced Options
----------------
**Use status message as in-game info**: If enabled, the status message set via
Pidgin (the text under Available, Away, etc in the buddy list) will be
used as the game info for Discord "Playing ...".

**Auto-create rooms on buddy list**: If enabled, the plugin will add the
channels (rooms) from the servers you're on as chats on your buddy list.
This is preferred if you're using Pidgin, so you don't need to access
the room list manually (from the buddy list, Tools->Room List). If
you're not using Pidgin (or finch), you probably don't want this, since
they have different buddy list APIs.
Note: If the room list changes, it won't recreate the list unless you
delete the entire group.

**Number of users in a large channel**: Mention behaviour is "smart" in
here. If you're in a small channel, every time a message is sent, you'll
be notified and the channel will pop up. If you're in a large channel,
you'll only be notified if you're explicitly mentioned in the message.
This value is the threshold to define a large channel. By default, if
there are more than 80 (online) users in the channel, it will be
considered large.

<a name="img">**Display images in conversations**</a>: Automatically
downloads attached images and displays them in DMs and small channels.

**Display images in large servers**: Like above, but for large channels. Needs
[Display images in conversations](#img) to be turned on to work.

**Max displayed image width (0 disables)**: The maximum image width to download
when [Display images in conversations](#img) is turned on. Plugin will fetch a
smaller version of the image if it is too large.

**Display custom emoji as inline images**: Automatically downloads custom
emoji from the server and displays it in Pidgin as an inline image instead
of as a URL link.

**Approximate max number of users to keep track of, per server (0 disables)**: The
approximate maximum number of users to store presence information on per server,
to keep memory use down. Works best in multiples of 100. Minimum is 200.

**Fetch unread chat messages when account connects**: Experimental. Attempts to
open and populate server channels at start based on your mention settings.

**Indicate thread replies with this prefix**: Sets the prefix used to indicate a
thread reply. Thread replies will be formatted as `[user-set prefix][thread
timestamp]: [message]`.

**Indicate thread parent messages with this prefix**: As above, but for the
first/parent message of a thread.

Mentions
--------
To mention a user in a chat room, you can either use tab-completion at the
start of the message, or prefix their username with an @ eg,
`SeriousEion: i am mentioning @SeriousEion`

Bitlbee and spectrum2 users
---------------------------
Discord doesn't like you trying to connect from remote IP addresses so
you'll need to grab an auth token from your browsers local storage:

* Chrome: Developer Tools -> Application -> Local Storage -> https://discordapp.com -> token
* Firefox: Web Developer -> Storage Inspector -> Local Storage -> https://discordapp.com -> token

Bitlbee users can then set the token with `acc eionrobb-discord set token ......`.

spectrum2 users will need to edit the accounts.xml file to add the token. `<setting name='token' type='string'>...</setting>`

Alternatively, if you've compiled with QR Code auth support, leaving the
password field empty will show a QR Code that you can scan from the Discord
mobile app to login.

Show your appreciation
----------------------
Did this plugin make your life happier?  [Send me $1](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PZMBF2QVF69GA) to say thanks!
