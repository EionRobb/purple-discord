# purple-discord
A libpurple/Pidgin plugin for Discord

( For free/libre software that allows you to create/manage your account with Discord, check out [Harmony](https://github.com/nickolas360/harmony) )

Windows
-------
Windows nightly builds from [here](https://eion.robbmob.com/libdiscord.dll)

The plugin requires libjson-glib which can be downloaded [from github](https://github.com/EionRobb/skype4pidgin/raw/master/skypeweb/libjson-glib-1.0.dll) and copied to the Program Files\Pidgin folder (not the plugins subfolder)

Fedora
---------
On Fedora you can install [package](https://apps.fedoraproject.org/packages/purple-discord) from Fedora's main repository:
```bash
	sudo dnf install purple-discord pidgin-discord
```

CentOS/RHEL
---------
On CentOS/RHEL you can install [package](https://apps.fedoraproject.org/packages/purple-discord) from Fedora's [EPEL7](http://fedoraproject.org/wiki/EPEL) repository:

```bash
	sudo yum install purple-discord pidgin-discord
```

Compiling
---------
Requires devel headers/libs for libpurple and libjson-glib [libglib2.0-dev, libjson-glib-dev and libpurple-dev]
```bash
	git clone git://github.com/EionRobb/purple-discord.git
	cd purple-discord
	make
	sudo make install
```

Advanced Options
----------------
**Use status message as in-game info**: If enabled, the status message set via
Pidgin (the text under Available, Away, etc in the buddy list) will be
used as the game info for Discord "Playing ...".

**Auto-create rooms on buddy list**: If enabled, the plugin will add the
channels (rooms) from the servers you're on as chats on your buddy list.
This is preferred if you're using Pidgin, so you don't need to access
the room list manually. If you're not using Pidgin (or finch), you
probably don't want this, since they have different buddy list APIs.
Note: If the room list changes, it won't recreate the list unless you
delete the entire group.

**Number of users in a large channel**: Mention behaviour is "smart" in
here. If you're in a small channel, every time a message is sent, you'll
be notified and the channel will pop up. If you're in a large channel,
you'll only be notified if you're explicitly mentioned in the message.
This value is the threshold to define a large channel. By default, if
there are more than 80 (online) users in the channel, it will be
considered large.


Show your appreciation
----------------------
Did this plugin make your life happier?  [Send me $1](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PZMBF2QVF69GA) to say thanks!
