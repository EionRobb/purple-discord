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

Show your appreciation
----------------------
Did this plugin make your life happier?  [Send me $1](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PZMBF2QVF69GA) to say thanks!
