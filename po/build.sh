#!/bin/sh
xgettext ../libdiscord.c -k_ -o purple-discord.pot
msgmerge es.po purple-discord.pot > es.po
