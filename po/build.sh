#!/bin/sh
xgettext ../libdiscord.c -k_ --no-location -o purple-discord.pot
msgmerge es.po purple-discord.pot > tmp && mv tmp es.po
