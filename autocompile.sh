#!/bin/sh
sudo apt-get install gettext git libglib2.0-dev libjson-glib-dev libpurple-dev
git clone git://github.com/EionRobb/purple-discord.git
cd purple-discord
make
sudo make install
