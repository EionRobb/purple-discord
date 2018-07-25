#!/bin/sh
sudo apt-get install gettext
sudo apt-get install git
git clone git://github.com/EionRobb/purple-discord.git
cd purple-discord
make
sudo make install
