
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc

PROTOC_C ?= protoc-c
PKG_CONFIG ?= pkg-config

DIR_PERM = 0755
LIB_PERM = 0755
FILE_PERM = 0644

# Note: Use "-C .git" to avoid ascending to parent dirs if .git not present
GIT_REVISION_ID = $(shell git -C .git rev-parse --short HEAD 2>/dev/null)
REVISION_ID = $(shell hg id -i 2>/dev/null)
REVISION_NUMBER = $(shell hg id -n 2>/dev/null)
ifneq ($(REVISION_ID),)
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d).git.r$(REVISION_NUMBER).$(REVISION_ID)
else ifneq ($(GIT_REVISION_ID),)
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d).git.$(GIT_REVISION_ID)
else
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d)
endif

CFLAGS ?= -O2 -g -pipe -Wall

CFLAGS += -std=c99 -DDISCORD_PLUGIN_VERSION='"$(PLUGIN_VERSION)"' -DMARKDOWN_PIDGIN

# Comment out to disable localisation
CFLAGS += -DENABLE_NLS

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  #only defined on 64-bit windows
  PROGFILES32 = ${ProgramFiles(x86)}
  ifndef PROGFILES32
    PROGFILES32 = $(PROGRAMFILES)
  endif
  DISCORD_TARGET = libdiscord.dll
  DISCORD_DEST = "$(PROGFILES32)/Pidgin/plugins"
  DISCORD_ICONS_DEST = "$(PROGFILES32)/Pidgin/pixmaps/pidgin/protocols"
  LOCALEDIR = "$(PROGFILES32)/Pidgin/locale"
  LOCALE_DEST = $(LOCALEDIR)
else
  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    CC ?= gcc
    LDFLAGS ?= -Wl,-z,relro
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      DISCORD_TARGET = FAILNOPURPLE
      DISCORD_DEST =
      DISCORD_ICONS_DEST =
      LOCALE_DEST =
    else
      DISCORD_TARGET = libdiscord.so
      DISCORD_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
      DISCORD_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
      LOCALEDIR = $(shell $(PKG_CONFIG) --variable=datadir purple)/locale
      LOCALE_DEST = $(DESTDIR)$(LOCALEDIR)
    endif
  else
    DISCORD_TARGET = libdiscord3.so
    DISCORD_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
    DISCORD_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
    LOCALEDIR = $(shell $(PKG_CONFIG) --variable=datadir purple-3)/locale
    LOCALE_DEST = $(DESTDIR)$(LOCALEDIR)
  endif
endif

WIN32_CFLAGS = -std=c99 -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -DENABLE_NLS -DDISCORD_PLUGIN_VERSION='"$(PLUGIN_VERSION)"' -DMARKDOWN_PIDGIN -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

CFLAGS += -DLOCALEDIR=\"$(LOCALEDIR)\"

C_FILES := markdown.c
PURPLE_COMPAT_FILES := purple2compat/*.c
PURPLE_C_FILES := libdiscord.c $(C_FILES)

.PHONY: all build install FAILNOPURPLE clean build-icons install-icons build-locales install-locales %-locale-install

LOCALES = $(patsubst %.po, %.mo, $(wildcard po/*.po))

all: $(DISCORD_TARGET)

build: all build-icons build-locales

libdiscord.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) $(CPPFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 zlib --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libdiscord3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) $(CPPFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 zlib --libs --cflags` $(INCLUDES)  -g -ggdb

libdiscord.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat
	
libfosscord.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -DFOSSCORD -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libdiscord3.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

po/purple-discord.pot: libdiscord.c
	xgettext $^ -k_ --no-location -o $@

po/%.po: po/purple-discord.pot
	msgmerge $@ po/purple-discord.pot > tmp-$*
	mv -f tmp-$* $@

po/%.mo: po/%.po
	msgfmt -o $@ $^

build-locales: $(LOCALES)

%-locale-install: po/%.mo
	mkdir -m $(DIR_PERM) -p $(LOCALE_DEST)/$(*F)/LC_MESSAGES
	install -m $(FILE_PERM) -p po/$(*F).mo $(LOCALE_DEST)/$(*F)/LC_MESSAGES/purple-discord.mo

install: $(DISCORD_TARGET) install-icons install-locales
	mkdir -m $(DIR_PERM) -p $(DISCORD_DEST)
	install -m $(LIB_PERM) -p $(DISCORD_TARGET) $(DISCORD_DEST)

discord16.png: discord-alt-logo.svg
	convert -strip -background none discord-alt-logo.svg -resize 16x16 discord16.png

discord22.png: discord-alt-logo.svg
	convert -strip -background none discord-alt-logo.svg -resize 22x22 discord22.png

discord48.png: discord-alt-logo.svg
	convert -strip -background none discord-alt-logo.svg -resize 48x48 discord48.png

build-icons: discord16.png discord22.png discord48.png

install-icons: build-icons
	mkdir -m $(DIR_PERM) -p $(DISCORD_ICONS_DEST)/16
	mkdir -m $(DIR_PERM) -p $(DISCORD_ICONS_DEST)/22
	mkdir -m $(DIR_PERM) -p $(DISCORD_ICONS_DEST)/48
	install -m $(FILE_PERM) -p discord16.png $(DISCORD_ICONS_DEST)/16/discord.png
	install -m $(FILE_PERM) -p discord22.png $(DISCORD_ICONS_DEST)/22/discord.png
	install -m $(FILE_PERM) -p discord48.png $(DISCORD_ICONS_DEST)/48/discord.png

install-locales: build-locales $(patsubst po/%.po, %-locale-install, $(wildcard po/*.po))

FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(DISCORD_TARGET)
	rm -f discord*.png
	rm -f po/*.mo

gdb:
	gdb --args pidgin -c ~/.fake_purple -n -m

