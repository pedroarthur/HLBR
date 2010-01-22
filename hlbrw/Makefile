# Makefile for HLBRW
#
# by Eriberto
#
# Possible targets: install and uninstall

CONF_PATH	= $(DESTDIR)/etc
PROGRAM_PATH	= $(DESTDIR)/usr/bin
LOG_PATH	= $(DESTDIR)/var/log/hlbrw
MANPAGE_PATH	= $(DESTDIR)/usr/share/man/man1

all: hlbrw

hlbrw:
	#
	# --------------------------------------
	# Run "# make install" to install HLBRW.
	# --------------------------------------
	#

install:
	@echo Installing program...
	cp hlbrw $(PROGRAM_PATH)
	chmod 755 $(PROGRAM_PATH)/hlbrw
	cp hlbrw.1.man $(MANPAGE_PATH)/hlbrw.1
	cp hlbrw.conf $(CONF_PATH)
	mkdir -p $(LOG_PATH)
	#
	# ----------------------------------------------
	# HLBRW installed. You must configure the iwatch
	# program. Please see the README.
	# ----------------------------------------------
	#

uninstall:
	rm -f $(PROGRAM_PATH)/hlbrw
	rm -f $(MANPAGE_PATH)/hlbrw.1
	rm -f $(CONF_PATH)/hlbrw.conf
	#
	# ---------------------------------------
	# HLBRW uninstalled.
	# The /var/log/hlbrw/ directory was kept.
	# ---------------------------------------
	#
