# Makefile for HLBRW
#
# by Eriberto
#
# Possible targets: install and uninstall

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
	rm -rf $(LOG_PATH)
	#
	# ------------------
	# HLBRW uninstalled.
	# ------------------
	#
