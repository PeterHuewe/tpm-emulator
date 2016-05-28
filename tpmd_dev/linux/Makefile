# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: Makefile 364 2010-02-11 10:24:45Z mast $

# kernel settingsRCH settings
ARCH		?= $(shell uname -m)

KERNEL_RELEASE := $(shell uname -r)
KERNEL_BUILD   ?= /lib/modules/$(KERNEL_RELEASE)/build
MOD_SUBDIR     := misc

# module settings
MODULE_NAME    := tpmd_dev
obj-m          := $(MODULE_NAME).o

# do not print "Entering directory ..."
MAKEFLAGS      += --no-print-directory
EXTRA_CFLAGS   += -Wall -Werror

all:
	@$(MAKE) LD=$(LD) CC=$(CC) ARCH=$(ARCH) -C $(KERNEL_BUILD) M=$(CURDIR) modules

clean:
	@$(MAKE) LD=$(LD) CC=$(CC) ARCH=$(ARCH) -C $(KERNEL_BUILD) M=$(CURDIR) clean
	@rm -f Modules.symvers tpmd_dev.rules

TPM_GROUP ?= tss
INSTALL ?= install

tpmd_dev.rules: tpmd_dev.rules.in
	@sed -e "s/\$$TPM_GROUP/$(TPM_GROUP)/g" tpmd_dev.rules.in > tpmd_dev.rules

install: tpmd_dev.rules
	@$(MAKE) LD=$(LD) CC=$(CC) ARCH=$(ARCH) -C $(KERNEL_BUILD) M=$(CURDIR) INSTALL_MOD_PATH=$(DESTDIR) modules_install
	@$(INSTALL) -m 644 -D tpmd_dev.rules $(DESTDIR)/etc/udev/rules.d/80-tpmd_dev.rules

.PHONY: all clean install

