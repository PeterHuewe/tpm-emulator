# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: Makefile 423 2010-02-22 16:32:22Z mast $

KEXT_NAME = tpm_bridge.kext
KEXT_BIN  = build/Release/$(KEXT_NAME)
KEXT_DIR  = $(DESTDIR)/System/Library/Extensions

all:
	@xcodebuild > /dev/null

clean:
	@xcodebuild clean > /dev/null

TPM_OWNER ?= root
TPM_GROUP ?= wheel

install: $(KEXT_BIN)
	@mkdir -p $(KEXT_DIR)
	@cp -Rp $(KEXT_BIN) $(KEXT_DIR)
	@chown -R $(TPM_OWNER):$(TPM_GROUP) $(KEXT_DIR)/$(KEXT_NAME)

.PHONY: all clean install
