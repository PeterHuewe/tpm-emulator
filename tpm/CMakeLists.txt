# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 364 2010-02-11 10:24:45Z mast $

file(GLOB tpm_SRCS "*.[h|c]")
add_library(tpm STATIC ${tpm_SRCS})

