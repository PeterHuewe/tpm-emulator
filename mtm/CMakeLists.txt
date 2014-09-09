# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 376 2010-02-16 14:51:42Z mast $

add_definitions(-DMTM_EMULATOR)
file(GLOB tpm_SRCS ../tpm/tpm_cmd_handler.c ../tpm/tpm_data.c)
file(GLOB mtm_SRCS "*.[h|c]")
add_library(mtm STATIC ${mtm_SRCS} ${tpm_SRCS})

