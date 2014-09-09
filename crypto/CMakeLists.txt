# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 464 2011-07-09 14:57:41Z mast $

file(GLOB tpm_crypto_SRCS "*.[h|c]")
file(GLOB bn_SRCS "bn_*.c")
list(REMOVE_ITEM tpm_crypto_SRCS ${bn_SRCS})

if(USE_OPENSSL)
list(APPEND tpm_crypto_SRCS "bn_openssl.c")
add_library(tpm_crypto STATIC ${tpm_crypto_SRCS})
target_link_libraries(tpm_crypto crypto)
else()
list(APPEND tpm_crypto_SRCS "bn_gmp.c")
add_library(tpm_crypto STATIC ${tpm_crypto_SRCS})
target_link_libraries(tpm_crypto gmp)
endif()

