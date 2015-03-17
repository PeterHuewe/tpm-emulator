# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 453 2010-09-11 11:00:58Z mast $

# select matching module sources
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")

set(tpmd_dev_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/linux")
set(tpmd_dev_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/linux")
set(tpmd_dev_OBJ "${tpmd_dev_BINARY_DIR}/tpmd_dev.ko")
if(CMAKE_COMPILER_IS_GNUCC)
  set(tpmd_dev_BUILD_CMD make -C ${tpmd_dev_BINARY_DIR} CC=${CMAKE_C_COMPILER} LD=${CMAKE_LINKER})
  set(tpmd_dev_INSTALL_CMD make -C ${tpmd_dev_BINARY_DIR} CC=${CMAKE_C_COMPILER} LD=${CMAKE_LINKER} install)
else()
  set(tpmd_dev_BUILD_CMD make -C ${tpmd_dev_BINARY_DIR})
  set(tpmd_dev_INSTALL_CMD make -C ${tpmd_dev_BINARY_DIR} install)
endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")

set(tpmd_dev_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/openbsd")
set(tpmd_dev_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/openbsd")
set(tpmd_dev_OBJ "${tpmd_dev_BINARY_DIR}/tpmd_dev.o")
set(tpmd_dev_BUILD_CMD gmake -C ${tpmd_dev_BINARY_DIR})
set(tpmd_dev_INSTALL_CMD gmake -C ${tpmd_dev_BINARY_DIR} install)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

set(tpmd_dev_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/darwin")
set(tpmd_dev_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/darwin")
set(tpmd_dev_OBJ "${tpmd_dev_BINARY_DIR}/build/Release/tpm_bridge.kext")
set(tpmd_dev_BUILD_CMD make -C ${tpmd_dev_BINARY_DIR})
set(tpmd_dev_INSTALL_CMD make -C ${tpmd_dev_BINARY_DIR} install)

endif()

# compile module
if(tpmd_dev_OBJ)

file(GLOB tpmd_dev_SRCS "${tpmd_dev_SOURCE_DIR}/*")

add_custom_command(OUTPUT ${tpmd_dev_OBJ}
                   COMMAND cp -rf ${tpmd_dev_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
                   COMMAND cp ${CMAKE_BINARY_DIR}/config.h ${tpmd_dev_BINARY_DIR}
                   COMMAND ${tpmd_dev_BUILD_CMD}
                   DEPENDS ${tpmd_dev_SRCS})

add_custom_target(tpmd_dev ALL DEPENDS ${tpmd_dev_OBJ})

install(CODE "EXECUTE_PROCESS(COMMAND ${tpmd_dev_INSTALL_CMD})")

endif()

