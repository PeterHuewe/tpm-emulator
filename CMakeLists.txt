# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 475 2011-12-20 18:21:19Z mast $

project(TPM_Emulator C)

cmake_minimum_required(VERSION 2.4)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)
if(COMMAND cmake_policy)
cmake_policy(SET CMP0003 NEW)
endif()

# enforce out of source build
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" IS_INSOURCE)
if(IS_INSOURCE)
    message(FATAL_ERROR "${PROJECT_NAME} requires an out of source build.")
endif()

# set project and build version
set(${PROJECT_NAME}_VERSION_MAJOR 0)
set(${PROJECT_NAME}_VERSION_MINOR 7)
string(REGEX REPLACE ".*Revision: ([0-9]+).*" "\\1" ${PROJECT_NAME}_VERSION_BUILD "$Revision: 475 $")

# create project configuration
if(WIN32)
STRING(REGEX REPLACE "\\\\" "/" PROGRAMFILES "$ENV{PROGRAMFILES}/${PROJECT_NAME}")
set(TPM_LOG_FILE "${PROGRAMFILES}/tpmd.log")
set(TPM_STORAGE_NAME "${PROGRAMFILES}/tpm_emulator-1_2_${${PROJECT_NAME}_VERSION_MAJOR}_${${PROJECT_NAME}_VERSION_MINOR}")
set(TPM_DEVICE_NAME "//./pipe/tpmd:0")
elseif(APPLE)
set(TPM_LOG_FILE "/private/var/log/tpmd.log")
set(TPM_SOCKET_NAME "/private/var/run/tpm/tpmd_socket:0")
set(TPM_STORAGE_NAME "/private/var/lib/tpm/tpm_emulator-1_2_${${PROJECT_NAME}_VERSION_MAJOR}_${${PROJECT_NAME}_VERSION_MINOR}")
set(TPM_DEVICE_NAME "/dev/tpm")
else()
set(TPM_LOG_FILE "/var/log/tpmd.log")
set(TPM_SOCKET_NAME "/var/run/tpm/tpmd_socket:0")
set(TPM_STORAGE_NAME "/var/lib/tpm/tpm_emulator-1_2_${${PROJECT_NAME}_VERSION_MAJOR}_${${PROJECT_NAME}_VERSION_MINOR}")
set(TPM_DEVICE_NAME "/dev/tpm")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
add_definitions(-Wall -Werror -Wno-unused-parameter -Wpointer-arith -Wcast-align -Wwrite-strings)
if("${CMAKE_SYSTEM}" MATCHES "Linux")
    add_definitions(-Wextra)
endif()
if(USE_OPENSSL)
    add_definitions(-DUSE_OPENSSL)
endif()
include_directories("/opt/local/include")
link_directories("/opt/local/lib")

# configure CPack
set(CPACK_PACKAGE_VERSION_MAJOR ${${PROJECT_NAME}_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${${PROJECT_NAME}_VERSION_MINOR})
set(CPACK_SOURCE_PACKAGE_FILE_NAME "tpm_emulator-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.4")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ".svn/" "/build/" "/.project" "/.cproject")
set(CPACK_GENERATOR "ZIP")
set(CPACK_SET_DESTDIR ON)
include(CPack)

# include root directories
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

# add internal libraries
add_subdirectory(tpm)
add_subdirectory(mtm)
add_subdirectory(crypto)

# add TDDL
add_subdirectory(tddl)

# add kernel modules
add_subdirectory(tpmd_dev)

# add executables
add_subdirectory(tpmd)

