# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 455 2010-09-17 18:34:04Z mast $

set(tddl-tpm-emulator_SRCS "tddl.c" "tddl-tpm-emulator.h")
add_library(tddl-tpm-emulator SHARED ${tddl-tpm-emulator_SRCS})
add_library(tddl-tpm-emulator_static STATIC ${tddl-tpm-emulator_SRCS})
if(UNIX)
  set_target_properties(tddl-tpm-emulator PROPERTIES SOVERSION "1.2"
    VERSION "1.2.${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}")
  set_target_properties(tddl-tpm-emulator_static PROPERTIES OUTPUT_NAME tddl-tpm-emulator)
elseif(WIN32)
  set_target_properties(tddl-tpm-emulator PROPERTIES OUTPUT_NAME ifxtpm)
  set_target_properties(tddl-tpm-emulator PROPERTIES PREFIX "")
endif()

install(TARGETS tddl-tpm-emulator DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS tddl-tpm-emulator_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES "tddl-tpm-emulator.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_tddl test_tddl.c)
target_link_libraries(test_tddl tddl-tpm-emulator_static)

