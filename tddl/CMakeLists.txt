# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: CMakeLists.txt 455 2010-09-17 18:34:04Z mast $

set(tddl_SRCS "tddl.c" "tddl.h")
add_library(tddl SHARED ${tddl_SRCS})
add_library(tddl_static STATIC ${tddl_SRCS})
if(UNIX)
  set_target_properties(tddl PROPERTIES SOVERSION "1.2"
    VERSION "1.2.${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}")
  set_target_properties(tddl_static PROPERTIES OUTPUT_NAME tddl)
elseif(WIN32)
  set_target_properties(tddl PROPERTIES OUTPUT_NAME ifxtpm)
  set_target_properties(tddl PROPERTIES PREFIX "")
endif()

install(TARGETS tddl DESTINATION lib)
install(TARGETS tddl_static DESTINATION lib)
install(FILES "tddl.h" DESTINATION include)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_tddl test_tddl.c)
target_link_libraries(test_tddl tddl_static)

