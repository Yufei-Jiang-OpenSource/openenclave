# Copyright (c) Microsoft Corporation. All rights reserved.
#

cmake_minimum_required (VERSION 3.8)

project ("IGVMAgent")

option(BUILD_TESTS "Build tests" ON)
include(CTest)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set (ROOT_DIR ${CMAKE_SOURCE_DIR})
set (AGENT_DIR ${ROOT_DIR}/agent)

add_compile_options("/std:c++17")
add_compile_definitions(
	CMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
	_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
)
add_subdirectory(idl)
add_subdirectory(agent)

if(BUILD_TESTS)
    enable_testing()
endif()

# TODO: Add tests and install targets if needed.
