# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required (VERSION 3.8)

find_package(Microsoft.WIL CONFIG)
find_package(Microsoft.GSL CONFIG)
find_package(cpprestsdk CONFIG REQUIRED)

add_executable(test_aad_client
	host.cpp
	${AGENT_DIR}/clients/aad_client.cpp
	)

target_include_directories(test_aad_client PRIVATE
	${AGENT_DIR}/include
	${TESTS_DIR}/include
	)

target_link_libraries(test_aad_client PRIVATE
	Microsoft.GSL::GSL
	bcrypt.lib
	Winhttp.lib
	cpprestsdk::cpprest 
	cpprestsdk::cpprestsdk_zlib_internal 
	cpprestsdk::cpprestsdk_brotli_internal
	)

add_test(NAME test_aad_client COMMAND $<TARGET_FILE:test_aad_client>)
