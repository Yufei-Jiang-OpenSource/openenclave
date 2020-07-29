# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required (VERSION 3.8)

find_package(Microsoft.WIL CONFIG)
find_package(Microsoft.GSL CONFIG)
find_package(cpprestsdk CONFIG REQUIRED)

add_executable(rpc_client
	rpc_client.cpp
	IGVmAgent_c_stub.c
	)

target_include_directories(rpc_client PRIVATE
    ${AGENT_DIR}
	${AGENT_DIR}/include
    ${TESTS_DIR}/include
    ${MIDL_OUTPUT_DIR}
	)
    
target_link_libraries(rpc_client PRIVATE
    Microsoft.GSL::GSL
    rpcrt4.lib
    bcrypt.lib
    Winhttp.lib
    cpprestsdk::cpprest 
    cpprestsdk::cpprestsdk_zlib_internal 
    cpprestsdk::cpprestsdk_brotli_internal
    )

add_dependencies(rpc_client
    agent_idl
    )

add_custom_command(
	TARGET rpc_client POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/data ${CMAKE_BINARY_DIR}/agent/tests/rpc_client/data
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/script ${CMAKE_BINARY_DIR}/agent/tests/rpc_client/script
    )

# file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}" WIN_CMAKE_BINARY_DIR)
# add_test(NAME test_rpc_client COMMAND cmd /C ${WIN_CMAKE_BINARY_DIR}\\agent\\tests\\rpc_client\\script\\run_rpc_client_test.cmd ${WIN_CMAKE_BINARY_DIR}\\agent ${WIN_CMAKE_BINARY_DIR}\\agent\\tests\\rpc_client)

# file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}" WIN_CMAKE_BINARY_DIR)
# add_test(NAME test_rpc_client COMMAND cmd "/C D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent\\tests\\rpc_client\\script\\run_rpc_client_test.cmd D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent\\tests\\rpc_client")

add_test(NAME test_rpc_client COMMAND ${CMAKE_COMMAND}
    -DSERVERBINPATH=${CMAKE_BINARY_DIR}/agent
    -DCLIENTBINPATH=${CMAKE_BINARY_DIR}/agent/tests/rpc_client
    -P ${CMAKE_CURRENT_SOURCE_DIR}/runtests.cmake)