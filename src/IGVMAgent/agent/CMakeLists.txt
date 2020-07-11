# Copyright (c) Microsoft Corporation. All rights reserved.
#

cmake_minimum_required (VERSION 3.8)

add_compile_definitions(
    CMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
)

find_package(Microsoft.GSL CONFIG)
find_package(cpprestsdk CONFIG REQUIRED)

# Add source to this project's executable.
add_executable (IGVMAgent
    "IGVMAgent.cpp"
    "IGVmAgent_s_stub.c"
    "Rpc.cpp"
    "Main.cpp"
    "clients/aad_client.cpp"
    "clients/maa_client.cpp"
    "clients/ccf_skr_client.cpp"
    "clients/akv_skr_client.cpp")

target_include_directories(IGVMAgent PRIVATE
    .
    include
    ${MIDL_OUTPUT_DIR}
    )

target_link_libraries(IGVMAgent PRIVATE
    Microsoft.GSL::GSL
    rpcrt4.lib
    bcrypt.lib
    Winhttp.lib
    cpprestsdk::cpprest 
    cpprestsdk::cpprestsdk_zlib_internal 
    cpprestsdk::cpprestsdk_brotli_internal
    )

add_dependencies(IGVMAgent
    agent_idl
    )

if(BUILD_TESTS)
	add_subdirectory(tests)
endif()