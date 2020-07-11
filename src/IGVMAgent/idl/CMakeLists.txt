# Copyright (c) Microsoft Corporation. All rights reserved.
#

cmake_minimum_required (VERSION 3.8)

set(MIDL_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
set(MIDL_OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/IGVmAgentRpc.h
    ${CMAKE_CURRENT_BINARY_DIR}/IGVmAgentRpc_c.c
    ${CMAKE_CURRENT_BINARY_DIR}/IGVmAgentRpc_s.c
    )
set(MIDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/IGVmAgentRpc.idl)

add_custom_command(
    OUTPUT ${MIDL_OUTPUT}
    COMMAND midl  ${MIDL_FILE} -oldnames
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${MIDL_FILE}
    VERBATIM
    )

add_custom_target(agent_idl
    DEPENDS ${MIDL_OUTPUT}
    )

set_source_files_properties(
    ${MIDL_OUTPUT}
        PROPERTIES
            GENERATED TRUE
            )