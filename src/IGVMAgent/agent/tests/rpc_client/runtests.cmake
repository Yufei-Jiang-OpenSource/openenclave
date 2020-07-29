# execute_process(COMMAND cmd /c IGVMAgent.exe
#     WORKING_DIRECTORY ${SERVERBINPATH}
#     OUTPUT_VARIABLE igvmagentoutput
#     ERROR_FILE error.err
# )
# message("rpcserver started")

# execute_process(COMMAND start /B IGVMAgent.exe
#     WORKING_DIRECTORY ${SERVERBINPATH}
#     OUTPUT_VARIABLE igvmagentoutput
#     ERROR_FILE error.err
# )
# message("rpcserver started")

# execute_process(COMMAND start /B "" "IGVMAgent.exe"
#                 COMMAND cmd /C timeout.exe /T 20
#     WORKING_DIRECTORY ${SERVERBINPATH}
#     OUTPUT_VARIABLE igvmagentoutput
#     ERROR_FILE error.err
# )
# message("rpcserver started")

# execute_process(COMMAND cmd "/C D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent\\tests\\rpc_client\\script\\run_rpc_client_test.cmd D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent D:\\repos\\ACC-CVM-IgvmAgent\\src\\IGVMAgent\\build\\agent\\tests\\rpc_client"
#     WORKING_DIRECTORY ${SERVERBINPATH}
#     OUTPUT_VARIABLE igvmagentoutput
#     ERROR_FILE error.err
# )
# message("rpcserver started")

file(TO_NATIVE_PATH "${SERVERBINPATH}" WIN_SERVERBINPATH)
execute_process(COMMAND cmd /C ${WIN_SERVERBINPATH}\\tests\\rpc_client\\script\\run_rpc_client_test.cmd ${WIN_SERVERBINPATH} ${WIN_SERVERBINPATH}\\tests\\rpc_client
    WORKING_DIRECTORY ${SERVERBINPATH}
    OUTPUT_VARIABLE igvmagentoutput
    ERROR_FILE error.err
)
message("rpcserver started")

# execute_process(COMMAND wmic process get processid,parentprocessid,executablepath | find "IGVMAgent.exe"
#     OUTPUT_VARIABLE output
# )
# message("'${output}'")

# execute_process(COMMAND taskkill /IM IGVMAgent.exe /F
#     WORKING_DIRECTORY ${SERVERBINPATH}
# )
# message("rpcserver killed")

