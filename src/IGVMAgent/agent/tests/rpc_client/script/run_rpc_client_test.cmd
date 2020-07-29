@echo Off

echo "Entering directory: %~dp0"
pushd "%~dp0"

pushd %1
start IGVMAgent.exe
popd

wmic process get processid,parentprocessid,executablepath | find "IGVMAgent.exe"

pushd %2
call rpc_client.exe
popd

taskkill /IM IGVMAgent.exe /F

popd