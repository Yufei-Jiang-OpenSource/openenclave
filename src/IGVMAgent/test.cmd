@echo off

echo "Running IGVMAgent tests"
vsdevcmd.bat
pushd release
ctest
popd
echo "Done IGVMAgent tests"