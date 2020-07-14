@echo off

echo "Running IGVMAgent tests"
pushd release
ctest
popd
echo "Done IGVMAgent tests"