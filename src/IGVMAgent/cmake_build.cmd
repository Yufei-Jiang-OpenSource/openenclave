@echo off


pushd "%~dp0"
echo "Building target %1"

echo "Creating directory: %~dp0%1"
mkdir %1

pushd %1
echo "Setting up VS dev cmd (x64)."
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

echo "Creating makefiles ..."
cmake .. -G "Ninja" -DCMAKE_INSTALL_PREFIX=C:\IGVMAgent -DCMAKE_TOOLCHAIN_FILE=%~dp0..\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=%1 || exit \b 1

echo "Starting build for target %1 ..."
ninja || exit \b 1

popd
popd

echo "Successfully built IGVMAgent target: %1"
