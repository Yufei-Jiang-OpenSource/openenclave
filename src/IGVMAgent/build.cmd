echo "Building IGVMAgent dependencies. %~dp0..\src"
vsdevcmd.bat
rmdir /s /q release
mkdir release
pushd release
cmake .. -GNinja -DCMAKE_TOOLCHAIN_FILE=%~dp0..\src\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
ninja
popd

echo "Successfully built IGVMAgent"