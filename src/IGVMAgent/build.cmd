echo "Building IGVMAgent dependencies"
rmdir /s /q release
mkdir release
pushd release
cmake .. -GNinja -DCMAKE_TOOLCHAIN_FILE=%CD%\..\..\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
ninja
popd

echo "Successfully built IGVMAgent"