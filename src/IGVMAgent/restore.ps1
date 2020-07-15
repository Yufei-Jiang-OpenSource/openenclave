pushd "..\vcpkg"
./bootstrap-vcpkg.bat
./vcpkg.exe integrate install
popd

../vcpkg/vcpkg.exe install @vcpkg-windows.txt
