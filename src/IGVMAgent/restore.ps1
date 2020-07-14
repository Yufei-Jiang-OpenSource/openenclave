pushd "%~dp0..src/vcpkg"
./bootstrap-vcpkg.bat
./vcpkg.exe integrate install
popd
%~dp0..src/vcpkg/vcpkg.exe install @vcpkg-windows.txt