# Clone repository
```
git clone --recurse-submodules https://sewong.visualstudio.com/DefaultCollection/IGVMAgent/_git/IGVMAgent
```

# Install Dependencies
- Microsoft Visual Studio 2019.
- Windows SDK (10.0.19041.0): https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/

Open a x64 Native Tools command prompt in elevated mode.

## Install VCPKG
Learn more about vcpkg at its [github repo](https://github.com/Microsoft/vcpkg).
```
cd vcpkg
./bootstrap-vcpkg.bat
vcpkg integrate install
```

## Install Other dependencies
```
vcpkg install wil:x64-windows
vcpkg install ms-gsl:x64-windows
vcpkg install cpprestsdk:x64-windows
```

# Build
## Building using Visual Studio 2019
- Open Visual Studio 2019, Build -> BuildAll

## Building using CMAKE
```
	cmake .. -GNinja -DCMAKE_TOOLCHAIN_FILE=<Repo location>\vcpkg\scripts\buildsystems\vcpkg.cmake
```

# Build Types
By default cmake uses Debug build type for single-configuration generators (e.g., Makefiles generator and Ninja generator). To change the build type for single-configuration generators, you need to set the build type flag CMAKE_BUILD_TYPE. Visual Studio generator is a multi-configuration generator. You don't need to set a build type flag if you are building with Visual Studio (you can change the build type later after you open a Visual Studio solution).

## Building with Debug type
Add flag -DCMAKE_BUILD_TYPE=Debug
```
	cmake .. -GNinja -DCMAKE_TOOLCHAIN_FILE=<Repo location>\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Debug
```

## Building with Release type
Add flag -DCMAKE_BUILD_TYPE=Release
```
	cmake .. -GNinja -DCMAKE_TOOLCHAIN_FILE=<Repo location>\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
```