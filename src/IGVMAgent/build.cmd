@echo off

pushd "%~dp0"
cmake_build.cmd Debug
cmake_build.cmd Release
popd
