@echo off

echo "Setting up VS dev cmd (x64). %~dp0"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

echo "Install IGVMAgent dependencies"
pushd "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -file "%~dp0restore.ps1" || exit \b 1
popd
echo "Successfully installed IGVMAgent dependencies"