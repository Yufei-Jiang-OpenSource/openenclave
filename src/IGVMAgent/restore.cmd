@echo off

echo "Install IGVMAgent dependencies"
 vsdevcmd.bat
powershell -file "%~dp0restore.ps1" || exit \b 1

echo "Successfully installed IGVMAgent dependencies"