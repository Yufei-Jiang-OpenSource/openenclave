@echo off

echo "Install IGVMAgent dependencies"
powershell -file "%~dp0restore.ps1" || exit \b 1

echo "Successfully installed IGVMAgent dependencies"