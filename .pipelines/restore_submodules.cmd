REM go to src directory

pushd "%~dp0../src"

echo "Restoring vcpkg submodule"

set repoUrl=https://msazure.visualstudio.com/DefaultCollection/One/_git/ACC-CVM-IgvmAgent
set outputDir=vcpkg

echo "Verify repo URL: %repoUrl%"

echo "Attempting to git clone"
git clone --progress --verbose --recursive %repoUrl% %outputDir%