@REM Licensed under the MIT license. See LICENSE file in the project root for full license information.

@setlocal EnableExtensions EnableDelayedExpansion
@echo off

set current-path=%~dp0
rem // remove trailing slash
set current-path=%current-path:~0,-1%

set repo_root=%current-path%\..

rem // resolve to fully qualified path
for %%i in ("%repo_root%") do set repo_root=%%~fi

set build_dir=%repo_root%\cmake\build

if NOT EXIST %build_dir% GOTO NO_CMAKE_DIR
rmdir /s/q %build_dir%
:NO_CMAKE_DIR

rem Go into the cmake directory
mkdir %build_dir%
pushd %build_dir%

rem cmake %repo_root% -G "Visual Studio 14 Win64" -Dpatchcords_ut:BOOL=ON -Denable_tls_lib:BOOL=ON
cmake %repo_root% -Dpatchcords_ut:BOOL=ON -Denable_tls_lib:BOOL=ON
if not !ERRORLEVEL!==0 exit /b !ERRORLEVEL!

echo "Building project"
msbuild /m patchcords.sln /p:Configuration=Debug
if not !ERRORLEVEL!==0 exit /b !ERRORLEVEL!

ctest -C "debug" -V

popd

goto :eof
