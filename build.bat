@echo off

set BUILD_DIR=build
set PATH=C:\MinGW\bin;C:\Program Files\CMake 2.8\bin;C:\Program Files (x86)\CMake 2.8\bin;%PATH%

if "%1" == "clean" rmdir "%BUILD_DIR%" /S /Q

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cd %BUILD_DIR%
cmake .. -G "MinGW Makefiles"
::cmake .. -G "MinGW Makefiles" -DMTM_EMULATOR=ON
mingw32-make
cd ..

