:: Software-based Trusted Platform Module (TPM) Emulator
:: Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
::
:: $Id: CMakeLists.txt 390 2010-02-18 10:04:12Z mast $

@echo off

set SERVICE_ID=tpmd
set SERVICE_NAME=TPM Emulator
set SERVICE_DIR=%~dp0
set SERVICE_EXE=%SERVICE_DIR%\tpmd.exe

if /i "%1" == ""        goto usage
if /i "%1" == "install" goto install
if /i "%1" == "remove"  goto remove
if /i "%1" == "start"   goto start
if /i "%1" == "stop"    goto stop
if /i "%1" == "status"  goto status
goto usage

:usage
echo Usage: %0 (install, remove, start, stop, status)
goto :eof

:install
if not exist "%SERVICE_EXE%" goto missing
sc create %SERVICE_ID% binpath= "%SERVICE_EXE% \"%SERVICE_CONF%\"" DisplayName= "%SERVICE_NAME%" start= demand
goto :eof
:missing
echo "Error: file '%SERVICE_EXE%' does not exists."
goto :eof

:remove
sc delete %SERVICE_ID%
goto :eof

:start
sc start %SERVICE_ID%
goto :eof

:stop
sc stop %SERVICE_ID%
goto :eof

:status
sc query %SERVICE_ID%
goto :eof

