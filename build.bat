@echo OFF

set BAT=%0
set sCMD=%1

echo cmd %sCMD%
if "%sCMD%" NEQ "" (
  if "%sCMD%" NEQ "build" (
    call :Clean
  ) else (
    call :Build
  )
) else (
  call :Help
)
exit /b

:Help
echo =====%BAT% usage===============
echo  %BAT% build : build x86/x64 
echo  %BAT%  : clean build
echo ===================================
exit /b

:Build
set LIB=""
set LIBPATH=""
set INCLUDE=""
set Path="%SystemRoot%\System32\"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars32.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86
MSBuild wlan.sln /m /t:Rebuild /p:Configuration=Release;Platform=Win32
mt -manifest "wlan.exe.manifest"  -outputresource:"Win32\Release\wlan.exe;#1"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
MSBuild wlan.sln /m /t:Rebuild /p:Configuration=Release;Platform=x64
mt -manifest "wlan.exe.manifest"  -outputresource:"x64\Release\wlan.exe;#1"

exit /b

:Clean
set LIB=""
set LIBPATH=""
set INCLUDE=""
set Path="%SystemRoot%\System32\"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars32.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86
MSBuild wlan.sln /m /t:clean /p:Configuration=Release;Platform=Win32

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
REM call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
MSBuild wlan.sln /m /t:clean /p:Configuration=Release;Platform=x64

exit /b
