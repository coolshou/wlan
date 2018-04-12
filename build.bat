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
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars32.bat"
MSBuild wlan.sln /t:Rebuild /p:Configuration=Release;Platform=Win32
mt -manifest "wlan.exe.manifest"  -outputresource:"Win32\Release\wlan.exe;#1"

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat"
MSBuild wlan.sln /t:Rebuild /p:Configuration=Release;Platform=x64
mt -manifest "wlan.exe.manifest"  -outputresource:"x64\Release\wlan.exe;#1"

exit /b

:Clean
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars32.bat"
MSBuild wlan.sln /t:clean /p:Configuration=Release;Platform=Win32

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat"
MSBuild wlan.sln /t:clean /p:Configuration=Release;Platform=x64

exit /b
