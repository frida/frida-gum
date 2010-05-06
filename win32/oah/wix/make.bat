@echo off
set RELEASE_PATH=%~dp0\..\Win32\Release
"%OAH_INSTALLED_PATH%\bin\pkg-config" --modversion %RELEASE_PATH%\lib\pkgconfig\gum.pc > modver.tmp || goto error
set /P MODVER= < modver.tmp
del modver.tmp

nmake /nologo version=%MODVER% api_version=%MAJORMINOR% release_path=%RELEASE_PATH% %*

goto:eof
:error
del modver.tmp
echo Couldn't start build process... have you compiled gum.sln with OAH_BUILD_OUTPUT cleared!??
