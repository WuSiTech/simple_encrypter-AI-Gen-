@echo off
REM ===========================================================================
REM  WuSi_Encrypter - MinGW-w64 (g++ 8.1.0) build script
REM  Fully STATIC linking:
REM    -static          link every library statically (incl. libwinpthread)
REM    -static-libgcc   embed libgcc (no libgcc_s_seh-1.dll)
REM    -static-libstdc++ embed libstdc++ (no libstdc++-6.dll)
REM  Result: the .exe only imports Windows system DLLs.
REM ===========================================================================
setlocal
cd /d "%~dp0"

echo [1/2] Compiling resource...
windres.exe resource.rc -O coff -o resource.o
if errorlevel 1 goto :fail

echo [2/2] Linking statically...
g++.exe -std=c++17 -O2 -s -municode -mwindows ^
    -static -static-libgcc -static-libstdc++ ^
    -o WuSi_Encrypter.exe main.cpp resource.o ^
    -lcomctl32 -lshell32 -lole32 -luuid -lgdi32
if errorlevel 1 goto :fail

echo.
echo Build OK -^> WuSi_Encrypter.exe  (static, no MinGW runtime DLLs required)
exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
