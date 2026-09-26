@echo off
setlocal
cd /d "%~dp0"
if not "%~1"=="" (
  set "CXX=%~1"
) else (
  set "CXX=g++"
)
echo Building NetWatch Pro...
"%CXX%" -std=c++11 -O2 -Wall -Wextra -pthread main.cpp -o NetWatchPro.exe -lws2_32
if errorlevel 1 (
  echo.
  echo Build failed. Supply the full g++.exe path from your Dev-C++ compiler.
  echo Example: build_windows.bat "C:\Dev-Cpp\MinGW64\bin\g++.exe"
  echo See README.md for Dev-C++ setup and thread support notes.
  pause
  exit /b 1
)
echo Build successful: NetWatchPro.exe
pause
