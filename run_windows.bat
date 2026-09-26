@echo off
cd /d "%~dp0"
if not exist NetWatchPro.exe (
  echo Build first using build_windows.bat or the Dev-C++ project.
  pause
  exit /b 1
)
NetWatchPro.exe
pause
