@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem 停止运行中的 Potato Mine 并排雷（移除 SACL、还原 auditpol）
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"
%PYEXE% potato_mine.py --stop
%PYEXE% potato_mine.py --disarm
pause
