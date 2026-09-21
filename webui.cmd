@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  Potato Mine 网页控制台启动器
rem  自提权（布雷 / 运行地雷需要管理员）-> 启动 webui.py
rem  可选参数透传： --port 9000 --open --verbose
rem ============================================================

net session >nul 2>&1
if errorlevel 1 (
  echo   正在请求管理员权限...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"

echo   控制台地址 http://127.0.0.1:8756  （Ctrl+C 结束，结束时自动排雷）
echo.
%PYEXE% -u webui.py %*
pause
