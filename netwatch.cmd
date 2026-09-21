@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  netwatch 启动器
rem   无参数 = watch 模式（免管理员，实时观察）
rem   admin  = deep 模式（需管理员：抓包取真实域名与上传字节数）
rem ============================================================

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"

if /i "%~1"=="admin" (
  net session >nul 2>&1
  if errorlevel 1 (
    echo   正在请求管理员权限...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'admin run' -Verb RunAs"
    exit /b
  )
  echo   deep 模式：抓包 120 秒（期间请在目标应用里制造流量）...
  %PYEXE% -u netwatch.py deep --seconds 120
  pause
  exit /b
)

%PYEXE% -u netwatch.py watch
pause
