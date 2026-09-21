@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  Potato Mine（土豆地雷）布雷启动器
rem  自提权 -> 布雷(auditpol+SACL) -> 后台隐藏运行地雷
rem  可选参数 --dry-run / --strict-orphans 会透传给地雷
rem ============================================================

net session >nul 2>&1
if errorlevel 1 (
  echo   正在请求管理员权限...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"

echo   [1/2] 布雷（auditpol + SACL）...
%PYEXE% potato_mine.py --arm || (echo 布雷失败 & pause & exit /b 1)

echo   [2/2] 启动地雷进程（后台，日志 potato-mine.log）...
powershell -NoProfile -Command ^
  "Start-Process -FilePath '%PYEXE%' -ArgumentList '-u','potato_mine.py','--run','%*' " ^
  "-WindowStyle Hidden -RedirectStandardOutput 'potato-mine-console.log' " ^
  "-RedirectStandardError 'potato-mine-console.err.log'"

echo.
echo   土豆地雷已布雷并进入后台运行。
echo   查看状态 : python potato_mine.py --status
echo   停止     : python potato_mine.py --stop   （SACL 仍在）
echo   排雷     : python potato_mine.py --disarm
pause
