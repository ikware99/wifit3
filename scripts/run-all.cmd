@echo off
setlocal
cd /d "%~dp0.."
set PY=.venv\Scripts\python.exe
if not exist "%PY%" (
    echo [错误] 找不到 %PY%
    echo 请先在仓库根目录准备虚拟环境（uv sync 或 python -m venv .venv）。
    pause
    exit /b 2
)
echo 正在执行一键测试，日志写入 logs\ 目录...
"%PY%" scripts\one_click_test.py %*
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
    echo === 全部通过 ===
) else (
    echo === 存在失败阶段，退出码 %RC%，详见 logs\ 下的日志 ===
)
pause
exit /b %RC%
