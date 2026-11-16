@echo off
setlocal
cd /d "%~dp0.."
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "VENV=%ROOT%\.venv"

echo ============================================================
echo  运行环境
echo ============================================================
echo   仓库根目录 : %ROOT%
echo   Python     : %PY%
echo   虚拟环境   : %VENV%

if not exist "%PY%" (
    echo   版本       : 未找到解释器
    echo   wifit3     : 无法确认（解释器缺失）
    echo.
    echo [错误] 找不到 %PY%
    echo 请先在仓库根目录准备虚拟环境（uv sync 或 python -m venv .venv）。
    pause
    exit /b 2
)

rem 版本号是纯 ASCII，可以走临时文件再 set /p 读回，和标签拼成一行。
"%PY%" -V > "%TEMP%\wifit3_run_ver.txt" 2>&1
set /p PYVER=<"%TEMP%\wifit3_run_ver.txt"
del "%TEMP%\wifit3_run_ver.txt" >nul 2>&1
echo   版本       : %PYVER%

rem 包路径含中文，不能走临时文件：Python 重定向时写 UTF-8，而 echo 按控制台代码页
rem 输出，中文会变成锟斤拷。让 Python 直接打到控制台（WriteConsoleW）才安全。
"%PY%" -c "import os,wifit3; print('   wifit3     : '+os.path.dirname(wifit3.__file__))" 2>nul
if errorlevel 1 echo   wifit3     : 导入失败，环境可能未就绪

rem PYTHONPATH 会抢先于 .venv 里的 src，是最容易被忽略的“跑的不是这份代码”。
if defined PYTHONPATH echo   PYTHONPATH : %PYTHONPATH%   注意：它会抢先于虚拟环境
echo.

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
