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

rem 是否改用自己输入的目标。口令仍然只从文件路径读，提示里绝不要求直接打口令。
rem 30 秒不选就当 N，这样双击打开的人走开也不会卡在这里。
echo 是否输入自己的 SSID/BSSID 做实测（口令仍只从文件路径读，不在提示里打口令）?
choice /c YN /n /t 30 /d N /m "  输入自己的 SSID/BSSID 实测 [Y/N]，30 秒不选按 N："
if errorlevel 2 (
    set "ASK="
) else (
    set "ASK=--ask-targets"
)
echo.

echo 正在执行一键测试，日志写入 logs\ 目录...
if defined ASK echo   目标改为交互输入：验证阶段会逐条询问 SSID / BSSID / 口令文件路径
rem 额外参数原样透传，例如 run-all.cmd --debug-plaintext 会把口令明文写到 .\logout.txt
"%PY%" scripts\one_click_test.py %ASK% %*
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
    echo === 全部通过 ===
) else if "%RC%"=="3" (
    echo === 通过，但有断言按调试开关暂停；本轮不是干净通过，详见 logs\ 下的日志 ===
) else (
    echo === 存在失败阶段，退出码 %RC%，详见 logs\ 下的日志 ===
)
pause
exit /b %RC%
