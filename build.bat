@echo off
chcp 65001 >nul
title REALITY-CF Windows 打包

echo ============================================
echo   REALITY-CF 节点发现 — Windows 打包
echo ============================================
echo.

:: 检查 Python（需要 3.10+）
python -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo X 需要 Python 3.10+，请先安装
    echo   下载: https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version

echo [1/3] 安装依赖...
python -m pip install -q -r requirements.txt pyinstaller
if %errorlevel% neq 0 (
    echo X 依赖安装失败
    pause
    exit /b 1
)

echo [2/3] 编译 exe...
pyinstaller --onefile --console --name reality-cf ^
    --hidden-import aiodns ^
    --hidden-import pycares ^
    --hidden-import aiohttp ^
    --add-data "README.md;." ^
    main.py
if %errorlevel% neq 0 (
    echo X 编译失败
    pause
    exit /b 1
)

echo [3/3] 完成
echo.
echo   输出: dist\reality-cf.exe
echo   用法: dist\reality-cf.exe --sni images.apple.com --targets ips.txt --cf-domain your.domain.com
echo   交互: dist\reality-cf.exe
echo.
pause
