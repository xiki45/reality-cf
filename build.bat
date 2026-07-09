@echo off
chcp 65001 >nul
title REALITY-CF Windows 打包

echo ============================================
echo   REALITY-CF 节点发现 — Windows 打包
echo ============================================
echo.

:: 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 未找到 Python，请先安装 Python 3.10+
    echo    下载: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] 安装依赖...
pip install cryptography aiodns colorama aiohttp pyinstaller -q

echo [2/3] 编译 exe...
pyinstaller --onefile --console --name reality-cf ^
    --add-data "PHASE2_REF.md;." ^
    main.py

if %errorlevel% neq 0 (
    echo ❌ 编译失败
    pause
    exit /b 1
)

echo [3/3] 完成！
echo.
echo   输出: dist\reality-cf.exe
echo   用法: dist\reality-cf.exe --sni images.apple.com --cf-domain your.domain.com
echo   交互: dist\reality-cf.exe
echo.
pause
