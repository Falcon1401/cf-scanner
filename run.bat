@echo off
chcp 65001 > nul
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Cloudflare IP Scanner  -  راه‌اندازی   ║
echo  ╚══════════════════════════════════════════╝
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [خطا] Python نصب نیست. لطفاً از python.org نصب کنید.
    pause
    exit /b 1
)

echo  [1/2] نصب کتابخانه‌های مورد نیاز ...
pip install requests ping3 --quiet

echo  [2/2] در حال اجرا ...
echo.
python main.py

pause
