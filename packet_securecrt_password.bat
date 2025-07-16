@echo off
cd /d %~dp0

echo 开始打包...
pyinstaller --onefile --name securecrt_password_tool --hidden-import=Crypto securecrt_password_main.py
echo.
echo 打包完成
echo 请查看dist目录下的可执行文件

pause
