@echo off
echo ========================================================
echo Building Secure File Sharing over WLAN
echo Author: ALAN JAISON
echo ========================================================

echo Installing Dependencies...
pip install -r requirements.txt --quiet

echo Starting PyInstaller Build...
pyinstaller --onefile --windowed --icon=icon.ico ^
  --add-data "icon.ico;." ^
  --add-data "crypto_utils.py;." ^
  --add-data "protocol.py;." ^
  --add-data "server.py;." ^
  --add-data "client.py;." ^
  --add-data "main.py;." ^
  --name "Secure-File-Sharing-WLAN" gui.py

echo Build complete! Executable is located in the dist/ folder.
pause
