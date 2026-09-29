@echo off
REM Runs Folder Forensics with a visible console window, for troubleshooting.
REM Normal use: just double-click FolderForensics.pyw instead - no console needed.
cd /d "%~dp0"
python "FolderForensics.pyw"
echo.
echo (window closed / exited - press any key to close this console)
pause >nul
