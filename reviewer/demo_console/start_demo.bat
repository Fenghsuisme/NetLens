@echo off
REM NetLens Command Center - start server (Intel CPU + Intel GPU) and open the browser
REM 需要：%USERPROFILE%\ovwin（Python 環境）、%USERPROFILE%\ov_models（模型），見 README.md
cd /d %~dp0
set PYTHONIOENCODING=utf-8
start "" /b cmd /c "timeout /t 35 /nobreak >nul & start msedge --start-fullscreen http://127.0.0.1:8765/"
"%USERPROFILE%\ovwin\Scripts\python.exe" -W ignore server.py --models "%USERPROFILE%\ov_models" %*
pause
