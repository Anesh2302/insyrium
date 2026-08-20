@echo off
title Insyrium Portal Server
cd /d %~dp0
echo Starting Insyrium Portal at http://127.0.0.1:5000 ...
echo Keep this window open. Close it to stop the server.
echo.
python app.py
pause
