@echo off
chcp 65001 >nul
title SecMind ATT^&CK Knowledge Search

cd /d "%~dp0"
set PYTHONPATH=%cd%\src
python scripts\search_knowledge.py

echo.
pause
