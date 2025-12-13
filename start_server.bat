@echo off
chcp 65001 >nul
title ospab.vpn Server
python server.py %*
pause
