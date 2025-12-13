@echo off
chcp 65001 >nul
title ospab.vpn Client
python client.py %*
pause
