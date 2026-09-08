@echo off
REM Double-click this file on the SCCM Site Server to launch the health dashboard.
REM No parameters or edits needed: the script auto-detects the site code and reads it
REM from the local machine.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SCCM-SiteSystemHealthDashboard.ps1"
