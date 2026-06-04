#!/bin/bash
cd ~/SOC-Threat-Hunting-Lab
echo "Starting SOC Dashboard..."
python3 server.py &
sleep 1
explorer.exe http://localhost:8000
echo "Dashboard live at http://localhost:8000"
echo "Ctrl+C to stop"
wait
