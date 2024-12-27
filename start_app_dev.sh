#!/bin/sh

echo "Starting RTAPServer Dev server..."
nohup uvicorn app_dev:app --host 0.0.0.0 --port 37200 > /dev/null 2>&1 &
echo $! > fastapi_dev.pid
echo "RTAPServer Dev server started with PID $(cat fastapi_dev.pid)"
