#!/bin/sh

echo "Starting RTAPServer Dev server..."
uvicorn app_dev:app --host 0.0.0.0 --port 37200 --reload &
echo $! > fastapi_dev.pid
echo "RTAPServer Dev server started with PID $(cat fastapi_dev.pid)"