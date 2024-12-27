#!/bin/sh

echo "Starting RTAPServer server..."
nohup uvicorn app:app --host 0.0.0.0 --port 37000 > /dev/null 2>&1 &
echo $! > fastapi_app.pid
echo "RTAPServer server started with PID $(cat fastapi_app.pid)"
