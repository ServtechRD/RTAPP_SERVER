#!/bin/sh

echo "Starting RTAPServer server..."
uvicorn app:app --host 0.0.0.0 --port 37000 --reload &
echo $! > fastapi_app.pid
echo "RTAPServer server started with PID $(cat fastapi_app.pid)"