#!/bin/bash

if [ -f fastapi_app.pid ]; then
  echo "Stopping RTAPServer server..."
  kill -9 $(cat fastapi_app.pid) && rm fastapi_app.pid
  echo "RTAPServer server stopped."
else
  echo "No PID file found. Is the server running?"
fi