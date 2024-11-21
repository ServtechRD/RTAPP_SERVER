#!/bin/bash

if [ -f fastapi_dev.pid ]; then
  echo "Stopping RTAPServer Dev server..."
  kill -9 $(cat fastapi_dev.pid) && rm fastapi_dev.pid
  echo "RTAPServer Dev server stopped."
else
  echo "No PID file found. Is the server running?"
fi