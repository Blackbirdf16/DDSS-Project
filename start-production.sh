#!/bin/bash
# Production startup script for FairRide backend
# Sets environment variables from .env and starts the server with PostgreSQL + Redis

echo "Loading environment variables from .env..."
export $(grep -v '^#' .env | xargs)

echo ""
echo "========================================"
echo "  FairRide Production Server"
echo "========================================"
echo ""
echo "PostgreSQL: $FAIRRIDE_DB_URL"
echo "Redis: $FAIRRIDE_REDIS_URL"
echo ""
echo "Running health checks..."
python healthcheck.py
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Health checks failed!"
    echo "Please ensure Docker containers are running: docker-compose up -d"
    exit 1
fi

echo ""
echo "Starting FastAPI server with production backends..."
echo ""
python app.py
