@echo off
REM Production startup script for FairRide backend
REM Sets environment variables from .env and starts the server with PostgreSQL + Redis

echo Loading environment variables from .env...
for /f "tokens=1,* delims==" %%a in (.env) do (
    if not "%%a"=="" (
        if not "%%a:~0,1%"=="#" (
            set "%%a=%%b"
        )
    )
)

echo.
echo ========================================
echo   FairRide Production Server
echo ========================================
echo.
echo PostgreSQL: %FAIRRIDE_DB_URL%
echo Redis: %FAIRRIDE_REDIS_URL%
echo.
echo Running health checks...
python healthcheck.py
if errorlevel 1 (
    echo.
    echo ERROR: Health checks failed!
    echo Please ensure Docker containers are running: docker-compose up -d
    exit /b 1
)

echo.
echo Starting FastAPI server with production backends...
echo.
python app.py
