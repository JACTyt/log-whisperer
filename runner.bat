@echo off
setlocal EnableDelayedExpansion
rem Log Whisperer launcher.
rem   runner.bat          start with Docker (UI http://localhost:8080)
rem   runner.bat local    start without Docker: API + Vite dev server in two windows (UI http://localhost:5173)
rem   runner.bat stop     stop the Docker stack (data is kept in the logw-data volume)
rem   runner.bat logs     follow Docker logs
rem Optional: set LOGW_OLLAMA_MODEL=<model> or LOGW_LLM_PROVIDER=anthropic before running.

cd /d "%~dp0"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=docker"

if /i "%MODE%"=="stop" (
    docker compose down
    exit /b %errorlevel%
)
if /i "%MODE%"=="logs" (
    docker compose logs -f
    exit /b %errorlevel%
)
if /i not "%MODE%"=="docker" if /i not "%MODE%"=="local" (
    echo Unknown option "%MODE%". Use: runner.bat [docker^|local^|stop^|logs]
    exit /b 1
)

where curl >nul 2>&1 || (echo curl.exe is required ^(included in Windows 10 1803+^). & exit /b 1)

rem ---------------------------------------------------------------- Ollama / model
call :check_ollama

if /i "%MODE%"=="local" goto :local

rem ---------------------------------------------------------------- Docker mode
docker info >nul 2>&1 || (
    echo Docker is not running. Start Docker Desktop and run this again.
    exit /b 1
)
if not exist "rules\sigma\VERSION" (
    echo Note: rules\sigma is empty - only custom rules will be used. Fetch SigmaHQ rules with:
    echo     cd backend ^&^& uv run logw rules sync
)

echo Building and starting containers ^(the first build takes a few minutes^)...
docker compose up -d --build || (
    echo docker compose failed. Run "runner.bat logs" to see why.
    exit /b 1
)
call :wait_for "http://localhost:8080/api/health" 90 || (
    echo The API did not become healthy. Run "runner.bat logs" to see why.
    exit /b 1
)
echo.
echo Log Whisperer is running at http://localhost:8080
echo   syslog: send to udp/tcp 127.0.0.1:5514 ^(start live ingestion in the UI^)
echo   stop:   runner.bat stop
start "" "http://localhost:8080"
exit /b 0

rem ---------------------------------------------------------------- Local mode
:local
where uv >nul 2>&1 || (echo uv is not installed: https://docs.astral.sh/uv/ & exit /b 1)
where npm >nul 2>&1 || (echo Node.js/npm is not installed: https://nodejs.org & exit /b 1)

pushd backend
echo Installing backend dependencies...
call uv sync --quiet || (popd & echo uv sync failed. & exit /b 1)
popd
if not exist "frontend\node_modules" (
    echo Installing frontend dependencies...
    pushd frontend
    call npm install --silent || (popd & echo npm install failed. & exit /b 1)
    popd
)

start "Log Whisperer API" cmd /k "cd /d "%~dp0backend" && uv run logw serve"
start "Log Whisperer UI" cmd /k "cd /d "%~dp0frontend" && npm run dev"
call :wait_for "http://127.0.0.1:8000/api/health" 60 || (
    echo The API did not start. Check the "Log Whisperer API" window.
    exit /b 1
)
call :wait_for "http://localhost:5173/" 60 || (
    echo The UI did not start. Check the "Log Whisperer UI" window.
    exit /b 1
)
echo.
echo Log Whisperer is running at http://localhost:5173 ^(close the two windows to stop^)
start "" "http://localhost:5173"
exit /b 0

rem ---------------------------------------------------------------- helpers
:check_ollama
if /i "%LOGW_LLM_PROVIDER%"=="anthropic" goto :eof
if /i "%LOGW_LLM_PROVIDER%"=="openai" goto :eof
curl -sf http://localhost:11434/api/version >nul 2>&1
if errorlevel 1 (
    echo Warning: Ollama is not running on localhost:11434. Ingest and detection work, but
    echo          explanations and chat need a model. Start the Ollama app, or set
    echo          LOGW_LLM_PROVIDER=anthropic and ANTHROPIC_API_KEY.
    goto :eof
)
if not defined LOGW_OLLAMA_MODEL set "LOGW_OLLAMA_MODEL=gemma4:26b-a4b"
ollama list 2>nul | findstr /b /i /c:"%LOGW_OLLAMA_MODEL% " >nul && goto :model_ok
rem Preferred model is not installed: fall back to an installed Gemma 4, then to any model.
set "FALLBACK="
for /f "skip=1 tokens=1" %%m in ('ollama list 2^>nul') do (
    if not defined FALLBACK (
        echo %%m | findstr /i "gemma-4 gemma4" >nul && set "FALLBACK=%%m"
    )
)
if not defined FALLBACK for /f "skip=1 tokens=1" %%m in ('ollama list 2^>nul') do (
    if not defined FALLBACK (
        echo %%m | findstr /i "embed" >nul || set "FALLBACK=%%m"
    )
)
if defined FALLBACK (
    echo Model %LOGW_OLLAMA_MODEL% is not installed; using !FALLBACK! instead.
    echo   ^(install the default with: ollama pull %LOGW_OLLAMA_MODEL%^)
    set "LOGW_OLLAMA_MODEL=!FALLBACK!"
    goto :model_ok
)
echo Warning: no Ollama models installed. Run: ollama pull %LOGW_OLLAMA_MODEL%
goto :eof
:model_ok
echo Using Ollama model: %LOGW_OLLAMA_MODEL%
goto :eof

:wait_for
rem %1 url, %2 attempts (2 s apart)
set /a "TRIES=%~2"
:wait_loop
curl -sf "%~1" >nul 2>&1 && exit /b 0
set /a "TRIES-=1"
if %TRIES% leq 0 exit /b 1
timeout /t 2 /nobreak >nul
goto :wait_loop
