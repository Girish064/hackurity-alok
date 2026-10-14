#!/usr/bin/env pwsh
# start.ps1 — AgentShield V3 startup script for Windows PowerShell
# Usage:
#   .\start.ps1              # Start backend only
#   .\start.ps1 -Dashboard   # Start backend + dashboard
#   .\start.ps1 -All         # Start infrastructure + backend + dashboard

param(
    [switch]$Dashboard,
    [switch]$All,
    [switch]$InfraOnly,
    [int]$BackendPort = 8000,
    [int]$DashboardPort = 8501
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  ___                    _   ____  _     _      _     _ " -ForegroundColor Cyan
Write-Host " / _ \   __ _  __ _ ___ | |_/ ___|| |__ (_) ___| | __| |" -ForegroundColor Cyan
Write-Host "| | | | / _' |/ _' / _ \| __\___ \| '_ \| |/ _ \ |/ _' |" -ForegroundColor Cyan
Write-Host "| |_| || (_| | (_| \  __/| |_ ___) | | | | |  __/ | (_| |" -ForegroundColor Cyan
Write-Host " \___/  \__, |\__, |\___| \__|____/|_| |_|_|\___|_|\__,_|" -ForegroundColor Cyan
Write-Host "         |___/ |___/" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AgentShield V3 — Adaptive Zero-Trust Action Security" -ForegroundColor White
Write-Host "  Don't just detect — mathematically guarantee the boundary." -ForegroundColor DarkGray
Write-Host ""

# ── Check prerequisites ────────────────────────────────────────────────────
function Check-Command($cmd) {
    $null = Get-Command $cmd -ErrorAction SilentlyContinue
    return $?
}

Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

if (Test-Path ".venv\Scripts\python.exe") {
    $python = ".venv\Scripts\python.exe"
    $pip    = ".venv\Scripts\pip.exe"
} else {
    $python = "python"
    $pip    = "pip"
}

# Check required packages
$missing = @()
foreach ($pkg in @("fastapi", "uvicorn", "sqlalchemy", "redis", "streamlit", "typer")) {
    $check = & $python -c "import $pkg" 2>&1
    if ($LASTEXITCODE -ne 0) { $missing += $pkg }
}
if ($missing.Count -gt 0) {
    Write-Host "  Installing missing packages: $($missing -join ', ')" -ForegroundColor Yellow
    & $pip install -r requirements.txt --quiet
}

Write-Host "  Prerequisites OK" -ForegroundColor Green

# ── Check .env ─────────────────────────────────────────────────────────────
Write-Host "[2/6] Checking configuration..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Write-Host "  .env not found — copying from .env.example" -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "  IMPORTANT: Edit .env and set ADMIN_SECRET_TOKEN and Ed25519 keys." -ForegroundColor Red
}

# Warn if keys are not set
$envContent = Get-Content ".env" -Raw
if ($envContent -notmatch "AGENTSHIELD_SIGNING_KEY_PEM=-----") {
    Write-Host "  WARNING: AGENTSHIELD_SIGNING_KEY_PEM not set. Ephemeral keys will be used." -ForegroundColor Yellow
    Write-Host "  Run the key generation command from README.md to persist keys." -ForegroundColor DarkGray
}
Write-Host "  Configuration OK" -ForegroundColor Green

# ── Start infrastructure (optional) ────────────────────────────────────────
if ($All) {
    Write-Host "[3/6] Starting infrastructure (Docker)..." -ForegroundColor Yellow
    if (Check-Command "docker") {
        docker compose up -d postgres redis
        Write-Host "  Waiting for postgres and redis to become healthy..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
        Write-Host "  Infrastructure started" -ForegroundColor Green
    } else {
        Write-Host "  Docker not found — skipping. Ensure postgres and redis are running." -ForegroundColor Yellow
    }
} else {
    Write-Host "[3/6] Skipping infrastructure start (pass -All to start Docker services)" -ForegroundColor DarkGray
}

# ── Run migrations ──────────────────────────────────────────────────────────
Write-Host "[4/6] Running database migrations..." -ForegroundColor Yellow
try {
    & $python -m alembic upgrade head 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    Write-Host "  Migrations OK" -ForegroundColor Green
} catch {
    Write-Host "  Migration failed (database may be unavailable): $_" -ForegroundColor Red
    if (-not $All) {
        Write-Host "  Start postgres first with: docker compose up -d postgres" -ForegroundColor Yellow
    }
}

# ── Start backend ──────────────────────────────────────────────────────────
Write-Host "[5/6] Starting AgentShield backend on port $BackendPort..." -ForegroundColor Yellow
$backendJob = Start-Job -ScriptBlock {
    param($python, $port, $dir)
    Set-Location $dir
    & $python -m uvicorn backend.main:app --host 0.0.0.0 --port $port --reload
} -ArgumentList $python, $BackendPort, $PSScriptRoot

Start-Sleep -Seconds 3
Write-Host "  Backend started (PID: $($backendJob.Id))" -ForegroundColor Green
Write-Host "  API docs: http://localhost:$BackendPort/docs" -ForegroundColor Cyan

# ── Start dashboard (optional) ─────────────────────────────────────────────
if ($Dashboard -or $All) {
    Write-Host "[6/6] Starting Streamlit dashboard on port $DashboardPort..." -ForegroundColor Yellow
    $dashJob = Start-Job -ScriptBlock {
        param($python, $port, $dir)
        Set-Location $dir
        & $python -m streamlit run dashboard\app.py --server.port $port --server.headless true
    } -ArgumentList $python, $DashboardPort, $PSScriptRoot
    Start-Sleep -Seconds 2
    Write-Host "  Dashboard started" -ForegroundColor Green
    Write-Host "  Dashboard: http://localhost:$DashboardPort" -ForegroundColor Cyan
} else {
    Write-Host "[6/6] Skipping dashboard (pass -Dashboard to start)" -ForegroundColor DarkGray
    Write-Host "  To start manually: .venv\Scripts\streamlit run dashboard\app.py" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  AgentShield V3 is running." -ForegroundColor White
Write-Host ""
Write-Host "  API:       http://localhost:$BackendPort" -ForegroundColor Cyan
Write-Host "  API docs:  http://localhost:$BackendPort/docs" -ForegroundColor Cyan
if ($Dashboard -or $All) {
    Write-Host "  Dashboard: http://localhost:$DashboardPort" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  CLI:  .venv\Scripts\python.exe -m terminal.agsh --help" -ForegroundColor DarkGray
Write-Host "  Stop: Ctrl+C (in the uvicorn terminal)" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Keep script alive and show job output
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
try {
    while ($true) {
        Start-Sleep -Seconds 5
        $backendJob | Receive-Job -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match "ERROR|Exception|error") {
                Write-Host "  [backend] $_" -ForegroundColor Red
            }
        }
    }
} finally {
    Write-Host "`nShutting down..." -ForegroundColor Yellow
    Stop-Job $backendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob -ErrorAction SilentlyContinue
    if ($Dashboard -or $All) {
        Stop-Job $dashJob -ErrorAction SilentlyContinue
        Remove-Job $dashJob -ErrorAction SilentlyContinue
    }
}
