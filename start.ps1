# ============================================================
#  CloudSecurityApp - Full Stack Startup Script
#  Starts: MySQL check, Backend (FastAPI), Frontend (Vite)
#  Run with: .\start.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ROOT = $PSScriptRoot

# --- Colors ---
function Info { param($m) Write-Host "  $m" -ForegroundColor Cyan }
function OK { param($m) Write-Host "  OK  $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "  WARN  $m" -ForegroundColor Yellow }
function Err { param($m) Write-Host "  ERR  $m" -ForegroundColor Red }
function Title {
    param($m)
    Write-Host ""
    Write-Host "--- $m ---" -ForegroundColor White
}

# -------------------------------------------------------------
Title "CloudSecurityApp - Cloud Security Platform"

# --- Step 1: Check .env file ---
Title "Step 1 - Environment Config"
$envFile = Join-Path $ROOT ".env"
if (-not (Test-Path $envFile)) {
    Warn ".env not found - copying from .env.example"
    Copy-Item (Join-Path $ROOT ".env.example") $envFile
    OK ".env created."
}
else {
    OK ".env found."
}

# --- Step 2: Check XAMPP MySQL ---
Title "Step 2 - MySQL (XAMPP) Check"
$mysqlRunning = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("127.0.0.1", 4306)
    $tcp.Close()
    $mysqlRunning = $true
    OK "MySQL is running on port 4306."
}
catch {
    Warn "MySQL is NOT running on port 4306."
    Warn "Please start XAMPP and ensure MySQL is ON."
    Write-Host ""
    $continue = Read-Host "  Continue anyway? [y/N]"
    if ($continue -ne "y") { exit 1 }
}

# --- Step 3: Install Python deps ---
Title "Step 3 - Python Dependencies"
try {
    pip install -r (Join-Path $ROOT "requirements.txt") --quiet
    OK "Python packages up to date."
}
catch {
    Err "pip install failed."
    exit 1
}

# --- Step 4: Check Ollama ---
Title "Step 4 - Ollama LLM Check"
try {
    $ollamaResp = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 -ErrorAction Stop
    OK "Ollama is running."
}
catch {
    Warn "Ollama is NOT running. Chat will fail."
}

# --- Step 5: Check Frontend deps ---
Title "Step 5 - Frontend Dependencies"
$uiDir = Join-Path $ROOT "ui"
$nodeModules = Join-Path $uiDir "node_modules"
if (-not (Test-Path $nodeModules)) {
    Info "node_modules not found - running npm install..."
    Push-Location $uiDir
    npm install --silent
    Pop-Location
    OK "npm packages installed."
}
else {
    OK "node_modules present."
}

# --- Step 6: Start Backend ---
Title "Step 6 - Starting Backend"
$tempScript = Join-Path $env:TEMP "CloudSecurityApp_backend.ps1"
# Create a simple command string instead of a here-string to avoid parser quirks
$cmd = "Set-Location '$ROOT'; uvicorn api:app --reload --host 127.0.0.1 --port 8000"
$cmd | Out-File -FilePath $tempScript -Encoding UTF8
Start-Process powershell -ArgumentList "-NoExit", "-File", "`"$tempScript`"" -WindowStyle Normal
OK "Backend started in new window."

# --- Step 7: Launch Frontend ---
Title "Step 7 - Starting Frontend"
OK "CloudSecurityApp UI available at: http://localhost:5173"
Write-Host ""

Push-Location $uiDir
# Open the browser first; Vite boots up very quickly.
Start-Process "http://localhost:5173"
npm run dev
Pop-Location
