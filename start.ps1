# CatPhish Backend Auto-Start Script
# Save this as start.ps1 in your CatPhish folder and double-click to run

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       CatPhish Backend Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js is installed
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
    Write-Host "Download it from https://nodejs.org and install the LTS version." -ForegroundColor Yellow
    pause
    exit
}

Write-Host "Node.js found: $(node --version)" -ForegroundColor Green

# Install dependencies if node_modules missing
if (-not (Test-Path "node_modules")) {
    Write-Host ""
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    Write-Host "Dependencies installed." -ForegroundColor Green
}

# Generate secrets file if .env doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host ""
    Write-Host "Generating secrets and creating .env file..." -ForegroundColor Yellow

    $jwt    = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
    $audit  = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
    $report = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"

    $envContent = @"
CATPHISH_JWT_SECRET=$jwt
CATPHISH_AUDIT_KEY=$audit
CATPHISH_REPORT_SECRET=$report
CATPHISH_DEMO_MODE=true
PORT=3030
NODE_ENV=development
"@

    $envContent | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host ".env file created with fresh secrets." -ForegroundColor Green
} else {
    Write-Host ".env file already exists, using existing secrets." -ForegroundColor Green
}

# Load .env into environment variables
Write-Host ""
Write-Host "Loading environment variables..." -ForegroundColor Yellow
Get-Content ".env" | ForEach-Object {
    if ($_ -match "^\s*#" -or $_ -match "^\s*$") { return }
    $parts = $_ -split "=", 2
    if ($parts.Length -eq 2) {
        $key = $parts[0].Trim()
        $val = $parts[1].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        Write-Host "  Set $key" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting CatPhish Backend..." -ForegroundColor Cyan
Write-Host "  URL: http://127.0.0.1:3030" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

node backend/server.js